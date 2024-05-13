// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package eth

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/txpool/filedatapool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

// EthAPIBackend implements ethapi.Backend and tracers.Backend for full nodes
type EthAPIBackend struct {
	extRPCEnabled       bool
	allowUnprotectedTxs bool
	//disableTxPool       bool
	eth                 *Ethereum
	//gpo                 *gasprice.Oracle
}

// ChainConfig returns the active chain configuration.
func (b *EthAPIBackend) ChainConfig() *params.ChainConfig {
	return b.eth.blockchain.Config()
}

func (b *EthAPIBackend) CurrentBlock() *types.Header {
	return b.eth.blockchain.CurrentBlock()
}

func (b *EthAPIBackend) SetHead(number uint64) {
	b.eth.blockchain.SetHead(number)
}

//TODO fix this bug
func (b *EthAPIBackend) HeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Header, error) {
	// Otherwise resolve and return the block
	if number == rpc.LatestBlockNumber {
		return b.eth.blockchain.CurrentBlock(), nil
	}

	//return b.eth.blockchain.GetHeaderByNumber(uint64(number)), nil
	return nil,nil
}


func (b *EthAPIBackend) BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error) {

	// Otherwise resolve and return the block
	if number == rpc.LatestBlockNumber {
		header := b.eth.blockchain.CurrentBlock()
		return b.eth.blockchain.GetBlock(header.Hash(), header.Number.Uint64()), nil
	}
	return b.eth.blockchain.GetBlockByNumber(uint64(number)), nil
}

func (b *EthAPIBackend) BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error) {
	return b.eth.blockchain.GetBlockByHash(hash), nil
}

func (b *EthAPIBackend) BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error) {
	var blockNr rpc.BlockNumber
	if blockNr, ok := blockNrOrHash.Number(); ok {
		return b.BlockByNumber(ctx, blockNr)
	}
	if hash, ok := blockNrOrHash.Hash(); ok {
		block := b.eth.blockchain.GetBlock(hash, uint64(blockNr.Int64()))
		if block == nil {
			return nil, errors.New("header found, but block body is missing")
		}
		return block, nil
	}
	return nil, errors.New("invalid arguments; neither block nor hash specified")
}

func (b *EthAPIBackend) GetTd(ctx context.Context) *big.Int {
	return b.eth.blockchain.GetTd()
}

// 上传文件的接口
func (b *EthAPIBackend) UploadFileData(data []byte) error {
	//decode data to struct
	fd := new(types.FileData)
	err := rlp.DecodeBytes(data, fd)
	if err != nil {
		return err
	}
	return b.eth.fdPool.Add([]*types.FileData{fd}, true, false)[0]
	//return nil
}

func (b *EthAPIBackend) UploadFileDataByParams(sender, submitter common.Address, index, length, gasPrice uint64, commitment, data, signData []byte, txHash common.Hash) error {
	fd := types.NewFileData(sender, submitter, index, length, gasPrice, commitment, data, signData, txHash)
	if b.eth.seqRPCService != nil {
		if err := b.eth.fdPool.Add([]*types.FileData{fd}, true, false)[0]; err != nil {
			log.Warn("successfully sent tx to sequencer, but failed to persist in local fileData pool", "err", err, "txHash", txHash.String())
		}
	}
	return b.eth.fdPool.Add([]*types.FileData{fd}, true, false)[0]
	//return nil
}

func (b *EthAPIBackend) GetFileDataByHash(hash common.Hash) (*types.FileData,filedatapool.DISK_FILEDATA_STATE,error) {
	fd,state,err := b.eth.fdPool.Get(hash)
	log.Info("EthAPIBackend-----GetFileDataByHash", "txHash", hash.String())
	if fd != nil {
		return fd,state,nil
	}
	return nil,state ,err
}

func (b *EthAPIBackend) GetFileDataByCommitment(comimt []byte) (*types.FileData, error) {
	fd,_,err := b.eth.fdPool.GetByCommitment(comimt)
	log.Info("EthAPIBackend-----GetFileDataByCommitment", "comimt", common.Bytes2Hex(comimt))
	if fd != nil {
		return fd, nil
	}
	return nil, err
}

func (b *EthAPIBackend) CheckSelfState(blockNr rpc.BlockNumber) (string,error) {
	bc := b.eth.BlockChain()
  block := bc.GetBlockByNumber(uint64(blockNr))
	db := b.eth.chainDb
	res := make([]*types.FileData, 0)
	var totalCount uint64
	log.Info("EthAPIBackend-----CheckSelfState", "blockNr", block.Number().Uint64())
	if block != nil {
		for i := 1; i < int(block.NumberU64()); i++ {
			currentNum := i
			currentBlock := bc.GetBlockByNumber(uint64(currentNum))
			txs := currentBlock.Body().Transactions
			for i := 0; i < len(txs); i++ {
				tx := txs[i]
				if tx.Type() == types.SubmitTxType {
					totalCount+=1
				}
			}
			headHash := currentBlock.Hash()
			fds := rawdb.ReadFileDatas(db,headHash,uint64(currentNum))
			if len(fds)!= 0 {
				 res = append(res, fds...)
			}
		}
	}

	infoStr := fmt.Sprintf("check goal block number is :%d should have:%d local data have:%d",blockNr.Int64(),int(totalCount),len(res))
	if len(res) == int(totalCount) {
		return infoStr,nil
	}
	
	return infoStr,errors.New("dont have full fileDatas with local node")
}

func (b *EthAPIBackend) BatchFileDataByHashes(hashes rpc.TxHashes) ([]uint, []error) {
	log.Info("EthAPIBackend-----GetFileDataByHashes", "len(hashes)",len(hashes.TxHashes))
	flags := make([]uint, len(hashes.TxHashes))
	errs := make([]error, len(hashes.TxHashes))
	for inde, hash := range hashes.TxHashes {
		_, state, err := b.eth.fdPool.Get(hash)
		switch state {
		case filedatapool.DISK_FILEDATA_STATE_DEL:
			flags[inde] = 0
		case filedatapool.DISK_FILEDATA_STATE_SAVE:	
			flags[inde] = 1
		case filedatapool.DISK_FILEDATA_STATE_MEMORY:
			flags[inde] = 2	
		case filedatapool.DISK_FILEDATA_STATE_UNKNOW:
			flags[inde] = 3
		}
		errs[inde] = err
	}
	return flags, errs
}

func (b *EthAPIBackend) BatchSaveFileDataWithHashes(hashes rpc.TxHashes) ([]bool, []error) {
	flags := make([]bool, len(hashes.TxHashes))
	errs := make([]error, len(hashes.TxHashes))
	for index, hash := range hashes.TxHashes {
		log.Info("BatchSaveFileDataWithHashes-----","hash",hash.String())
		err := b.eth.fdPool.SaveFileDataToDisk(hash)
		if err != nil {
			flags[index] = false 
			errs[index] = err
		}
		flags[index] = true
	}
	return flags, errs
}

func (b *EthAPIBackend) DiskSaveFileDataWithHash(hash common.Hash) (bool, error) {
	err := b.eth.fdPool.SaveFileDataToDisk(hash)
	if err != nil {
		return false, err
	}
	return true, err
}

func (b *EthAPIBackend) DiskSaveFileDatas(hashed []common.Hash,blockNrOrHash rpc.BlockNumberOrHash) (bool, error) {
	flag,err := b.eth.fdPool.SaveBatchFileDatasToDisk(hashed,*blockNrOrHash.BlockHash,uint64(*blockNrOrHash.BlockNumber))
	return flag,err
}

// ChangeCurrentState implements ethapi.Backend.
func (b *EthAPIBackend) ChangeCurrentState(state int,number rpc.BlockNumber) bool{
	 return true
}

func (b *EthAPIBackend) GetPoolFileData(hash common.Hash) *types.FileData {
	fd,_,err := b.eth.fdPool.Get(hash)
	if err != nil {
		log.Info("GetPoolFileData---get", "err", err.Error())
	}
	return fd
}

func (b *EthAPIBackend) GetTransaction(ctx context.Context, txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
	tx, blockHash, blockNumber, index := rawdb.ReadTransaction(b.eth.ChainDb(), txHash)
	return tx, blockHash, blockNumber, index, nil
}


func (b *EthAPIBackend) SubscribeNewFileDataEvent(ch chan<- core.NewFileDataEvent) event.Subscription {
	return b.eth.fdPool.SubscribenFileDatas(ch)
}


func (b *EthAPIBackend) ChainDb() ethdb.Database {
	return b.eth.ChainDb()
}

func (b *EthAPIBackend) EventMux() *event.TypeMux {
	return b.eth.EventMux()
}

func (b *EthAPIBackend) AccountManager() *accounts.Manager {
	return b.eth.AccountManager()
}

func (b *EthAPIBackend) ExtRPCEnabled() bool {
	return b.extRPCEnabled
}

func (b *EthAPIBackend) UnprotectedAllowed() bool {
	return b.allowUnprotectedTxs
}

func (b *EthAPIBackend) RPCGasCap() uint64 {
	return b.eth.config.RPCGasCap
}

func (b *EthAPIBackend) RPCEVMTimeout() time.Duration {
	return b.eth.config.RPCEVMTimeout
}

func (b *EthAPIBackend) RPCTxFeeCap() float64 {
	return b.eth.config.RPCTxFeeCap
}

func (b *EthAPIBackend) HistoricalRPCService() *rpc.Client {
	return b.eth.historicalRPCService
}

func (b *EthAPIBackend) Genesis() *types.Block {
	return b.eth.blockchain.Genesis()
}
