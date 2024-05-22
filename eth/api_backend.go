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
	eth                 *Ethereum
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
	fd := new(types.DA)
	err := rlp.DecodeBytes(data, fd)
	if err != nil {
		return err
	}
	return b.eth.fdPool.Add([]*types.DA{fd}, true, false)[0]
}

func (b *EthAPIBackend) SendDAByParams(sender common.Address,index,length uint64,commitment,data []byte,dasKey [32]byte) ([]byte,error) {
	fd := types.NewDA(sender, index, length, commitment, data, dasKey)
	//flag,err := b.eth.singer.Verify(fd)
	//if err != nil || flag == false {
	//	return nil, err
	//}else {
	//	b.eth.fdPool.Add([]*types.DA{fd},true,false)
		return b.eth.singer.Sign(fd)
	//}
}

func (b *EthAPIBackend) BatchSendDA(datas [][]byte) ([][]byte,[]error) {
	var da types.DA
	signHashes := make([][]byte,len(datas))
	errlist   := make([]error,len(datas))
	for index,data := range datas{
		err := rlp.DecodeBytes(data,&da)
		if err == nil{
			flag,err := b.eth.singer.Verify(&da)
			if err != nil || flag == false {
				errlist[index] = err
				continue
			}else {
				b.eth.fdPool.Add([]*types.DA{&da},true,false)
				sign,err :=  b.eth.singer.Sign(&da)
				if err != nil {
					errlist[index] = err
					continue
				}else {
					signHashes[index] = sign
				}
			}
		}
	}
	return signHashes,errlist
}

func (b *EthAPIBackend) GetFileDataByHash(hash common.Hash) (*types.DA,filedatapool.DISK_FILEDATA_STATE,error) {
	fd,state,err := b.eth.fdPool.Get(hash)
	log.Info("EthAPIBackend-----GetFileDataByHash", "txHash", hash.String())
	if fd != nil {
		return fd,state,nil
	}
	return nil,state ,err
}

func (b *EthAPIBackend) GetFileDataByCommitment(comimt []byte) (*types.DA, error) {
	fd,err := b.eth.fdPool.GetDAByCommit(comimt)
	log.Info("EthAPIBackend-----GetFileDataByCommitment", "comimt", common.Bytes2Hex(comimt))
	if fd != nil {
		return fd, nil
	}
	return nil, err
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

func (b *EthAPIBackend) GetPoolFileData(hash common.Hash) *types.DA {
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
