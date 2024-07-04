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
	"github.com/ethereum/go-ethereum/ethdb/db"
	"time"

	sigSdk "github.com/MultiAdaptive/sig-sdk"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
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

func (b *EthAPIBackend) SendDAByParams(sender common.Address,index,length uint64,commitment ,data []byte,dasKey [32]byte,proof []byte,claimedValue []byte,outTimeStamp int64) ([]byte,error) {
	var digest kzg.Digest
	digest.SetBytes(commitment)
	fd := types.NewDA(sender, index, length, digest, data, dasKey, proof, claimedValue)
	t := time.Unix(outTimeStamp,0)
	fd.OutOfTime = t
	flag,err := b.eth.singer.VerifyEth(fd)
	if err != nil || flag == false {
		return nil,err
	}else {
		signData,err := b.eth.singer.Sign(fd)
		b.eth.fdPool.Add([]*types.DA{fd},true,false)
		return signData,err
	}
}

func (b *EthAPIBackend) SendBTCDAByParams(commitment ,data []byte,dasKey [32]byte,proof []byte,claimedValue []byte,revealTxBytes, commitTxBytes, inscriptionScript []byte) ([]byte,error)  {
	var digest kzg.Digest
	digest.SetBytes(commitment)
	da := new(types.DA)
	da.Commitment = digest
	da.Proof = proof
	da.DasKey = dasKey
	da.Data = data
	da.ClaimedValue = claimedValue
	flag,err := b.eth.singer.VerifyBtc(da)
	if err != nil || flag == false {
		return nil, err
	}else {
		priv := common.Hex2Bytes(b.eth.config.BtcPrivate)
		log.Info("SendBTCDAByParams------","commit",common.Bytes2Hex(commitment))
		sign,err := sigSdk.SigWithSchnorr(commitment,priv,commitTxBytes,revealTxBytes,inscriptionScript)
		if err != nil {
			log.Info("SendBTCDAByParams------SigWithSchnorr","err",err.Error())
			return nil,err
		}
		b.eth.fdPool.Add([]*types.DA{da},true,false)
		return sign,nil
	}
}

func (b *EthAPIBackend) SendBatchDA(datas [][]byte) ([][]byte,[]error) {
	var da types.DA
	signHashes := make([][]byte,len(datas))
	errlist   := make([]error,len(datas))
	for index,data := range datas{
		err := rlp.DecodeBytes(data,&da)
		if err == nil{
			flag,err := b.eth.singer.VerifyEth(&da)
			if err != nil || flag == false {
				errlist[index] = err
				continue
			}else {
				da.ReceiveAt = time.Now()
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

func (b *EthAPIBackend) GetDAByHash(hash common.Hash) (*types.DA,error) {
	fd,err := b.eth.fdPool.Get(hash)
	log.Info("EthAPIBackend-----GetDAByHash", "txHash", hash.String())
	if fd != nil {
		return fd,nil
	}
	return nil,err
}

func (b *EthAPIBackend) GetBatchDAsByHashes(hashes []common.Hash) ([]*types.DA,[]error) {
	das := make([]*types.DA,len(hashes))
	errs := make([]error,len(hashes))
	for index,hash := range hashes {
		da,err := b.eth.fdPool.Get(hash)
		log.Info("EthAPIBackend-----GetDAByHash", "txHash", hash.String())
		if da != nil {
			das[index] = da
		}else {
			errs[index] = err
		}
	}
	return das,errs
}

func (b *EthAPIBackend) GetDAByCommitment(comimt []byte) (*types.DA, error) {
	fd,err := b.eth.fdPool.GetDAByCommit(comimt)
	log.Info("EthAPIBackend-----GetDAByCommitment", "comimt", common.Bytes2Hex(comimt))
	if fd != nil {
		return fd, nil
	}
	return nil, err
}

func (b *EthAPIBackend) GetBatchDAsByCommitments(commitments [][]byte) ([]*types.DA,[]error) {
	das := make([]*types.DA,len(commitments))
	errs := make([]error,len(commitments))
	for index,commitment := range commitments {
		chash := common.BytesToHash(commitment)
		da,err := b.eth.fdPool.Get(chash)
		log.Info("EthAPIBackend-----GetDAByCommitment", "commitmentHash", chash.String())
		if da != nil {
			das[index] = da
		}else {
			errs[index] = err
		}
	}
	return das,errs
}

func (b *EthAPIBackend) GetPoolFileData(hash common.Hash) *types.DA {
	fd,err := b.eth.fdPool.Get(hash)
	if err != nil {
		log.Info("GetPoolFileData---get", "err", err.Error())
	}
	return fd
}

func (b *EthAPIBackend) GetTransaction(ctx context.Context, txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error) {
	tx, blockHash, blockNumber, index := rawdb.ReadTransaction(b.eth.ChainDb(), txHash)
	if tx == nil{
		tx = new(types.Transaction)
		txData := db.GetTransactionByHash(b.eth.sqlDb,txHash)
		data := common.Hex2Bytes(txData.Encoded)
		tx.UnmarshalBinary(data)
		block,_ := db.GetBlockByNum(b.eth.sqlDb,uint64(txData.BlockNum))
		blockHash = block.Hash()
		blockNumber = block.NumberU64()
	}
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


func (b *EthAPIBackend) HistoricalRPCService() *rpc.Client {
	return b.eth.historicalRPCService
}

func (b *EthAPIBackend) Genesis() *types.Block {
	return b.eth.blockchain.Genesis()
}
