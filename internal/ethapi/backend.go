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

// Package ethapi implements the general Ethereum API functions.
package ethapi

import (
	"context"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
)

// Backend interface provides the common API services (that are provided by
// both full and light clients) with access to necessary functions.
type Backend interface {
	// General Ethereum API
	//SyncProgress() ethereum.SyncProgress
	ChainDb() ethdb.Database
	AccountManager() *accounts.Manager
	ExtRPCEnabled() bool
	RPCGasCap() uint64            // global gas cap for eth_call over rpc: DoS protection
	UnprotectedAllowed() bool     // allows only for EIP155 transactions.

	// Blockchain API
	SetHead(number uint64)
	CurrentBlock() *types.Header
	BlockByNumber(ctx context.Context, number rpc.BlockNumber) (*types.Block, error)
	BlockByHash(ctx context.Context, hash common.Hash) (*types.Block, error)
	BlockByNumberOrHash(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash) (*types.Block, error)

	// Transaction pool API
	GetTransaction(ctx context.Context, txHash common.Hash) (*types.Transaction, common.Hash, uint64, uint64, error)

	// FileData pool API
	SendDAByParams(sender common.Address,index,length uint64,commitment,data []byte,nodeGroupKey [32]byte,proof []byte,claimedValue []byte,outTimeStamp int64) ([]byte,error)
	SendBTCDAByParams(commitment ,data []byte,nodeGroupKey [32]byte,proof []byte,claimedValue []byte,revealTxBytes, commitTxBytes, inscriptionScript []byte) ([]byte,error)
	SendBatchDA(datas [][]byte) ([][]byte,[]error)
	GetDAByHash(hash common.Hash) (*types.DA,error)
	GetBatchDAsByHashes(hashes []common.Hash) ([]*types.DA,[]error)
	GetDAByCommitment(comimt []byte) (*types.DA, error)
	GetBatchDAsByCommitments(commitments [][]byte) ([]*types.DA,[]error)
	SubscribeNewFileDataEvent(chan<- core.NewFileDataEvent) event.Subscription

	ChainConfig() *params.ChainConfig
	HistoricalRPCService() *rpc.Client
	Genesis() *types.Block
}

func GetAPIs(apiBackend Backend) []rpc.API {
	nonceLock := new(AddrLocker)
	return []rpc.API{
		 {
			Namespace: "eth",
			Service:   NewBlockChainAPI(apiBackend),
		},{
			Namespace: "eth",
			Service:   NewTransactionAPI(apiBackend, nonceLock),
		}, {
			Namespace: "eth",
			Service:   NewDAAPI(apiBackend),
		}, {
			Namespace: "debug",
			Service:   NewDebugAPI(apiBackend),
		}, {
			Namespace: "eth",
			Service:   NewEthereumAccountAPI(apiBackend.AccountManager()),
		}, {
			Namespace: "personal",
			Service:   NewPersonalAccountAPI(apiBackend, nonceLock),
		},
	}
}
