// Copyright 2021 The go-ethereum Authors
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

package core

import (
	"github.com/ethereum/go-ethereum/ethdb/db"
	"gorm.io/gorm"
	"math/big"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)



// CurrentBlock retrieves the current head block of the canonical chain. The
// block is retrieved from the blockchain's internal cache.
func (bc *BlockChain) CurrentBlock() *types.Header {
	header:= bc.currentBlock.Load()
	if header != nil {
		return header
	}
	head := rawdb.ReadHeadBlockHash(bc.db)
	if head == (common.Hash{}) {
		return nil
	}
	// Make sure the entire head block is available
	headBlock := bc.GetBlockByHash(head)
	return headBlock.Header()
}

// CurrentSnapBlock retrieves the current snap-sync head block of the canonical
// chain. The block is retrieved from the blockchain's internal cache.
func (bc *BlockChain) CurrentSnapBlock() *types.Header {
	return bc.currentSnapBlock.Load()
}


// HasBlock checks if a block is fully present in the database or not.
func (bc *BlockChain) HasBlock(hash common.Hash, number uint64) bool {
	return rawdb.HasBody(bc.db, hash, number)
}


// GetBlock retrieves a block from the database by hash and number,
// caching it if found.
func (bc *BlockChain) GetBlock(hash common.Hash, number uint64) *types.Block {
	// Short circuit if the block's already in the cache, retrieve otherwise
	if block, ok := bc.blockCache.Get(hash); ok {
		return block
	}
	block := rawdb.ReadBlock(bc.db, hash, number)
	if block == nil {
		return nil
	}
	// Cache the found block for next time and return
	bc.blockCache.Add(block.Hash(), block)
	return block
}

// GetBlockByHash retrieves a block from the database by hash, caching it if found.
func (bc *BlockChain) GetBlockByHash(hash common.Hash) *types.Block {
	if block, ok := bc.blockCache.Get(hash); ok {
		return block
	}
	number := rawdb.ReadHeaderNumber(bc.db, hash)
	if number == nil {
		block,err := db.GetBlockByHash(bc.sqlDb,hash)
		if err != nil {
			return nil
		}
		return block
	}
	return bc.GetBlock(hash, *number)
}

// GetBlockByNumber retrieves a block from the database by number, caching it
// (associated with its hash) if found.
func (bc *BlockChain) GetBlockByNumber(number uint64) *types.Block {
	hash := rawdb.ReadCanonicalHash(bc.db, number)
	if hash == (common.Hash{}) {
		block,err := db.GetBlockByNum(bc.sqlDb,number)
		if err != nil {
			return nil
		}
		return block
	}
	return bc.GetBlock(hash, number)
}


// GetFileDatasByHash retrieves the fileDatas in a given block.
func (bc *BlockChain) GetFileDatasByHash(hash common.Hash) []*types.DA {
	number := rawdb.ReadHeaderNumber(bc.db, hash)
	if number == nil {
		return nil
	}
	//header := bc.GetHeader(hash, *number)
	//if header == nil {
	//	return nil
	//}
	fds := rawdb.ReadFileDatas(bc.db,hash,*number)
	return fds
}

//TODO fix this bug
// GetTd retrieves a block's total difficulty in the canonical chain from the
// database by hash and number, caching it if found.
func (bc *BlockChain) GetTd() *big.Int {
	//return bc.hc.GetTd(hash, number)
	return bc.CurrentBlock().Difficulty
}

func (bc *BlockChain) SqlDB() *gorm.DB{
	return bc.sqlDb
}

// stateRecoverable checks if the specified state is recoverable.
// Note, this function assumes the state is not present, because
// state is not treated as recoverable if it's available, thus
// false will be returned in this case.
func (bc *BlockChain) stateRecoverable(root common.Hash) bool {
	if bc.triedb.Scheme() == rawdb.HashScheme {
		return false
	}
	result, _ := bc.triedb.Recoverable(root)
	return result
}

// ContractCodeWithPrefix retrieves a blob of data associated with a contract
// hash either from ephemeral in-memory cache, or from persistent storage.
//
// If the code doesn't exist in the in-memory cache, check the storage with
// new code scheme.
func (bc *BlockChain) ContractCodeWithPrefix(hash common.Hash) ([]byte, error) {
	type codeReader interface {
		ContractCodeWithPrefix(address common.Address, codeHash common.Hash) ([]byte, error)
	}
	// TODO(rjl493456442) The associated account address is also required
	// in Verkle scheme. Fix it once snap-sync is supported for Verkle.
	return bc.stateCache.(codeReader).ContractCodeWithPrefix(common.Address{}, hash)
}

// Config retrieves the chain's fork configuration.
func (bc *BlockChain) Config() *params.ChainConfig { return bc.chainConfig }


// Snapshots returns the blockchain snapshot tree.
func (bc *BlockChain) Snapshots() *snapshot.Tree {
	return bc.snaps
}

// GasLimit returns the gas limit of the current HEAD block.
func (bc *BlockChain) GasLimit() uint64 {
	return bc.CurrentBlock().GasLimit
}

// Genesis retrieves the chain's genesis block.
func (bc *BlockChain) Genesis() *types.Block {
	return bc.genesisBlock
}


// TrieDB retrieves the low level trie database used for data storage.
func (bc *BlockChain) TrieDB() *trie.Database {
	return bc.triedb
}

// Db returns the disk database 
func (bc *BlockChain) Db() ethdb.Database {
	return bc.db
}

//// SubscribeRemovedLogsEvent registers a subscription of RemovedLogsEvent.
//func (bc *BlockChain) SubscribeRemovedLogsEvent(ch chan<- RemovedLogsEvent) event.Subscription {
//	return bc.scope.Track(bc.rmLogsFeed.Subscribe(ch))
//}
//
//// SubscribeChainEvent registers a subscription of ChainEvent.
//func (bc *BlockChain) SubscribeChainEvent(ch chan<- ChainEvent) event.Subscription {
//	return bc.scope.Track(bc.chainFeed.Subscribe(ch))
//}
//
//
//// SubscribeLogsEvent registers a subscription of []*types.Log.
//func (bc *BlockChain) SubscribeLogsEvent(ch chan<- []*types.Log) event.Subscription {
//	return bc.scope.Track(bc.logsFeed.Subscribe(ch))
//}
