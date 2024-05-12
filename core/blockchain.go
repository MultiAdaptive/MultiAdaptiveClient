package core

import (
	"domiconexec/common"
	"domiconexec/core/types"
	"domiconexec/ethdb"
	"domiconexec/ethdb/db"
	"domiconexec/params"
	"gorm.io/gorm"
	"math/big"
	"strconv"

	//"domiconexec/state"
	"domiconexec/trie"
	"domiconexec/trie/triedb/hashdb"
	"domiconexec/trie/triedb/pathdb"
	"sync/atomic"
	"time"
	"domiconexec/core/rawdb"
)

const (
	BlockChainVersion uint64 = 8
)

// CacheConfig contains the configuration values for the trie database
// and state snapshot these are resident in a blockchain.
type CacheConfig struct {
	TrieCleanLimit      int           // Memory allowance (MB) to use for caching trie nodes in memory
	TrieCleanNoPrefetch bool          // Whether to disable heuristic state prefetching for followup blocks
	TrieDirtyLimit      int           // Memory limit (MB) at which to start flushing dirty trie nodes to disk
	TrieDirtyDisabled   bool          // Whether to disable trie write caching and GC altogether (archive node)
	TrieTimeLimit       time.Duration // Time limit after which to flush the current in-memory trie to disk
	SnapshotLimit       int           // Memory allowance (MB) to use for caching snapshot entries in memory
	Preimages           bool          // Whether to store preimage of trie key to the disk
	StateHistory        uint64        // Number of blocks from head whose state histories are reserved.
	StateScheme         string        // Scheme used to store ethereum states and merkle tree nodes on top

	SnapshotNoBuild bool // Whether the background generation is allowed
	SnapshotWait    bool // Wait for snapshot construction on startup. TODO(karalabe): This is a dirty hack for testing, nuke it
}

// triedbConfig derives the configures for trie database.
func (c *CacheConfig) triedbConfig() *trie.Config {
	config := &trie.Config{Preimages: c.Preimages}
	if c.StateScheme == rawdb.HashScheme {
		config.HashDB = &hashdb.Config{
			CleanCacheSize: c.TrieCleanLimit * 1024 * 1024,
		}
	}
	if c.StateScheme == rawdb.PathScheme {
		config.PathDB = &pathdb.Config{
			StateHistory:   c.StateHistory,
			CleanCacheSize: c.TrieCleanLimit * 1024 * 1024,
			DirtyCacheSize: c.TrieDirtyLimit * 1024 * 1024,
		}
	}
	return config
}

// defaultCacheConfig are the default caching values if none are specified by the
// user (also used during testing).
var defaultCacheConfig = &CacheConfig{
	TrieCleanLimit: 256,
	TrieDirtyLimit: 256,
	TrieTimeLimit:  5 * time.Minute,
	SnapshotLimit:  256,
	SnapshotWait:   true,
	StateScheme:    rawdb.HashScheme,
}

// DefaultCacheConfigWithScheme returns a deep copied default cache config with
// a provided trie node scheme.
func DefaultCacheConfigWithScheme(scheme string) *CacheConfig {
	config := *defaultCacheConfig
	config.StateScheme = scheme
	return &config
}

type BlockChain struct {
	chainConfig       *params.ChainConfig // Chain & network configuration
	cacheConfig       *CacheConfig        // Cache configuration for pruning
	db                ethdb.Database    // Low level persistent database to store final content in
	triedb            *trie.Database    // The database handler for maintaining trie nodes.
	sqlDb             *gorm.DB
	genesisBlock      *types.Block
	currentBlock      atomic.Pointer[types.Block] // Current head of the chain

	//cfg Config
	//state          state.State
}

func NewBlockChain(db ethdb.Database,cacheConfig *CacheConfig,genesis *Genesis,sqlDb *gorm.DB) *BlockChain {
	if cacheConfig == nil {
		cacheConfig = defaultCacheConfig
	}
	triedb := trie.NewDatabase(db, cacheConfig.triedbConfig())

	bc := &BlockChain{
		cacheConfig: cacheConfig,
		db: db,
		triedb: triedb,
		sqlDb:sqlDb,
	}

	//bc.genesisBlock = genesis
	bc.currentBlock.Store(nil)
	return bc
}

// CurrentBlock retrieves the current head block of the canonical chain. The
// block is retrieved from the blockchain's internal cache.
func (bc *BlockChain) CurrentBlock() *types.Block {
	return bc.currentBlock.Load()
	//return nil
}

func (bc *BlockChain) SetCurrentBlock(block *types.Block)  {
	bc.currentBlock.Store(block)
}

// Config retrieves the chain's fork configuration.
func (bc *BlockChain) Config() *params.ChainConfig { return bc.chainConfig }


// Genesis retrieves the chain's genesis block.
func (bc *BlockChain) Genesis() *types.Block {
	return bc.genesisBlock
}

// CurrentHeader retrieves the current head header of the canonical chain. The
// header is retrieved from the HeaderChain's internal cache.
func (bc *BlockChain) CurrentHeader() *types.Header {
	return nil
	//return bc.hc.CurrentHeader()
}

// TrieDB retrieves the low level trie database used for data storage.
func (bc *BlockChain) TrieDB() *trie.Database {
	return bc.triedb
}

func (bc *BlockChain) GetBlock(hash common.Hash, number uint64) *types.Header  {
	res := db.GetBlockByNum(bc.sqlDb,number)
	timeData,_ := strconv.ParseUint(res.ReceivedAt,10,64)
	header := types.Header{
		ParentHash: common.HexToHash(res.ParentHash),
		Number: new(big.Int).SetInt64(res.BlockNum),
		Time: timeData,
	}
	return &header
}

func (bc *BlockChain) SqlDB() *gorm.DB{
	return bc.sqlDb
}