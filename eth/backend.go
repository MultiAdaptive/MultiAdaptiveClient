// Copyright 2014 The go-ethereum Authors
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

// Package eth implements the Ethereum protocol.
package eth

import (
	"domiconexec/accounts"
	"domiconexec/common"
	"domiconexec/common/hexutil"
	"domiconexec/core"
	"domiconexec/core/filedatapool"
	"domiconexec/core/rawdb"
	"domiconexec/core/state/pruner"
	"domiconexec/core/types"
	"domiconexec/eth/downloader"
	"domiconexec/eth/ethconfig"
	"domiconexec/eth/protocols/eth"
	"domiconexec/eth/protocols/snap"
	"domiconexec/ethdb"
	"domiconexec/ethdb/db"
	"domiconexec/event"
	"domiconexec/internal/ethapi"
	"domiconexec/internal/shutdowncheck"
	"domiconexec/log"
	"domiconexec/node"
	"domiconexec/p2p"
	"domiconexec/p2p/dnsdisc"
	"domiconexec/p2p/enode"
	"domiconexec/params"
	"domiconexec/rlp"
	"domiconexec/rpc"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"math/big"
	"runtime"
	"sync"
)

// Config contains the configuration options of the ETH protocol.
// Deprecated: use ethconfig.Config instead.
type Config = ethconfig.Config

// Ethereum implements the Ethereum full node service.
type Ethereum struct {
	config *ethconfig.Config
	// Handlers
	sqlDb              *gorm.DB
	fdPool            *filedatapool.FilePool
	blockchain         *core.BlockChain
	handler            *handler
	ethDialCandidates  enode.Iterator
	snapDialCandidates enode.Iterator
	seqRPCService        *rpc.Client
	historicalRPCService *rpc.Client

	// DB interfaces
	chainDb ethdb.Database // Block chain database
	eventMux       *event.TypeMux
	accountManager *accounts.Manager
	APIBackend *EthAPIBackend
	gasPrice  *big.Int
	etherbase common.Address
	networkID     uint64
	netRPCService *ethapi.NetAPI
	p2pServer *p2p.Server
	lock sync.RWMutex // Protects the variadic fields (e.g. gas price and etherbase)
	shutdownTracker *shutdowncheck.ShutdownTracker // Tracks if and when the node has shutdown ungracefully
	nodeCloser func() error
}

// New creates a new Ethereum object (including the
// initialisation of the common Ethereum object)
func New(stack *node.Node, config *ethconfig.Config) (*Ethereum, error) {
	// Ensure configuration values are compatible and sane
	if config.SyncMode == downloader.LightSync {
		return nil, errors.New("can't run eth.Ethereum in light sync mode, use les.LightEthereum")
	}
	if !config.SyncMode.IsValid() {
		return nil, fmt.Errorf("invalid sync mode %d", config.SyncMode)
	}

	if config.NoPruning && config.TrieDirtyCache > 0 {
		if config.SnapshotCache > 0 {
			config.TrieCleanCache += config.TrieDirtyCache * 3 / 5
			config.SnapshotCache += config.TrieDirtyCache * 2 / 5
		} else {
			config.TrieCleanCache += config.TrieDirtyCache
		}
		config.TrieDirtyCache = 0
	}
	log.Info("Allocated trie memory caches", "clean", common.StorageSize(config.TrieCleanCache)*1024*1024, "dirty", common.StorageSize(config.TrieDirtyCache)*1024*1024)

	// Assemble the Ethereum object
	chainDb, err := stack.OpenDatabaseWithFreezer("chaindata", config.DatabaseCache, config.DatabaseHandles, config.DatabaseFreezer, "eth/db/chaindata/", false)
	if err != nil {
		return nil, err
	}
	scheme, err := rawdb.ParseStateScheme(config.StateScheme, chainDb)
	if err != nil {
		return nil, err
	}
	// Try to recover offline state pruning only in hash-based.
	if scheme == rawdb.HashScheme {
		if err := pruner.RecoverPruning(stack.ResolvePath(""), chainDb); err != nil {
			log.Error("Failed to recover state", "error", err)
		}
	}
	// Transfer mining-related config to the ethash config.
	_, err = core.LoadChainConfig(chainDb, config.Genesis)
	if err != nil {
		return nil, err
	}
	eth := &Ethereum{
		config:            config,
		chainDb:           chainDb,
		eventMux:          stack.EventMux(),
		accountManager:    stack.AccountManager(),
		networkID:         config.NetworkId,
		etherbase:         config.Etherbase,
		p2pServer:         stack.Server(),
		shutdownTracker:   shutdowncheck.NewShutdownTracker(chainDb),
		nodeCloser:        stack.Close,
	}
	bcVersion := rawdb.ReadDatabaseVersion(chainDb)
	var dbVer = "<nil>"
	if bcVersion != nil {
		dbVer = fmt.Sprintf("%d", *bcVersion)
	}

	if !config.SkipBcVersionCheck {
		if bcVersion != nil && *bcVersion > core.BlockChainVersion {
			return nil, fmt.Errorf("database version is v%d, Geth %s only supports v%d", *bcVersion, params.VersionWithMeta, core.BlockChainVersion)
		} else if bcVersion == nil || *bcVersion < core.BlockChainVersion {
			if bcVersion != nil { // only print warning on upgrade, not on init
				log.Warn("Upgrade blockchain database version", "from", dbVer, "to", core.BlockChainVersion)
			}
			rawdb.WriteDatabaseVersion(chainDb, core.BlockChainVersion)
		}
	}
	var (
		cacheConfig = &core.CacheConfig{
			TrieCleanLimit:      config.TrieCleanCache,
			TrieCleanNoPrefetch: config.NoPrefetch,
			TrieDirtyLimit:      config.TrieDirtyCache,
			TrieDirtyDisabled:   config.NoPruning,
			TrieTimeLimit:       config.TrieTimeout,
			SnapshotLimit:       config.SnapshotCache,
			Preimages:           config.Preimages,
			StateHistory:        config.StateHistory,
			StateScheme:         scheme,
		}
	)

	//TODO
	//// Core State DB
	stateSqlDB, err := db.NewSqlDB(stack.Config().DataDir)
	if err != nil {
		log.Error("create sql db failed:","err",err.Error())
	}
	db.MigrateUp(stateSqlDB)
	eth.blockchain = core.NewBlockChain(chainDb, cacheConfig, config.Genesis,stateSqlDB)
	eth.sqlDb = stateSqlDB
	//modify by echo
	//eth.blockchain.SetReceiptChan(fileDataPool.ReceiptCh())
	if chainConfig := eth.blockchain.Config(); chainConfig != nil { // config.Genesis.Config.ChainID cannot be used because it's based on CLI flags only, thus default to mainnet L1
		config.NetworkId = chainConfig.ChainID.Uint64() // optimism defaults eth network ID to chain ID
		eth.networkID = config.NetworkId
	}
	log.Info("Initialising Ethereum protocol", "network", config.NetworkId, "dbversion", dbVer)

	//added by echo
	if config.FileDataPool.Journal != "" {
		config.FileDataPool.Journal = stack.ResolvePath(config.FileDataPool.Journal)
	}

	fileDataPool := filedatapool.New(config.FileDataPool,eth.blockchain)
	if err != nil {
		return nil, err
	}
	eth.fdPool = fileDataPool
	// Permit the downloader to use the trie cache allowance during fast sync
	cacheLimit := cacheConfig.TrieCleanLimit + cacheConfig.TrieDirtyLimit + cacheConfig.SnapshotLimit
	if eth.handler, err = newHandler(&handlerConfig{
		Database:       chainDb,
		Chain:          eth.blockchain,
		FileDataPool:  	eth.fdPool,
		Network:        config.NetworkId,
		Sync:           config.SyncMode,
		BloomCache:     uint64(cacheLimit),
		EventMux:       eth.eventMux,
		SqlDb:          stateSqlDB,
	}); err != nil {
		return nil, err
	}

	eth.APIBackend = &EthAPIBackend{stack.Config().ExtRPCEnabled(), stack.Config().AllowUnprotectedTxs, true, eth}
	// Setup DNS discovery iterators.
	dnsclient := dnsdisc.NewClient(dnsdisc.Config{})
	eth.ethDialCandidates, err = dnsclient.NewIterator(eth.config.EthDiscoveryURLs...)
	if err != nil {
		return nil, err
	}
	eth.snapDialCandidates, err = dnsclient.NewIterator(eth.config.SnapDiscoveryURLs...)
	if err != nil {
		return nil, err
	}

	// Start the RPC service
	eth.netRPCService = ethapi.NewNetAPI(eth.p2pServer, config.NetworkId)

	// Register the backend on the node
	stack.RegisterAPIs(eth.APIs())
	stack.RegisterProtocols(eth.Protocols())
	stack.RegisterLifecycle(eth)
	// Successful startup; push a marker and check previous unclean shutdowns.
	eth.shutdownTracker.MarkStartup()

	return eth, nil
}


func makeExtraData(extra []byte) []byte {
	if len(extra) == 0 {
		// create default extradata
		extra, _ = rlp.EncodeToBytes([]interface{}{
			uint(params.OPVersionMajor<<16 | params.OPVersionMinor<<8 | params.OPVersionPatch),
			"geth",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		log.Warn("Miner extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", params.MaximumExtraDataSize)
		extra = nil
	}
	return extra
}

// APIs return the collection of RPC services the ethereum package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *Ethereum) APIs() []rpc.API {
	apis := ethapi.GetAPIs(s.APIBackend)

	// Append all the local APIs and return
	return append(apis, []rpc.API{
		{
			Namespace: "eth",
			Service:   NewEthereumAPI(s),
		},
		//{
		//	Namespace: "eth",
		//	Service:   downloader.NewDownloaderAPI(s.handler.downloader, s.eventMux),
		//},
		{
			Namespace: "admin",
			Service:   NewAdminAPI(s),
		}, {
			Namespace: "net",
			Service:   s.netRPCService,
		},
	}...)
}

//TODO should fix this
func (s *Ethereum) ResetWithGenesisBlock(gb *types.Block) {
	//s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *Ethereum) Etherbase() (eb common.Address, err error) {
	s.lock.RLock()
	etherbase := s.etherbase
	s.lock.RUnlock()

	if etherbase != (common.Address{}) {
		return etherbase, nil
	}
	return common.Address{}, errors.New("etherbase must be explicitly specified")
}

// SetEtherbase sets the mining reward address.
func (s *Ethereum) SetEtherbase(etherbase common.Address) {
	s.lock.Lock()
	s.etherbase = etherbase
	s.lock.Unlock()

	s.etherbase = etherbase
}

func (s *Ethereum) AccountManager() *accounts.Manager  { return s.accountManager }
func (s *Ethereum) BlockChain() *core.BlockChain       { return s.blockchain }
//func (s *Ethereum) TxPool() *txpool.TxPool             { return s.txPool }
//func (s *Ethereum) DB() ethdb.Database 				   { return s.blockchain.Db()}
func (s *Ethereum) FilePool() *filedatapool.FilePool   { return s.fdPool }
func (s *Ethereum) EventMux() *event.TypeMux           { return s.eventMux }
func (s *Ethereum) ChainDb() ethdb.Database            { return s.chainDb }
func (s *Ethereum) IsListening() bool                  { return true } // Always listening
//func (s *Ethereum) Downloader() *downloader.Downloader { return s.handler.downloader }
//func (s *Ethereum) Synced() bool                       { return s.handler.synced.Load() }
//func (s *Ethereum) SetSynced()                         { s.handler.enableSyncedFeatures() }
func (s *Ethereum) ArchiveMode() bool                  { return s.config.NoPruning }
//func (s *Ethereum) BloomIndexer() *core.ChainIndexer   { return s.bloomIndexer }
//func (s *Ethereum) Merger() *consensus.Merger          { return s.merger }
//func (s *Ethereum) SyncMode() downloader.SyncMode {
//	mode, _ := s.handler.chainSync.modeAndLocalHead()
//	return mode
//}

// Protocols returns all the currently configured
// network protocols to start.
func (s *Ethereum) Protocols() []p2p.Protocol {
	protos := eth.MakeProtocols((*ethHandler)(s.handler), s.networkID, s.ethDialCandidates)
	if s.config.SnapshotCache > 0 {
		protos = append(protos, snap.MakeProtocols((*snapHandler)(s.handler), s.snapDialCandidates)...)
	}
	return protos
}

// Start implements node.Lifecycle, starting all internal goroutines needed by the
// Ethereum protocol implementation.
func (s *Ethereum) Start() error {
	eth.StartENRUpdater(s.blockchain, s.p2pServer.LocalNode())

	//// Start the bloom bits servicing goroutines
	//s.startBloomHandlers(params.BloomBitsBlocks)

	// Regularly update shutdown marker
	s.shutdownTracker.Start()

	// Figure out a max peers count based on the server limits
	maxPeers := s.p2pServer.MaxPeers
	if s.config.LightServ > 0 {
		if s.config.LightPeers >= s.p2pServer.MaxPeers {
			return fmt.Errorf("invalid peer config: light peer count (%d) >= total peer count (%d)", s.config.LightPeers, s.p2pServer.MaxPeers)
		}
		maxPeers -= s.config.LightPeers
	}
	// Start the networking layer and the light server if requested
	s.handler.Start(maxPeers)
	return nil
}

// Stop implements node.Lifecycle, terminating all internal goroutines used by the
// Ethereum protocol.
func (s *Ethereum) Stop() error {
	// Stop all the peer-related stuff first.
	s.ethDialCandidates.Close()
	s.snapDialCandidates.Close()
	s.handler.Stop()
	db.CloseDB(s.sqlDb)
	// Then stop everything else.
	//s.bloomIndexer.Close()
	//close(s.closeBloomHandler)
	s.fdPool.Close()
	//s.blockchain.Stop()
	if s.seqRPCService != nil {
		s.seqRPCService.Close()
	}
	if s.historicalRPCService != nil {
		s.historicalRPCService.Close()
	}

	// Clean shutdown marker as the last thing before closing db
	s.shutdownTracker.Stop()

	s.chainDb.Close()
	s.eventMux.Stop()

	return nil
}
//
//// HandleRequiredProtocolVersion handles the protocol version signal. This implements opt-in halting,
//// the protocol version data is already logged and metered when signaled through the Engine API.
//func (s *Ethereum) HandleRequiredProtocolVersion(required params.ProtocolVersion) error {
//	var needLevel int
//	switch s.config.RollupHaltOnIncompatibleProtocolVersion {
//	case "major":
//		needLevel = 3
//	case "minor":
//		needLevel = 2
//	case "patch":
//		needLevel = 1
//	default:
//		return nil // do not consider halting if not configured to
//	}
//	haveLevel := 0
//	switch params.OPStackSupport.Compare(required) {
//	case params.OutdatedMajor:
//		haveLevel = 3
//	case params.OutdatedMinor:
//		haveLevel = 2
//	case params.OutdatedPatch:
//		haveLevel = 1
//	}
//	if haveLevel >= needLevel { // halt if we opted in to do so at this granularity
//		log.Error("Opted to halt, unprepared for protocol change", "required", required, "local", params.OPStackSupport)
//		return s.nodeCloser()
//	}
//	return nil
//}
