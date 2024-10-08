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
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/forkid"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/fetcher"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/eth/protocols/snap"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/trie/triedb/pathdb"
)

const (
	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096

	fdChanSize = 60
	// txMaxBroadcastSize is the max size of a transaction that will be broadcasted.
	// All transactions with a higher size will be announced and need to be fetched
	// by the peer.
	txMaxBroadcastSize = 4096
)

var syncChallengeTimeout = 15 * time.Second // Time allowance for a node to reply to the sync progress challenge

// daPool defines the methods needed from a fileData pool implementation to
// support all the operations needed by the Ethereum chain protocols.
type daPool interface {
	// Has returns an indicator whether daPool has a fileData
	// cached with the given hash.
	Has(hash common.Hash) bool

	// Get retrieves the fileData from local daPool with given
	// tx hash.
	Get(hash common.Hash) (*types.DA, error)

	GetDA(hash common.Hash) (*types.DA, error)

	GetDAByCommit(commit []byte) (*types.DA, error)

	SendNewDAEvent(fileData []*types.DA)

	GetSender(da *types.DA) ([]common.Address,[]error)

	RemoveDA(das []*types.DA)

	// Add should add the given transactions to the pool.
	Add(fds []*types.DA, local bool, sync bool) []error

	// SubscribenDAS subscribes to new fileData events. The subscriber
	// can decide whether to receive notifications only for newly seen DA
	// or also for reorged out ones.
	SubscribenDAS(ch chan<- core.NewDAEvent) event.Subscription

	// SubscribenDASHash subscribes to get fileData Hash  events.
	SubscribenDASHash(ch chan<- core.DAHashEvent) event.Subscription
}

// handlerConfig is the collection of initialization parameters to create a full
// node network handler.
type handlerConfig struct {
	Database ethdb.Database   // Database for direct sync insertions
	Chain    *core.BlockChain // Blockchain to serve data from
	//modify by echo
	DAPool      daPool        // DA Pool to propagate from
	//Merger         *consensus.Merger   // The manager for eth1/2 transition
	Network        uint64              // Network identifier to advertise
	Sync           downloader.SyncMode // Whether to snap or full sync
	BloomCache     uint64              // Megabytes to alloc for snap sync bloom
	EventMux       *event.TypeMux      // Legacy event mux, deprecate for `feed`
	L1ScanUrl      string              //l1 scan url
	L1ScanHost     string              //l1 scan host
	L1ScanUser     string              //l1 scan user
	L1ScanPassword string              //l1 scan password
	NodeType       string              //local node type
	Address        common.Address
	ChainName      string              //l1 chain name
	NoTxGossip     bool                // Disable P2P transaction gossip
}

type handler struct {
	networkID  uint64
	forkFilter forkid.Filter // Fork ID filter, constant across the lifetime of the node

	snapSync atomic.Bool // Flag whether snap sync is enabled (gets disabled if we already have blocks)
	synced   atomic.Bool // Flag whether we're considered synchronised (enables transaction processing)

	database     ethdb.Database
	daPool daPool // DA Pool to propagate from
	chain        *core.BlockChain
	maxPeers     int

	noTxGossip bool

	fdFetcher    *fetcher.DAFetcher
	peers        *peerSet
	eventMux      *event.TypeMux
	fdsCh         chan core.NewDAEvent
	fdHashCh      chan core.DAHashEvent
	fdsSub        event.Subscription
	fdHashSub     event.Subscription

	quitSync chan struct{}

	chainSync *chainSyncer
	wg        sync.WaitGroup

	handlerStartCh chan struct{}
	handlerDoneCh  chan struct{}
}

// newHandler returns a handler for all Ethereum chain management protocol.
func newHandler(config *handlerConfig) (*handler, error) {
	// Create the protocol manager with the base fields
	if config.EventMux == nil {
		config.EventMux = new(event.TypeMux) // Nicety initialization for tests
	}
	h := &handler{
		networkID:      config.Network,
		forkFilter:     forkid.NewFilter(config.Chain),
		eventMux:       config.EventMux,
		database:       config.Database,
		daPool:   config.DAPool,
		noTxGossip:     config.NoTxGossip,
		chain:          config.Chain,
		peers:          newPeerSet(),
		quitSync:       make(chan struct{}),
		handlerDoneCh:  make(chan struct{}),
		handlerStartCh: make(chan struct{}),
	}
	// Construct the downloader (long sync)

	if ttd := h.chain.Config().TerminalTotalDifficulty; ttd != nil {
		if h.chain.Config().TerminalTotalDifficultyPassed {
			log.Info("Chain post-merge, sync via beacon client")
		} else {
			//head := h.chain.CurrentBlock()
			if td := h.chain.GetTd(); td.Cmp(ttd) >= 0 {
				log.Info("Chain post-TTD, sync via beacon client")
			} else {
				log.Warn("Chain pre-merge, sync via PoW (ensure beacon client is ready)")
			}
		}
	} else if h.chain.Config().TerminalTotalDifficultyPassed {
		log.Error("Chain configured post-merge, but without TTD. Are you debugging sync?")
	}

	fetchFd := func(peer string, hashes []common.Hash) error {
		p := h.peers.peer(peer)
		if p == nil {
			return errors.New("unknown peer")
		}

		for _, hash := range hashes {
			log.Info("fetchFd----", "peer", peer, "hash", hash)
		}
		return p.RequestDAs(hashes)
	}
	addFds := func(fds []*types.DA) []error {
		return h.daPool.Add(fds, false, false)
	}
	h.fdFetcher = fetcher.NewFdFetcher(h.daPool.Has, addFds, fetchFd, h.removePeer)
	h.chainSync = newChainSync(
		context.Background(),
		h.chain.SqlDB(),
		config.L1ScanUrl,
		config.L1ScanHost,
		config.L1ScanUser,
		config.L1ScanPassword,
		config.Address,
		h,
		h.chain,
		config.NodeType,
		config.ChainName)
	return h, nil
}

// protoTracker tracks the number of active protocol handlers.
func (h *handler) protoTracker() {
	defer h.wg.Done()
	var active int
	for {
		select {
		case <-h.handlerStartCh:
			active++
		case <-h.handlerDoneCh:
			active--
		case <-h.quitSync:
			// Wait for all active handlers to finish.
			for ; active > 0; active-- {
				<-h.handlerDoneCh
			}
			return
		}
	}
}

// incHandlers signals to increment the number of active handlers if not
// quitting.
func (h *handler) incHandlers() bool {
	select {
	case h.handlerStartCh <- struct{}{}:
		return true
	case <-h.quitSync:
		return false
	}
}

// decHandlers signals to decrement the number of active handlers.
func (h *handler) decHandlers() {
	h.handlerDoneCh <- struct{}{}
}

// runEthPeer registers an eth peer into the joint eth/snap peerset, adds it to
// various subsystems and starts handling messages.
func (h *handler) runEthPeer(peer *eth.Peer, handler eth.Handler) error {
	if !h.incHandlers() {
		return p2p.DiscQuitting
	}
	defer h.decHandlers()

	// If the peer has a `snap` extension, wait for it to connect so we can have
	// a uniform initialization/teardown mechanism
	snap, err := h.peers.waitSnapExtension(peer)
	if err != nil {
		peer.Log().Error("Snapshot extension barrier failed", "err", err)
		return err
	}

	// Execute the Ethereum handshake
	var (
		genesis = h.chain.Genesis()
		head    = h.chain.CurrentBlock()
		hash    = head.Hash()
		number  = head.Number.Uint64()
		td      = h.chain.GetTd()
	)
	forkID := forkid.NewID(h.chain.Config(), genesis, number, head.Time)
	if err := peer.Handshake(h.networkID, td, hash, genesis.Hash(), forkID, h.forkFilter); err != nil {
		//peer.Log().Info("Ethereum handshake failed","err",err)
		return err
	}
	reject := false // reserved peer slots
	if h.snapSync.Load() {
		if snap == nil {
			// If we are running snap-sync, we want to reserve roughly half the peer
			// slots for peers supporting the snap protocol.
			// The logic here is; we only allow up to 5 more non-snap peers than snap-peers.
			if all, snp := h.peers.len(), h.peers.snapLen(); all-snp > snp+5 {
				reject = true
			}
		}
	}
	// Ignore maxPeers if this is a trusted peer
	if !peer.Peer.Info().Network.Trusted {
		if reject || h.peers.len() >= h.maxPeers {
			return p2p.DiscTooManyPeers
		}
	}
	peer.Log().Debug("Ethereum peer connected", "name", peer.Name())

	// Register the peer locally
	if err := h.peers.registerPeer(peer, snap); err != nil {
		peer.Log().Error("Ethereum peer registration failed", "err", err)
		return err
	}
	defer h.unregisterPeer(peer.ID())

	p := h.peers.peer(peer.ID())
	if p == nil {
		return errors.New("peer dropped during handling")
	}

	//h.chainSync.handlePeerEvent()

	// Propagate existing transactions. new transactions appearing
	// after this will be sent via broadcasts.
	//h.syncTransactions(peer)

	// Create a notification channel for pending requests if the peer goes down
	dead := make(chan struct{})
	defer close(dead)

	// Handle incoming messages until the connection is torn down
	return handler(peer)
}

// runSnapExtension registers a `snap` peer into the joint eth/snap peerset and
// starts handling inbound messages. As `snap` is only a satellite protocol to
// `eth`, all subsystem registrations and lifecycle management will be done by
// the main `eth` handler to prevent strange races.
func (h *handler) runSnapExtension(peer *snap.Peer, handler snap.Handler) error {
	if !h.incHandlers() {
		return p2p.DiscQuitting
	}
	defer h.decHandlers()

	if err := h.peers.registerSnapExtension(peer); err != nil {
		if metrics.Enabled {
			if peer.Inbound() {
				snap.IngressRegistrationErrorMeter.Mark(1)
			} else {
				snap.EgressRegistrationErrorMeter.Mark(1)
			}
		}
		peer.Log().Debug("Snapshot extension registration failed", "err", err)
		return err
	}
	return handler(peer)
}

// removePeer requests disconnection of a peer.
func (h *handler) removePeer(id string) {
	peer := h.peers.peer(id)
	if peer != nil {
		peer.Peer.Disconnect(p2p.DiscUselessPeer)
	}
}

// unregisterPeer removes a peer from the downloader, fetchers and main peer set.
func (h *handler) unregisterPeer(id string) {
	// Create a custom logger to avoid printing the entire id
	var logger log.Logger
	if len(id) < 16 {
		// Tests use short IDs, don't choke on them
		logger = log.New("peer", id)
	} else {
		logger = log.New("peer", id[:8])
	}
	// Abort if the peer does not exist
	peer := h.peers.peer(id)
	if peer == nil {
		logger.Error("Ethereum peer removal failed", "err", errPeerNotRegistered)
		return
	}
	// Remove the `eth` peer if it exists
	logger.Debug("Removing Ethereum peer", "snap", peer.snapExt != nil)

	if err := h.peers.unregisterPeer(id); err != nil {
		logger.Error("Ethereum peer removal failed", "err", err)
	}
}

func (h *handler) Start(maxPeers int) {
	h.maxPeers = maxPeers
	// broadcast DA  (only new ones, not resurrected ones)
	h.wg.Add(2)
	h.fdsCh = make(chan core.NewDAEvent, fdChanSize)
	h.fdHashCh = make(chan core.DAHashEvent, fdChanSize)
	h.fdsSub = h.daPool.SubscribenDAS(h.fdsCh)
	h.fdHashSub = h.daPool.SubscribenDASHash(h.fdHashCh)
	go h.fdBroadcastLoop()
	go h.fdGetDAsLoop()

	// start sync handlers
	h.wg.Add(1)
	go h.chainSync.loop()

	// start peer handler tracker
	h.wg.Add(1)
	go h.protoTracker()
}

func (h *handler) Stop() {
	//h.txsSub.Unsubscribe()        // quits txBroadcastLoop
	h.fdsSub.Unsubscribe()    // quits DABroadcastLoop
	h.fdHashSub.Unsubscribe() // quits getDAHashLoop

	// Quit chainSync and txsync64.
	// After this is done, no new peers will be accepted.
	close(h.quitSync)

	// Disconnect existing sessions.
	// This also closes the gate for any new registrations on the peer set.
	// sessions which are already established but not added to h.peers yet
	// will exit when they try to register.
	h.peers.close()
	h.wg.Wait()

	log.Info("Ethereum protocol stopped")
}

// TODO fix
func (h *handler) BroadcastDA(fds types.DAs) {
	var (
		directCount int // Number of DA sent directly to peers (duplicates included)
		directPeers int // Number of peers that were sent DA directly

		// annCount    int // Number of DA announced across all peers (duplicates included)
		// annPeers    int // Number of peers announced about DA

		fdset = make(map[*ethPeer][]common.Hash)
		//annos = make(map[*ethPeer][]common.Hash) // Set peer->hash to announce
	)
	for _, fd := range fds {
		var commitIsEmpty bool
		if fd.Commitment.X.IsZero() && fd.Commitment.Y.IsZero() {
			commitIsEmpty = true
		}

		var peers []*ethPeer
		switch {

		case fd.TxHash.Cmp(common.Hash{}) == 0 && commitIsEmpty:
			return
		case fd.TxHash.Cmp(common.Hash{}) == 0 && !commitIsEmpty:
			cmHash := common.BytesToHash(fd.Commitment.Marshal())
			peers = h.peers.peerWithOutDA(cmHash)
			// Send the DA unconditionally to a subset of our peers
			for _, peer := range peers {
				fdset[peer] = append(fdset[peer], cmHash)
			}
			log.Info("BroadcastDA---", "需要广播的fileData",cmHash)

		case fd.TxHash.Cmp(common.Hash{}) != 0 && !commitIsEmpty:
			cmHash := common.BytesToHash(fd.Commitment.Marshal())
			peers = h.peers.peerWithOutDA2(fd.TxHash,cmHash)
			// Send the DA unconditionally to a subset of our peers
			for _, peer := range peers {
				fdset[peer] = append(fdset[peer], cmHash)
			}
			log.Info("BroadcastDA---", "需要广播的DA", fd.TxHash.String())
		case fd.TxHash.Cmp(common.Hash{}) != 0 && commitIsEmpty:
			peers = h.peers.peerWithOutDA(fd.TxHash)
			// Send the DA unconditionally to a subset of our peers
			for _, peer := range peers {
				fdset[peer] = append(fdset[peer], fd.TxHash)
			}
			log.Info("BroadcastDA---", "需要广播的DA",fd.TxHash)
		}
		log.Info("全量广播----", "peer count", len(peers))
	}

	for peer, hashes := range fdset {
		directPeers++
		directCount += len(hashes)
		log.Info("BroadcastDA----", "peer info", peer.Info().Enode, "peer id", peer.ID())
		peer.AsyncSendDA(hashes)
	}

	// for peer, hashes := range annos {
	// 	annPeers++
	// 	annCount += len(hashes)
	// 	log.Info("BroadcastDA----hash","peer info",peer.Info().Enode,"peer id",peer.ID())
	// 	peer.AsyncSendPooledDAHashes(hashes)
	// }

	log.Debug("Distributed DA", "bcastpeers", directPeers, "bcastcount", directCount, "plainfds", len(fds))
}

// GetDAsshould get fileData by txHash from remote peer.
func (h *handler) GetDAsDA(hashs []common.Hash) {
	var (
		annCount int // Number of DA announced across all peers (duplicates included)
		annPeers int // Number of peers announced about DA

		annos = make(map[*ethPeer][]common.Hash) // Set peer->hash to announce
	)

	for _, hash := range hashs {
		log.Info("GetDAsDA---", "需要找的", hash.String())
		peers := h.peers.peersToGetDA()
		for _, peer := range peers[:] {
			annos[peer] = append(annos[peer], hash)
		}
	}
	for peer, hashes := range annos {
		annPeers++
		annCount += len(hashes)
		log.Info("GetDAsDA----hash", "peer info", peer.Info().Enode, "peer id", peer.ID())
		peer.RequestDAs(hashes)
	}
}

// fdBroadcastLoop announces new fileData to connected peers.
func (h *handler) fdBroadcastLoop() {
	defer h.wg.Done()
	for {
		select {
		case event := <-h.fdsCh:
			h.BroadcastDA(event.Fileds)
		case <-h.fdsSub.Err():
			return
		}
	}
}

// getDAsLoop get fileData by Txhash from connected peers.
func (h *handler) fdGetDAsLoop() {
	defer h.wg.Done()
	for {
		select {
		case event := <-h.fdHashCh:
			log.Info("fdGetDAsLoop----", "hash", event.Hashes[0].String())
			h.GetDAsDA(event.Hashes)
		case <-h.fdHashSub.Err():
			return
		}
	}
}

// enableSyncedFeatures enables the post-sync functionalities when the initial
// sync is finished.
func (h *handler) enableSyncedFeatures() {
	// Mark the local node as synced.
	h.synced.Store(true)

	// If we were running snap sync and it finished, disable doing another
	// round on next sync cycle
	if h.snapSync.Load() {
		log.Info("Snap sync complete, auto disabling")
		h.snapSync.Store(false)
	}
	if h.chain.TrieDB().Scheme() == rawdb.PathScheme {
		h.chain.TrieDB().SetBufferSize(pathdb.DefaultBufferSize)
	}
}
