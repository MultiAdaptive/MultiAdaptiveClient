// Copyright 2020 The go-ethereum Authors
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
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/protocols/eth"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/rlp"
)

// ethHandler implements the eth.Backend interface to handle the various network
// packets that are sent as replies or broadcasts.
type ethHandler handler

// FildDataPool implements eth.Backend.
func (h *ethHandler) FildDataPool() eth.FileDataPool {
	return h.fileDataPool
}

func (h *ethHandler) Chain() *core.BlockChain { return h.chain }

// NilPool satisfies the TxPool interface but does not return any tx in the
// pool. It is used to disable transaction gossip.
type NilPool struct{}

// NilPool Get always returns nil
func (n NilPool) Get(hash common.Hash) *types.Transaction { return nil }


// RunPeer is invoked when a peer joins on the `eth` protocol.
func (h *ethHandler) RunPeer(peer *eth.Peer, hand eth.Handler) error {
	return (*handler)(h).runEthPeer(peer, hand)
}

// PeerInfo retrieves all known `eth` information about a peer.
func (h *ethHandler) PeerInfo(id enode.ID) interface{} {
	if p := h.peers.peer(id.String()); p != nil {
		return p.info()
	}
	return nil
}

// AcceptTxs retrieves whether transaction processing is enabled on the node
// or if inbound transactions should simply be dropped.
func (h *ethHandler) AcceptTxs() bool {
	if h.noTxGossip {
		return false
	}
	return h.synced.Load()
}

// Handle is invoked from a peer's message handler when it receives a new remote
// message that the handler couldn't consume and serve itself.
func (h *ethHandler) Handle(peer *eth.Peer, packet eth.Packet) error {
	// Consume any broadcasts and announces, forwarding the rest to the downloader
	switch packet := packet.(type) {

	case *eth.FileDataPacket:
		return h.fdFetcher.Enqueue(peer.ID(), *packet, true)
	
	case *eth.NewPooledFileDataHashesPacket67:
		return h.fdFetcher.Notify(peer.ID(), nil, nil, *packet)

	case *eth.NewPooledFileDataHashesPacket68:	
		return h.fdFetcher.Notify(peer.ID(), nil, packet.Sizes, packet.Hashes)

	case *eth.PooledFileDataResponse:	
		return h.fdFetcher.Enqueue(peer.ID(), *packet, true)

	case *eth.FileDatasResponse:

		log.Info("handle-----receive FileDatasResponse")	
		var btfd eth.BantchFileData
	  err := rlp.DecodeBytes(*packet,&btfd)
		if err != nil {
			log.Error("handle---FileDatasResponse msg decode","err",err.Error())
		}
		//decode to fileData
		fds := make([]*types.FileData, len(btfd.FileDatas))
		for indx,data := range btfd.FileDatas {
			var fd types.FileData	
			err = rlp.DecodeBytes(data,&fd)
			if err == nil {
				fds[indx] = &fd
			}
		}
		return h.fdFetcher.Enqueue(peer.ID(),fds,true)

	default:
		return fmt.Errorf("unexpected eth packet type: %T", packet)
	}
}

