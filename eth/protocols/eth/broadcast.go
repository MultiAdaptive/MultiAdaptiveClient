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
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

const (
	// This is the target size for the packs of transactions or announcements. A
	// pack can get larger than this if a single transactions exceeds this size.
	maxTxPacketSize = 100 * 1024
)

// blockPropagation is a block propagation event, waiting for its turn in the
// broadcast queue.
type blockPropagation struct {
	block *types.Block
	td    *big.Int
}

// broadcastDA is a write loop that schedules fileData broadcasts
// to the remote peer. The goal is to have an async writer that does not lock up
// node internals and at the same time rate limits queued data.
func (p *Peer) broadcastDA() {
	var (
		queue  []common.Hash         // Queue of hashes to broadcast as full fileData
		done   chan struct{}         // Non-nil if background broadcaster is running
		fail   = make(chan error, 1) // Channel used to receive network error
		failed bool                  // Flag whether a send failed, discard everything onward
	)

	for {
		// If there's no in-flight broadcast running, check if a new one is needed
		if done == nil && len(queue) > 0 {
			// Pile fileData until we reach our allowed network limit
			var (
				hashesCount uint64
				fds         []*types.DA
				//size        common.StorageSize
			)
			for i := 0; i < len(queue) ; i++ {
				if fd,err := p.fdpool.Get(queue[i]); fd != nil && err == nil{
					fds = append(fds, fd)
				}
				hashesCount++
			}
			queue = queue[:copy(queue, queue[hashesCount:])]

			if len(fds) > 0 {
				done = make(chan struct{})
				go func() {
					log.Info("broadcastDA---节点广播","peer",p.id)
					if err := p.SendDAs(fds); err != nil {
						fail <- err
						return
					}
					close(done)
					p.Log().Trace("Sent fileData", "count", len(fds))
				}()
			}
		}
		// Transfer goroutine may or may not have been started, listen for events
		select {
		case hashes := <-p.fdBroadcast:
			// If the connection failed, discard all fileData events
			if failed {
				continue
			}
			// New batch of fileData to be broadcast, queue them (with cap)
			queue = append(queue, hashes...)
			if len(queue) > maxQueuedDA {
				// Fancy copy and resize to ensure buffer doesn't grow indefinitely
				queue = queue[:copy(queue, queue[len(queue)-maxQueuedDA:])]
			}

		case <-done:
			done = nil

		case <-fail:
			failed = true

		case <-p.term:
			return
		}
	}
}

// announceDAs is a write loop that schedules fileData broadcasts
// to the remote peer. The goal is to have an async writer that does not lock up
// node internals and at the same time rate limits queued data.
func (p *Peer) announceDAs() {
	var (
		queue  []common.Hash         // Queue of hashes to announce as fileData stubs
		done   chan struct{}         // Non-nil if background announcer is running
		fail   = make(chan error, 1) // Channel used to receive network error
		failed bool                  // Flag whether a send failed, discard everything onward
	)
	for {
		// If there's no in-flight announce running, check if a new one is needed
		if done == nil && len(queue) > 0 {
			// Pile fileData hashes until we reach our allowed network limit
			var (
				count        int
				sending      []common.Hash
				sizes 		 []uint32
				size         common.StorageSize
			)
			for count = 0; count < len(queue) && size < maxTxPacketSize; count++ {
				if fd,err := p.fdpool.Get(queue[count]); fd != nil && err == nil {
					sending = append(sending, queue[count])
					sizes = append(sizes, uint32(fd.Size()))
					size += common.HashLength
				}
			}
			// Shift and trim queue
			queue = queue[:copy(queue, queue[count:])]

			// If there's anything available to transfer, fire up an async writer
			if len(sending) > 0 {
				done = make(chan struct{})
				go func() {
					if p.version >= ETH68 {
						if err := p.sendPooledDAHashes68(sending, sizes); err != nil {
							fail <- err
							return
						}
					} else {
						if err := p.sendPooledDAHashes66(sending); err != nil {
							fail <- err
							return
						}
					}
					close(done)
					p.Log().Trace("Sent transaction announcements", "count", len(sending))
				}()
			}
		}
		// Transfer goroutine may or may not have been started, listen for events
		select {
		case hashes := <-p.fdAnnounce:
			// If the connection failed, discard all transaction events
			if failed {
				continue
			}
			// New batch of DA to be broadcast, queue them (with cap)
			queue = append(queue, hashes...)
			if len(queue) > maxQueuedDA {
				// Fancy copy and resize to ensure buffer doesn't grow indefinitely
				queue = queue[:copy(queue, queue[len(queue)-maxQueuedFdAnns:])]
			}

		case <-done:
			done = nil

		case <-fail:
			failed = true

		case <-p.term:
			return
		}
	}
}