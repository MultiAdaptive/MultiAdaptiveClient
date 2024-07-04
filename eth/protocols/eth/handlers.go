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

package eth

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
)


var fileDataReceiveTimes uint64

func handleDAs(backend Backend, msg Decoder, peer *Peer) error {
	// DAs can be processed, parse all of them and deliver to the pool
	var fds DAPacket
	if err := msg.Decode(&fds); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}

	txHash := fds[0].TxHash
	commitData := fds[0].Commitment
	var commitIsEmpty bool
	if commitData.X.IsZero() && commitData.Y.IsZero() {
		commitIsEmpty = true
	}
	var flag bool
	switch  {
	case txHash.Cmp(common.Hash{}) == 0 && commitIsEmpty:
		return errDADataIllegal
	case txHash.Cmp(common.Hash{}) == 0 && !commitIsEmpty:
		cmHash := common.BytesToHash(commitData.Marshal())
		flag = peer.knownFds.Contains(cmHash)
	case txHash.Cmp(common.Hash{}) != 0 && !commitIsEmpty:
		cmHash := common.BytesToHash(commitData.Marshal())
		flag = peer.knownFds.Contains(cmHash) || peer.knownFds.Contains(txHash)
	case txHash.Cmp(common.Hash{}) != 0 && !commitIsEmpty:
		flag = peer.knownFds.Contains(txHash)
	}

	if flag {
		return nil
	}

	fileDataReceiveTimes++

	for i, fd := range fds {
		// Validate and mark the remote fileData
		if fd == nil {
			return fmt.Errorf("%w: fileData %d is nil", errDecode, i)
		}
		commitData = fd.Commitment
		if commitData.X.IsZero() && commitData.Y.IsZero() {
			commitIsEmpty = true
		}
		switch  {
		case fd.TxHash.Cmp(common.Hash{}) == 0 && commitIsEmpty:
			return errDADataIllegal
		case fd.TxHash.Cmp(common.Hash{}) == 0 && !commitIsEmpty:
			cmHash := common.BytesToHash(commitData.Marshal())
			peer.markDA(cmHash)
		case fd.TxHash.Cmp(common.Hash{}) != 0 && commitIsEmpty:
			peer.markDA(fd.TxHash)
		case fd.TxHash.Cmp(common.Hash{}) != 0 && !commitIsEmpty:
			cmHash := common.BytesToHash(commitData.Marshal())
			peer.markDA(cmHash)
			peer.markDA(fd.TxHash)
		}
	}
	log.Info("handleDAs----收到了DAPacket","fileDataReceiveTimes",fileDataReceiveTimes)
	return backend.Handle(peer, &fds)
}

func handleGetPooledDAs(backend Backend,msg Decoder,peer *Peer) error {
	var query GetPooledDAPacket
	if err := msg.Decode(&query); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}	
	log.Info("handleGetPooledDAs----获取要拿的请求","query hash",query.GetPooledDAsRequest[0].String())
	hashes,fds := answerGetPooledDAs(backend, query.GetPooledDAsRequest)
	return peer.ReplyPooledDAsRLP(query.RequestId, hashes, fds)
}

func answerGetPooledDAs(backend Backend, query GetPooledDAsRequest) ([]common.Hash, []rlp.RawValue) {
	// Gather DA until the fetch or network limits is reached
	var (
		bytes  int
		hashes []common.Hash
		fds    []rlp.RawValue
	)
	for _, hash := range query {
		if hash.Cmp(common.Hash{}) == 0 {
			return []common.Hash{}, []rlp.RawValue{}
		}
		// Retrieve the requested fileData, skipping if unknown to us
		fd,err := backend.FildDataPool().GetDA(hash)
		if err != nil  {
			continue
		}
		if fd != nil {
			// If known, encode and queue for response packet
			if encoded, err := rlp.EncodeToBytes(fd); err != nil {
				log.Error("Failed to encode transaction", "err", err)
			} else {
				hashes = append(hashes, hash)
				fds = append(fds, encoded)
				bytes += len(encoded)
			}	
		}
	}
	return hashes, fds
}

func handleNewPooledDAHashes67(backend Backend, msg Decoder, peer *Peer) error {
	ann := new(NewPooledDAHashesPacket67)
	if err := msg.Decode(ann); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	// Schedule all the unknown hashes for retrieval
	for _, hash := range *ann {
		log.Info("handleNewPooledDAHashes67---收到了交易哈希","txHash",hash.String())
		peer.markDA(hash)
	}
	return backend.Handle(peer, ann)
}

func handleNewPooledDAHashes68(backend Backend, msg Decoder, peer *Peer) error {
	ann := new(NewPooledDAHashesPacket68)
	if err := msg.Decode(ann); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	if len(ann.Hashes) != len(ann.Sizes) {
		return fmt.Errorf("%w: message %v: invalid len of fields: %v %v", errDecode, msg, len(ann.Hashes), len(ann.Sizes))
	}
	// Schedule all the unknown hashes for retrieval
	for _, hash := range ann.Hashes {
		log.Info("handleNewPooledDAHashes68---收到了交易哈希","txHash",hash.String())
		peer.markDA(hash)
	}
	return backend.Handle(peer, ann)
}

func handlePooledDAs(backend Backend, msg Decoder, peer *Peer) error {
	// DAs can be processed, parse all of them and deliver to the pool
	var fds PooledDAPacket
	if err := msg.Decode(&fds); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}

	for i, fd := range fds.PooledDAResponse {
			// Validate and mark the remote fileData
			if fd == nil {
				return fmt.Errorf("%w: fileData %d is nil", errDecode, i)
			}
			log.Info("handlePooledDAs----","txHash",fd.TxHash.String())
			peer.markDA(fd.TxHash)
	}
	requestTracker.Fulfil(peer.id, peer.version, PooledDAsMsg, fds.RequestId)
	return backend.Handle(peer, &fds.PooledDAResponse)
}

func handleResDAs(backend Backend, msg Decoder, peer *Peer) error {
	// A batch of DA arrived to one of our previous requests
	res := new(DAsResponseRLPPacket)
	if err := msg.Decode(res); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	
	metaData := func () interface{} {
		var btfd BantchDA
	  err := rlp.DecodeBytes(res.DAsResponse,&btfd)
		if err != nil {
			log.Error("handleResDAs----decode BantchDA err","err",err.Error())
		}
		hashes := make([]common.Hash, len(btfd.DAs))
		for inde,data := range btfd.DAs {
			var fd types.DA
			rlp.DecodeBytes(data,&fd)
			hashes[inde] = fd.TxHash
		}
		return hashes
	}
	
	return peer.dispatchResponse(&Response{
		id:   res.RequestId,
		code: ResDAsMsg,
		Res:  &res.DAsResponse,
	}, metaData)
}

func handleReqDAs(backend Backend, msg Decoder, peer *Peer) error {
	// Decode the block DA retrieval message
	var query GetDAsPacket
	if err := msg.Decode(&query); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	response := ServiceGetDAsQuery(backend.Chain(), query.GetDAsRequest)
	errs := peer.ReplyDAsMarshal(query.RequestId, response)
	if len(errs) != 0 {
		return errors.New("send Requested DAs failed")
	}else{
		return nil
	}
}

type BantchDA struct {
		HeaderHash    common.Hash 	`json:"headerhash"`
		Cap						uint64				`json:"cap"`
		Length        uint64				`json:"length"`
		DAs     [][]byte			`json:"filedatas"`
}

// ServiceGetDAsQuery assembles the response to a fileData query. It is
// exposed to allow external packages to test protocol behavior.
func ServiceGetDAsQuery(chain *core.BlockChain, query GetDAsRequest) []*BantchDA {
	// Gather state data until the fetch or network limits is reached
	var (
		bytes    int
	)

	var batch 	uint64
	var cap 		uint64

	resultList := make([]*BantchDA, 0)

	for _, hash := range query {
		// Retrieve the requested block's fileData
		results := chain.GetDAsByHash(hash)
		if results == nil {
			if header := chain.GetBlockByHash(hash); header == nil{
				continue
			}
		}

		// how many batch of DA should send by one header hash
		cap = uint64(len(results))
		batchDAs := make([][][]byte, 0)
		for index,fd := range results{
				encoded,err := rlp.EncodeToBytes(fd)
				if err != nil {
					log.Error("Failed to encode fileData", "err", err)
				}else {
					bytes += len(encoded)
					if bytes >= fileDataSoftResponseLimit || len(batchDAs[batch]) >= maxDAsServe {
						batch ++
					}

					list := batchDAs[index]
					if list == nil {
						list = make([][]byte, 0)
					}else {
						list = append(list, encoded)
					}
					batchDAs[index] = list
				}
		}
		
		//
		for _,datas := range batchDAs {
				btFD := &BantchDA{
					HeaderHash: hash,
					Cap: cap,
					Length: uint64(len(datas)),
					DAs: datas,
				}
				resultList = append(resultList, btFD)
		}
		
	}
	return resultList
} 