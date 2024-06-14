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

func handleFileDatas(backend Backend, msg Decoder, peer *Peer) error {
	// FileDatas can be processed, parse all of them and deliver to the pool
	var fds FileDataPacket
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
			peer.markFileData(cmHash)
		case fd.TxHash.Cmp(common.Hash{}) != 0 && commitIsEmpty:
			peer.markFileData(fd.TxHash)
		case fd.TxHash.Cmp(common.Hash{}) != 0 && !commitIsEmpty:
			cmHash := common.BytesToHash(commitData.Marshal())
			peer.markFileData(cmHash)
			peer.markFileData(fd.TxHash)
		}
	}
	log.Info("handleFileDatas----收到了FileDataPacket","fileDataReceiveTimes",fileDataReceiveTimes)
	return backend.Handle(peer, &fds)
}

func handleGetPooledFileDatas(backend Backend,msg Decoder,peer *Peer) error {
	var query GetPooledFileDataPacket
	if err := msg.Decode(&query); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}	
	log.Info("handleGetPooledFileDatas----获取要拿的请求","query hash",query.GetPooledFileDatasRequest[0].String())
	hashes,fds := answerGetPooledFileDatas(backend, query.GetPooledFileDatasRequest)
	return peer.ReplyPooledFileDatasRLP(query.RequestId, hashes, fds)
}

func answerGetPooledFileDatas(backend Backend, query GetPooledFileDatasRequest) ([]common.Hash, []rlp.RawValue) {
	// Gather fileDatas until the fetch or network limits is reached
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
		fd,err := backend.FildDataPool().Get(hash)
		if err != nil  {
			fd,err = backend.FildDataPool().GetDA(hash)
			if err != nil {
				continue
			}
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

func handleNewPooledFileDataHashes67(backend Backend, msg Decoder, peer *Peer) error {
	ann := new(NewPooledFileDataHashesPacket67)
	if err := msg.Decode(ann); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	// Schedule all the unknown hashes for retrieval
	for _, hash := range *ann {
		log.Info("handleNewPooledFileDataHashes67---收到了交易哈希","txHash",hash.String())
		peer.markFileData(hash)
	}
	return backend.Handle(peer, ann)
}

func handleNewPooledFileDataHashes68(backend Backend, msg Decoder, peer *Peer) error {
	ann := new(NewPooledFileDataHashesPacket68)
	if err := msg.Decode(ann); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	if len(ann.Hashes) != len(ann.Sizes) {
		return fmt.Errorf("%w: message %v: invalid len of fields: %v %v", errDecode, msg, len(ann.Hashes), len(ann.Sizes))
	}
	// Schedule all the unknown hashes for retrieval
	for _, hash := range ann.Hashes {
		log.Info("handleNewPooledFileDataHashes68---收到了交易哈希","txHash",hash.String())
		peer.markFileData(hash)
	}
	return backend.Handle(peer, ann)
}

func handlePooledFileDatas(backend Backend, msg Decoder, peer *Peer) error {
	// FileDatas can be processed, parse all of them and deliver to the pool
	var fds PooledFileDataPacket
	if err := msg.Decode(&fds); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}

	for i, fd := range fds.PooledFileDataResponse {
			// Validate and mark the remote fileData
			if fd == nil {
				return fmt.Errorf("%w: fileData %d is nil", errDecode, i)
			}
			log.Info("handlePooledFileDatas----","txHash",fd.TxHash.String())
			peer.markFileData(fd.TxHash)
	}
	requestTracker.Fulfil(peer.id, peer.version, PooledFileDatasMsg, fds.RequestId)
	return backend.Handle(peer, &fds.PooledFileDataResponse)
}

func handleResFileDatas(backend Backend, msg Decoder, peer *Peer) error {
	// A batch of fileDatas arrived to one of our previous requests
	res := new(FileDatasResponseRLPPacket)
	if err := msg.Decode(res); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	
	metaData := func () interface{} {
		var btfd BantchFileData
	  err := rlp.DecodeBytes(res.FileDatasResponse,&btfd)
		if err != nil {
			log.Error("handleResFileDatas----decode BantchFileData err","err",err.Error())
		}
		hashes := make([]common.Hash, len(btfd.FileDatas))
		for inde,data := range btfd.FileDatas {
			var fd types.DA
			rlp.DecodeBytes(data,&fd)
			hashes[inde] = fd.TxHash
		}
		return hashes
	}
	
	return peer.dispatchResponse(&Response{
		id:   res.RequestId,
		code: ResFileDatasMsg,
		Res:  &res.FileDatasResponse,
	}, metaData)
}

func handleReqFileDatas(backend Backend, msg Decoder, peer *Peer) error {
	// Decode the block fileDatas retrieval message
	var query GetFileDatasPacket
	if err := msg.Decode(&query); err != nil {
		return fmt.Errorf("%w: message %v: %v", errDecode, msg, err)
	}
	response := ServiceGetFileDatasQuery(backend.Chain(), query.GetFileDatasRequest)
	errs := peer.ReplyFileDatasMarshal(query.RequestId, response)
	if len(errs) != 0 {
		return errors.New("send Requested FileDatas failed")
	}else{
		return nil
	}
}

type BantchFileData struct {
		HeaderHash    common.Hash 	`json:"headerhash"`
		Cap						uint64				`json:"cap"`
		Length        uint64				`json:"length"`
		FileDatas     [][]byte			`json:"filedatas"`
}

// ServiceGetFileDatasQuery assembles the response to a fileData query. It is
// exposed to allow external packages to test protocol behavior.
func ServiceGetFileDatasQuery(chain *core.BlockChain, query GetFileDatasRequest) []*BantchFileData {
	// Gather state data until the fetch or network limits is reached
	var (
		bytes    int
	)

	var batch 	uint64
	var cap 		uint64

	resultList := make([]*BantchFileData, 0)

	for _, hash := range query {
		// Retrieve the requested block's fileData
		results := chain.GetFileDatasByHash(hash)
		if results == nil {
			if header := chain.GetBlockByHash(hash); header == nil{
				continue
			}
		}

		// how many batch of fileDatas should send by one header hash
		cap = uint64(len(results))
		batchFileDatas := make([][][]byte, 0)
		for index,fd := range results{
				encoded,err := rlp.EncodeToBytes(fd)
				if err != nil {
					log.Error("Failed to encode fileData", "err", err)
				}else {
					bytes += len(encoded)
					if bytes >= fileDataSoftResponseLimit || len(batchFileDatas[batch]) >= maxFileDatasServe {
						batch ++
					}

					list := batchFileDatas[index]
					if list == nil {
						list = make([][]byte, 0)
					}else {
						list = append(list, encoded)
					}
					batchFileDatas[index] = list
				}
		}
		
		//
		for _,datas := range batchFileDatas {
				btFD := &BantchFileData{
					HeaderHash: hash,
					Cap: cap,
					Length: uint64(len(datas)),
					FileDatas: datas,
				}
				resultList = append(resultList, btFD)
		}
		
	}
	return resultList
} 