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
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/contract"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth/tool"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethdb/db"
	"github.com/ethereum/go-ethereum/log"
	"gorm.io/gorm"
	"math/big"
	"strings"
	"time"
)

const (
	forceSyncCycle      = 10 * time.Second // Time interval to force syncs, even if few peers are available
	defaultMinSyncPeers = 5                // Amount of peers desired to start syncing
	QuickReqTime        = 1 * time.Second
	LongReqTime         = 5 * time.Second
	SyncChunkSize       = 10
)

// chainSyncer coordinates blockchain sync components.
type chainSyncer struct {
	ctx       context.Context
	force     *time.Timer
	forced    bool
	ethClient *ethclient.Client
	btcClient *rpcclient.Client
	handler   *handler
	db        *gorm.DB
	nodeType  string
	address   common.Address
	chainName string
	chain     *core.BlockChain
	cancel    context.CancelFunc
	doneCh    chan error
}

func newChainSync(
	ctx context.Context,
	sqlDb *gorm.DB,
	url string,
	host string,
	user string,
	password string,
	address common.Address,
	handler *handler,
	chain *core.BlockChain,
	nodeType string,
	chainName string) *chainSyncer {
	log.Info("newChainSync", "chainName", chainName)

	switch strings.ToLower(chainName) {
	case "ethereum", "eth":
		return newEthereumChainSync(ctx, sqlDb, url, handler, chain, address ,nodeType, chainName)
	case "bitcoin", "btc":
		return newBitcoinChainSync(ctx, sqlDb, host, user, password, handler, chain, nodeType, chainName)
	default:
		return nil
	}
}

func newEthereumChainSync(
	ctx context.Context,
	sqlDb *gorm.DB,
	url string,
	handler *handler,
	chain *core.BlockChain,
	address common.Address,
	nodeType string,
	chainName string) *chainSyncer {
	log.Info("newEthereumChainSync", "url", url)

	ethClient, err := ethclient.Dial(url)
	if err != nil {
		log.Error("newEthereumChainSync failed", "err", err.Error(), "url", url)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())

	return &chainSyncer{
		ctx:       ctx,
		handler:   handler,
		ethClient: ethClient,
		db:        sqlDb,
		nodeType:  nodeType,
		address:   address,
		chainName: chainName,
		chain:     chain,
		cancel:    cancel,
	}
}

func newBitcoinChainSync(
	ctx context.Context,
	sqlDb *gorm.DB,
	host string,
	user string,
	password string,
	handler *handler,
	chain *core.BlockChain,
	nodeType string,
	chainName string) *chainSyncer {
	log.Info("newBitcoinChainSync", "host", host, "user", user, "password", password)

	cleanedHost := tool.TrimPrefixes(host, "http://", "https://")

	connCfg := &rpcclient.ConnConfig{
		Host:         cleanedHost,
		User:         user,
		Pass:         password,
		HTTPPostMode: true,
		DisableTLS:   true,
	}

	btcClient, err := rpcclient.New(connCfg, nil)

	if err != nil {
		log.Error("newBitcoinChainSync failed", "err", err.Error(), "host", host, "user", user, "password", password)
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())

	return &chainSyncer{
		ctx:       ctx,
		handler:   handler,
		btcClient: btcClient,
		db:        sqlDb,
		nodeType:  nodeType,
		chainName: chainName,
		chain:     chain,
		cancel:    cancel,
	}
}

func (cs *chainSyncer) startSync() {
	cs.doneCh = make(chan error, 1)
	go func() {
		cs.doneCh <- cs.doSync()
	}()
}

func (cs *chainSyncer) loop() {
	defer cs.handler.wg.Done()
	cs.handler.fdFetcher.Start()
	defer cs.handler.fdFetcher.Stop()

	cs.force = time.NewTimer(forceSyncCycle)
	defer cs.force.Stop()

	for {
		select {
		case <-cs.doneCh:
			cs.doneCh = nil
			cs.forced = false
			cs.force.Reset(forceSyncCycle)

		case <-cs.force.C:
			if !cs.forced {
				cs.startSync()
			}
			cs.force.Reset(forceSyncCycle)
			log.Info("force sync cycle time out", "is sync", !cs.forced)

		case <-cs.handler.quitSync:
			log.Info("chainSyncer---loop quit")
			cs.cancel()
			if cs.doneCh != nil {
				<-cs.doneCh
			}
			return
		}
	}
}

func (cs *chainSyncer) doSync() error {
	log.Info("doSync-----")
	switch strings.ToLower(cs.chainName) {
	case "ethereum", "eth":
		return cs.doEthereumSync()
	case "bitcoin", "btc":
		return cs.doBitcoinSync()
	default:
		return nil
	}
}

func (cs *chainSyncer) doBitcoinSync() error {
	log.Info("doBitcoinSync-----")
	if cs.forced == true {
		return errors.New("chainSyncer is syncing")
	}
	magicNumber := cs.chain.Config().L1Conf.BitcoinMagicNumber
	net := cs.chain.Config().L1Conf.BitcoinNet
	startNum := cs.chain.Config().L1Conf.GenesisBlockNumber
	cs.forced = true
	ctx := context.Background()
	ws := NewWorkerService(cs.db, cs.btcClient, magicNumber, net, startNum)
	transaction2Commitments, err := ws.RunSync(ctx)
	if err != nil {
		log.Error("bitcoin sync fail", "err", err)
		return err
	}

	for tx, commitments := range transaction2Commitments {
		for _, commitment := range commitments {
			log.Info("Sync", "tx", tx, "commitment", common.Bytes2Hex(commitment))
		}
	}

	daDatas := make([]*types.DA, 0)

	for tx, commitments := range transaction2Commitments {
		for _, commitment := range commitments {
			//new commit get from memory pool
			da, err := cs.handler.fileDataPool.GetDAByCommit(commitment)
			if err != nil || da == nil {
				continue
			}
			da.TxHash = common.HexToHash(tx)
			da.ReceiveAt = time.Now()
			cs.handler.fileDataPool.Add([]*types.DA{da}, true, false)
			daDatas = append(daDatas, da)
		}
	}

	log.Info("number of daDatas", "number", len(daDatas))

	if len(daDatas) != 0 {
		parentHashData, err := db.GetMaxIDDAStateHash(cs.db)
		if err != nil {
			parentHashData = ""
		}
		parentHash := common.HexToHash(parentHashData)
		cs.handler.fileDataPool.SendNewFileDataEvent(daDatas)
		_ = db.SaveBatchCommitment(cs.db, daDatas, parentHash)
		cs.handler.fileDataPool.RemoveFileData(daDatas)
	}
	cs.forced = false
	return nil
}

func (cs *chainSyncer) doEthereumSync() error {
	log.Info("doEthereumSync-----")
	if cs.forced == true {
		return errors.New("chainSyncer is syncing")
	}
	var currentHeader uint64
	currentBlock := cs.chain.CurrentBlock()
	if currentBlock == nil || currentBlock.Number == nil || currentBlock.Number.Uint64() == 0 {
		num, err := db.GetLastBlockNum(cs.db)
		if err != nil {
			return err
		}
		blockNum, err := db.GetMaxIDBlockNum(cs.db)
		if err != nil {
			log.Info("doEthereumSync----GetMaxIDBlockNum", "err", err.Error())
		}
		log.Info("doEthereumSync----GetMaxIDBlockNum", "blockNum", blockNum)
		if uint64(blockNum) >= num {
			currentHeader = uint64(blockNum)
		} else {
			currentHeader = num
		}
	} else {
		currentHeader = currentBlock.Number.Uint64()
	}

	l1Num, err := cs.ethClient.BlockNumber(cs.ctx)
	if err != nil {
		return err
	}
	log.Info("doSync-----", "l1num", l1Num, "currentHeader", currentHeader)
	cs.forced = true

	//当前高度为零 可以直接从genesis开始同步
	if currentHeader == 0 {
		requireTime := time.NewTimer(QuickReqTime)
		startNum := cs.chain.Config().L1Conf.GenesisBlockNumber
		var shouldBreak bool
		for i := startNum; true; i += SyncChunkSize {
			log.Info("chainSyncer---", "i----", i)
			blocks := make([]*types.Block, 0)
			for j := i; j < i+SyncChunkSize; j++ {
				if j >= l1Num {
					shouldBreak = true
					log.Info("doSync-----shouldBreak----", "j", j, "l1Num", l1Num)
					break
				}
				toBlockNum := j
				select {
				case <-requireTime.C:
					block, err := cs.ethClient.BlockByNumber(cs.ctx, new(big.Int).SetUint64(toBlockNum))
					if err == nil {
						blocks = append(blocks, block)
						requireTime.Reset(QuickReqTime)
					} else {
						cs.forced = false
						return err
					}
				case <-cs.ctx.Done():
					log.Info("chainSyncer-----", "chainSyncer stop")
					return nil
				}
			}
			cs.processBlocks(blocks)
			if shouldBreak {
				cs.forced = false
				break
			}
		}
	} else {
		log.Info("chainSyncer---start---", "currentHeader", currentHeader)
		//当前数据库有数据需要检查是否回滚
		latestBlock, err := db.GetBlockByNum(cs.db, currentHeader)
		if err != nil {
			return err
		}
		flag, org := cs.checkReorg(latestBlock)
		switch flag {
		case true:
			//回滚了删除从org开始的数据重新同步
			for i := latestBlock.NumberU64(); i > org.NumberU64(); i-- {
				db.DeleteBlockByNum(cs.db, uint64(i))
			}
			num, err := db.GetLastBlockNum(cs.db)
			db.Begin(cs.db)
			if err != nil {
				db.AddLastBlockNum(db.Tx, org.NumberU64())
			} else {
				db.UpDataLastBlocNum(db.Tx, num, org.NumberU64())
			}
			db.Commit(db.Tx)
		case false:
			//没回滚继续同步
			//cs.startSyncWithNum(uint64(org.BlockNum+1))
		}
		cs.startSyncWithNum(org.NumberU64() + 1)
	}
	return nil
}

func (cs *chainSyncer) startSyncWithNum(num uint64) error {
	requerTimer := time.NewTimer(QuickReqTime)
	for {
		select {
		case <-requerTimer.C:
			block, err := cs.ethClient.BlockByNumber(cs.ctx, new(big.Int).SetUint64(num))
			if err == nil && block != nil {
				currentNum, _ := cs.ethClient.BlockNumber(context.Background())
				if block.NumberU64() == currentNum {
					cs.forced = false
					return nil
				} else if block.NumberU64() < currentNum {
					num++
					requerTimer.Reset(QuickReqTime)
				} else {
					return nil
				}
				cs.processBlocks([]*types.Block{block})
			}
		case <-cs.ctx.Done():
			return nil
		}
	}
}

func (cs *chainSyncer) processBlocks(blocks []*types.Block) error {
	//save to db
	db.Begin(cs.db)
	err := db.AddBatchBlocks(db.Tx, blocks)
	if err != nil {
		log.Error("processBlocks-----", "AddBatchBlocks---err", err.Error())
		return err
	}
	commitCache := db.NewOrderedMap()
	var latestNum uint64
	length := len(blocks)
	//get tx
	for _, bc := range blocks {
		trans := make([]*types.Transaction, 0)
		if bc != nil {
			if latestNum < bc.NumberU64() {
				latestNum = bc.NumberU64()
			}
			for _, tx := range bc.Transactions() {
				if tx.To() != nil {
					switch tx.To().String() {
					case cs.chain.Config().L1Conf.CommitmentManagerProxy:
						//get data from trans data
						trans = append(trans, tx)
						txData := tx.Data()
						if len(txData) != 0 {
							commitment := slice(txData)
							commitCache.Set(tx.Hash().String(),&db.CommitDetail{
								Commit:  commitment,
								BlockNum: bc.NumberU64(),
								TxHash: tx.Hash(),
								Time:  time.Unix(0, int64(bc.Time())),
							} )
						}
					}
				}
			}
			if len(trans) != 0 {
				err := db.AddBatchTransactions(db.Tx, trans, bc.Number().Int64())
				if err != nil {
					log.Error("AddBatchTransactions----", "err", err.Error())
				}
			}
		}
	}

	checkHash := commitCache.Keys()
	receipts := make([]*types.Receipt, len(checkHash))

	for i, k := range checkHash {
		txHash := common.HexToHash(k)
		time.Sleep(1 * time.Second)
		receipt, err := cs.ethClient.TransactionReceipt(cs.ctx, txHash)
		if err == nil && receipt != nil && receipt.Status == types.ReceiptStatusSuccessful {
			receipts[i] = receipt
		} else {
			commitCache.Del(k)
		}
	}
	err = db.AddBatchReceipts(db.Tx, receipts)
	if err != nil {
		log.Error("AddBatchReceipts--", "err", err.Error())
	}

	logs := make([]*types.Log, 0)
	for _, receipt := range receipts {
		logs = append(logs, receipt.Logs...)
	}

	err = db.AddBatchLogs(db.Tx, logs)
	if err != nil {
		log.Error("AddBatchLogs--", "err", err.Error())
	}
	db.Commit(db.Tx)
	contractAddr := common.HexToAddress(cs.chain.Config().L1Conf.CommitmentManagerProxy)
	instance, _ := contract.NewCommitmentManager(contractAddr,cs.ethClient)

	for _,logDetail := range logs{
		daDetail,err := instance.ParseSendDACommitment(*logDetail)
		if err != nil {
			log.Error("ParseSendDACommitment--", "err", err.Error())
		}
		detailFinal,ok := commitCache.Get(logDetail.TxHash.Hex())
		if ok&&err==nil {
			detailFinal.NameSpaceId = daDetail.NameSpaceId
			detailFinal.Nonce = daDetail.Nonce.Uint64()
			detailFinal.Root = daDetail.Root
			detailFinal.SigData = daDetail.Signatures
			detailFinal.BlockNum = logDetail.BlockNumber
			addrList,err := cs.handler.fileDataPool.GetSender(daDetail.Signatures)
			for _,errDetail := range err {
				if errDetail != nil {
					log.Info("GetSender----","err",errDetail.Error())
				}
			}
			detailFinal.SignAddress = addrList
		}
		commitCache.Set(logDetail.TxHash.Hex(),detailFinal)
	}

	finalKeys := commitCache.Keys()
	daDatas := make([]*types.DA, 0)
	for _, txHash := range finalKeys {
		daDetail, flag := commitCache.Get(txHash)
		if flag {
			//new commit get from memory pool
			da, err := cs.handler.fileDataPool.GetDAByCommit(daDetail.Commit)
			if err != nil {
				log.Info("processBlocks-----", "err", err.Error())
			}
			if err == nil && da != nil {
				da.NameSpaceID = daDetail.NameSpaceId
				da.TxHash = common.HexToHash(txHash)
				da.Nonce = daDetail.Nonce
				da.ReceiveAt = daDetail.Time
				da.SignData = daDetail.SigData
				da.BlockNum = daDetail.BlockNum
				da.SignerAddr = daDetail.SignAddress
				da.Root = daDetail.Root
				da.ReceiveAt = time.Now()
				cs.handler.fileDataPool.Add([]*types.DA{da}, true, false)
				daDatas = append(daDatas, da)
			}
		}
	}
	
	if len(daDatas) > 0 {
		parentHashData, err := db.GetMaxIDDAStateHash(cs.db)
		if err != nil {
			parentHashData = ""
		}
		parentHash := common.HexToHash(parentHashData)
		storageAddr := common.HexToAddress(cs.chain.Config().L1Conf.StorageManagementProxy)
		storageIns, _ := contract.NewStorageManager(storageAddr,cs.ethClient)
		num := cs.chain.CurrentBlock()
		for _,da := range daDatas{
			log.Info("processBlocks------存数据----1","commit Hash",common.BytesToHash(da.Commitment.Marshal()).Hex(),"num",num.Number.Uint64())

			if da.NameSpaceID.Uint64() != 0 && cs.nodeType == "s" {
				opts := &bind.CallOpts{
					Pending: false,
					From: cs.address,
					BlockNumber: num.Number,
					Context: context.Background(),
				}

				ns,_ := storageIns.NAMESPACE(opts,da.NameSpaceID)
				flag :=  addressIncluded(ns.Addr,cs.address)
				if flag {
					db.SaveDACommit(cs.db,da,true,parentHash)
				}
			}

			if cs.nodeType == "b" {
				log.Info("processBlocks------存数据----","commit Hash",common.BytesToHash(da.Commitment.Marshal()).Hex())
				currentHash,_ := db.SaveDACommit(cs.db,da,true,parentHash)
				parentHash = currentHash
			}

		}
	}

	if len(daDatas) != 0 {
		cs.handler.fileDataPool.SendNewFileDataEvent(daDatas)
		cs.handler.fileDataPool.RemoveFileData(daDatas)
	}

	if len(blocks) >= 1 {
		cs.chain.SetCurrentBlock(blocks[length-1])
	} else {
		return nil
	}
	return nil
}

func addressIncluded(list []common.Address,targe common.Address) bool {
	for _,addr  := range list{
		if addr == targe {
			return true
		}
	}
	return false
}


func slice(data []byte) []byte {
	digst := new(kzg.Digest)
	digst.X.SetBytes(data[132 : 132+32])
	digst.Y.SetBytes(data[132+32 : 132+64])
	return digst.Marshal()
}

// false 没有回滚
func (cs *chainSyncer) checkReorg(block *types.Block) (bool, *types.Block) {
	var parentHash common.Hash
	blockNum := block.NumberU64()
	time.After(QuickReqTime)
	l1Block, err := cs.ethClient.BlockByNumber(cs.ctx, block.Number())
	if err != nil {
		log.Error("checkReorg------BlockByNumber", "num", blockNum)
	}
	if block.Hash().Hex() == l1Block.Hash().String() {
		return false, block
	} else {
		parentHash = block.ParentHash()
		block, err := cs.ethClient.BlockByHash(cs.ctx, parentHash)
		if err != nil || block == nil {
			block, _ := db.GetBlockByHash(cs.db, parentHash)
			if block.NumberU64() == cs.chain.Config().L1Conf.GenesisBlockNumber {
				return true, block
			}
			cs.checkReorg(block)
		}
	}
	return true, block
}
