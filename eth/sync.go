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
	"bytes"
	"context"
	"errors"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/ethereum/go-ethereum"
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

const TopicAddress string = "0x9057e36780b94e7894f43d35979c11e9190d633cbc49e719ab96ad04f4eef3b4"

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
		return newEthereumChainSync(ctx, sqlDb, url, handler, chain, address, nodeType, chainName)
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

	var netParams *chaincfg.Params
	switch strings.ToLower(net) {
	case "regtest":
		netParams = &chaincfg.RegressionNetParams
	case "mainnet":
		netParams = &chaincfg.MainNetParams
	case "simnet":
		netParams = &chaincfg.SimNetParams
	case "testnet3":
		netParams = &chaincfg.TestNet3Params
	default:
		log.Error("err config bitcoinNet. should be regtest or mainnet or simnet or testnet3", "net", net)
		netParams = nil
	}

	if netParams == nil {
		return errors.New("err config bitcoinNet")
	}

	ws := NewWorkerService(cs.db, cs.btcClient, magicNumber, netParams, startNum)
	transaction2TransactionBriefs, err := ws.RunSync(ctx)
	if err != nil {
		log.Error("bitcoin sync fail", "err", err)
		return err
	}

	/*for tx, transactionBriefs := range transaction2TransactionBriefs {
		for _, transactionBrief := range transactionBriefs {
			log.Info("RunSync complete",
				"tx", tx,
				"addresses", transactionBrief.Addresses,
				"signatures", transactionBrief.Signatures,
				"blockNum", transactionBrief.BlockNum,
				"commitment", common.Bytes2Hex(transactionBrief.Commitment))
		}
	}*/
	for _, tx := range transaction2TransactionBriefs.Keys() {
		value := transaction2TransactionBriefs.Get(tx)
		transactionBriefs,ok := value.([]TransactionBrief)
		if ok {
			for _, transactionBrief := range transactionBriefs {
				log.Info("RunSync complete",
					"tx", tx,
					"addresses", transactionBrief.Addresses,
					"signatures", transactionBrief.Signatures,
					"blockNum", transactionBrief.BlockNum,
					"commitment", common.Bytes2Hex(transactionBrief.Commitment))
			}
		}
	}

	daDatas := make([]*types.DA, 0)
	for _, tx := range transaction2TransactionBriefs.Keys() {
		value := transaction2TransactionBriefs.Get(tx)
		transactionBriefs,ok := value.([]TransactionBrief)
		if ok {
			for _, transactionBrief := range transactionBriefs {
				//new commit get from memory pool
				commitment := transactionBrief.Commitment
				da, err := cs.handler.daPool.GetDAByCommit(commitment)
				if err != nil || da == nil {
					continue
				}
				ws.stateNonce++
				signData := make([][]byte, 0)
				for _, signature := range transactionBrief.Signatures {
					signData = append(signData, common.Hex2Bytes(signature))
				}
				da.Nonce = ws.stateNonce
				da.SignerAddr = transactionBrief.Addresses
				da.BlockNum = uint64(transactionBrief.BlockNum)
				da.SignData = signData
				da.TxHash = common.HexToHash(tx)
				da.ReceiveAt = time.Now()
				cs.handler.daPool.Add([]*types.DA{da}, true, false)
				daDatas = append(daDatas, da)
			}
		}

	}

	log.Info("number of daDatas", "number", len(daDatas))

	if len(daDatas) != 0 {
		parentHashData, err := db.GetMaxIDDAStateHash(cs.db)
		if err != nil {
			parentHashData = ""
		}
		parentHash := common.HexToHash(parentHashData)
		cs.handler.daPool.SendNewDAEvent(daDatas)
		_ = db.SaveBatchCommitment(cs.db, daDatas, parentHash)
		cs.handler.daPool.RemoveDA(daDatas)
	}
	cs.forced = false
	return nil
}

func (cs *chainSyncer) doEthereumSync() error {
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
		addr := common.HexToAddress(cs.chain.Config().L1Conf.CommitmentManagerProxy)
		topic := common.HexToHash(TopicAddress)
		startNum := cs.chain.Config().L1Conf.GenesisBlockNumber
		scanTimes := (l1Num - startNum) / 100
		for i := 0; i < int(scanTimes); i ++ {
			i := i
			fromBlockNum := startNum +(uint64(i) * 100)
			toBlockNum := startNum +(uint64(i+1) * 100)
			queryLog := ethereum.FilterQuery{
				FromBlock: new(big.Int).SetUint64(fromBlockNum),
				ToBlock: new(big.Int).SetUint64(toBlockNum),
				Addresses: []common.Address{
					addr,
				},
				Topics: [][]common.Hash{{
					topic,
				}},
			}
			logs, err := cs.ethClient.FilterLogs(cs.ctx,queryLog)
			blocks := make([]*types.Block,0)
			if err == nil {
				for _,logDetail := range logs{
					if err == nil {
						time.Sleep(QuickReqTime)
						requireTime := time.NewTimer(QuickReqTime)
						select {
						case <-requireTime.C:
							block,err := cs.ethClient.BlockByNumber(cs.ctx,new(big.Int).SetUint64(logDetail.BlockNumber))
							if err == nil {
								log.Info("doSync--------","block num",block.NumberU64())
								blocks = append(blocks,block)
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
				}
			}
			cs.processBlocks(blocks)
		}
		cs.forced = false
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
							//由于txData变化导致的commit位置发生变化没有修改
							commitment := slice(txData)
							commitCache.Set(tx.Hash().String(), &db.CommitDetail{
								Commit:   commitment,
								BlockNum: bc.NumberU64(),
								TxHash:   tx.Hash(),
								Time:     time.Unix(int64(bc.Time()),0 ),
							})
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
	instance, _ := contract.NewCommitmentManager(contractAddr, cs.ethClient)

	for _, logDetail := range logs {
		daDetail, err := instance.ParseSendDACommitment(*logDetail)
		if err != nil {
			log.Error("ParseSendDACommitment--", "err", err.Error())
		}
		detailFinal, ok := commitCache.Get(logDetail.TxHash.Hex())
		if ok && err == nil {
			detailFinal.NameSpaceKey = daDetail.NameSpaceKey
			detailFinal.Nonce = daDetail.Nonce.Uint64()
			detailFinal.Index = daDetail.Index.Uint64()
			detailFinal.OutOfTime = time.Unix(daDetail.Timestamp.Int64(),0)
			detailFinal.SigData = daDetail.Signatures
			detailFinal.BlockNum = logDetail.BlockNumber
			addrList, err := cs.handler.daPool.GetSender(daDetail.Signatures)
			for _, errDetail := range err {
				if errDetail != nil {
					log.Info("GetSender----", "err", errDetail.Error())
				}
			}
			list := make([]string,len(addrList))
			for i,addr := range addrList{
				list[i] = addr.Hex()
			}
			detailFinal.SignAddress = list
		}
		commitCache.Set(logDetail.TxHash.Hex(), detailFinal)
	}

	finalKeys := commitCache.Keys()
	daDatas := make([]*types.DA, 0)
	for _, txHash := range finalKeys {
		daDetail, flag := commitCache.Get(txHash)
		if flag {
			//daDetail.Time
			//new commit get from memory pool
			outTime := daDetail.Time.Add(14*24*time.Hour)
			outOfData := outTime.Before(time.Now())
			log.Info("outOfData------","outOfData",outOfData)
			if !outOfData {
				da, err := cs.handler.daPool.GetDAByCommit(daDetail.Commit)
				if err != nil {
					log.Info("processBlocks-----", "err", err.Error())
					continue
				}
				if err == nil && da != nil {
					da.NameSpaceKey = daDetail.NameSpaceKey
					da.TxHash = common.HexToHash(txHash)
					da.Nonce = daDetail.Nonce
					da.ReceiveAt = daDetail.Time
					da.SignData = daDetail.SigData
					da.BlockNum = daDetail.BlockNum
					da.SignerAddr = daDetail.SignAddress
					da.ReceiveAt = time.Now()
					da.OutOfTime = daDetail.OutOfTime
					cs.handler.daPool.Add([]*types.DA{da}, false, false)
					daDatas = append(daDatas, da)
				}
			}
		}
	}

	if len(daDatas) > 0 {
		storageAddr := common.HexToAddress(cs.chain.Config().L1Conf.StorageManagementProxy)
		storageIns, _ := contract.NewStorageManager(storageAddr, cs.ethClient)
		num := cs.chain.CurrentBlock()
		for _, da := range daDatas {
			if  bytes.Compare(da.NameSpaceKey.Bytes(),common.Hash{}.Bytes()) != 0 && cs.nodeType == "s" {
				opts := &bind.CallOpts{
					Pending:     false,
					From:        cs.address,
					BlockNumber: num.Number,
					Context:     context.Background(),
				}
				ns, _ := storageIns.NAMESPACE(opts, da.NameSpaceKey)
				flag := addressIncluded(ns.Addr, cs.address)
				if flag {
					db.SaveDACommit(cs.db, da, true)
				}
			}

			if cs.nodeType == "b" {
				log.Info("SaveDACommit-----","da",da.BlockNum)
				 db.SaveDACommit(cs.db, da, true)
			}
		}
	}

	if len(daDatas) != 0 {
		cs.handler.daPool.SendNewDAEvent(daDatas)
		cs.handler.daPool.RemoveDA(daDatas)
	}

	if len(blocks) >= 1 {
		cs.chain.SetCurrentBlock(blocks[length-1])
	} else {
		return nil
	}
	return nil
}

func addressIncluded(list []common.Address, targe common.Address) bool {
	for _, addr := range list {
		if addr == targe {
			return true
		}
	}
	return false
}

func slice(data []byte) []byte {
	digst := new(kzg.Digest)
	digst.X.SetBytes(data[132 + 32: 132+32+32])
	digst.Y.SetBytes(data[132+32+32 : 132+64+32])
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
	if block == nil || bytes.Compare(common.Hash{}.Bytes(),block.Hash().Bytes()) == 0  {
		return false,block
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
