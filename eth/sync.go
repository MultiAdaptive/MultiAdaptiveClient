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
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethdb/db"
	"gorm.io/gorm"
	"math/big"
	"time"
	"context"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

const (
	forceSyncCycle      = 10 * time.Second // Time interval to force syncs, even if few peers are available
	defaultMinSyncPeers = 5                // Amount of peers desired to start syncing
	QuickReqTime        = 1 * time.Second
	LongReqTime         = 5 * time.Second
	SyncChunkSize       = 1024
)


// chainSyncer coordinates blockchain sync components.
type chainSyncer struct {
	ctx         context.Context
	force       *time.Timer
	forced      bool
	ethclient  *ethclient.Client
	handler    *handler
	db         *gorm.DB
	chain      *core.BlockChain
	//stopCh     chan struct{}
	doneCh     chan error
}

func newChainSync(ctx context.Context,sqlDb *gorm.DB,url string,handler *handler, chain *core.BlockChain) *chainSyncer {
	eth,err := ethclient.Dial(url)
	if err != nil {
		log.Error("NewChainSync Dial url failed","err",err.Error(),"url",url)
		return nil
	}
	return &chainSyncer{
		ctx: ctx,
		handler: handler,
		ethclient: eth,
		db: sqlDb,
		chain: chain,
	}
}
func (cs *chainSyncer) startSync() {
	cs.doneCh = make(chan error,1)
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

	for  {
		if !cs.forced {
			cs.startSync()
		}

		select {
		case  <-cs.doneCh:
			cs.doneCh = nil
			cs.forced = false
			cs.force.Reset(forceSyncCycle)

		case <-cs.force.C:
			if !cs.forced {
				cs.startSync()
			}

		case  <-cs.handler.quitSync:
			if cs.doneCh != nil {
				<-cs.doneCh
			}
			return
		}

	}
}

func (cs *chainSyncer) doSync() error {
	log.Info("chainSyncer---start---doSync")
	var currentHeader uint64
	currentBlock := cs.chain.CurrentBlock()
	if currentBlock == nil || currentBlock.Number == nil {
		num,err := db.GetLastBlockNum(cs.db)
		if err != nil {
			log.Error("chainSyncer----local db err","err",err.Error())
			return err
		}
		currentHeader = num
	}else {
		currentHeader = currentBlock.Number.Uint64()
	}

	l1Num,err := cs.ethclient.BlockNumber(cs.ctx)
	if err != nil {
		log.Info("doSync-----","err",err.Error())
		return err
	}
	log.Info("doSync-----","l1num",l1Num)
	cs.forced = true

	//当前高度为零 可以直接从genesis开始同步
	if currentHeader == 0 {
		requireTime := time.NewTimer(QuickReqTime)
		startNum := cs.chain.Config().L1Conf.GenesisBlockNumber
		blocks := make([]*types.Block,SyncChunkSize)
		var shouldBreak bool
		//TODO should fix this bug
		for i := startNum;true;i += SyncChunkSize {
			for j := i;j<SyncChunkSize;j++ {
				if j > l1Num  {
					shouldBreak = true
					break
				}
				toBlockNum := j
				select {
				case <-requireTime.C:
					block,err := cs.ethclient.BlockByNumber(cs.ctx,new(big.Int).SetUint64(toBlockNum))
					if err == nil {
						blocks[j] = block
					}
				default:
				}
			}
			cs.processBlocks(blocks)
			if shouldBreak {
				break
			}
		}
	}else {
		//当前数据库有数据需要检查是否回滚
		latestBlock,_ := db.GetBlockByNum(cs.db,currentHeader)
		flag,org := cs.checkReorg(latestBlock)
		switch flag {
		case true:
			//回滚了删除从org开始的数据重新同步
			for i:=latestBlock.NumberU64();i > org.NumberU64();i-- {
				db.DeleteBlockByNum(cs.db,uint64(i))
			}
			db.SetLastBlocNum(cs.db,org.NumberU64())

		case false:
			//没回滚继续同步
			//cs.startSyncWithNum(uint64(org.BlockNum+1))
		}
		cs.startSyncWithNum(org.NumberU64()+1)
	}
	return nil
}

func (cs *chainSyncer) startSyncWithNum(num uint64) {
	requerTimer := time.NewTimer(QuickReqTime)
	for  {
		select {
		case <-requerTimer.C:
			block,err := cs.ethclient.BlockByNumber(cs.ctx,new(big.Int).SetUint64(num))
			if err == nil && block != nil{
				currentNum,_ := cs.ethclient.BlockNumber(context.Background())
				if block.NumberU64() == currentNum {
					requerTimer = time.NewTimer(LongReqTime)
				}else if(block.NumberU64() < currentNum) {
					num++
				}else {
					return
				}
				cs.processBlocks([]*types.Block{block})
			}

		}
	}
}

func (cs *chainSyncer) processBlocks(blocks []*types.Block) error {
	//save to db
	err := db.AddBatchBlocks(cs.db,blocks)
	if err != nil {
		return err
	}

	commitCache := db.NewOrderedMap()
	var latestNum uint64
	trans := make([]*types.Transaction,0)
	length := len(blocks)
	//get tx
	for _,bc := range blocks{
		if latestNum < bc.NumberU64() {
			latestNum = bc.NumberU64()
		}
		for _,tx := range bc.Transactions(){
			switch tx.To().String() {
			case cs.chain.Config().L1Conf.DomiconCommitmentProxy:
				//get data from trans data
				trans = append(trans,tx)
				txData := tx.Data()
				commitment := slice(txData)
				commitCache.Set(tx.Hash().String(),commitment)
			}
		}
		db.AddBatchTransactions(cs.db,trans,bc.Number().Int64())
	}

	checkHash := commitCache.Keys()
	receipts := make([]*types.Receipt,len(checkHash))

	for i,k := range checkHash{
		txHash := common.HexToHash(k)
		time.Sleep(1*time.Second)
		receipt,err := cs.ethclient.TransactionReceipt(cs.ctx,txHash)
		if err == nil && receipt != nil && receipt.Status == types.ReceiptStatusSuccessful{
			receipts[i] = receipt
		}else {
			commitCache.Del(k)
		}
	}
	db.AddBatchReceipts(cs.db,receipts)

	//write commitment to db


	//更新最后的区块号
	db.SetLastBlocNum(cs.db,latestNum)
	cs.chain.SetCurrentBlock(blocks[length-1])
	return nil
}

func slice(data []byte) []byte {
	dataLength := len(data)
	return data[dataLength-65:]
}

//false 没有回滚
func (cs *chainSyncer) checkReorg(block *types.Block) (bool,*types.Block) {
	var parentHash common.Hash
	blockNum := block.NumberU64()
	l1Block,err := cs.ethclient.BlockByNumber(cs.ctx,block.Number())
	if err != nil {
		log.Error("checkReorg------BlockByNumber","num",blockNum)
	}
	if block.Hash().Hex() == l1Block.Hash().String() {
		return false,block
	}else {
		parentHash = block.ParentHash()
		block,err := cs.ethclient.BlockByHash(cs.ctx,parentHash)
		if err != nil || block == nil {
			block,_ := db.GetBlockByHash(cs.db,parentHash)
			if block.NumberU64() == cs.chain.Config().L1Conf.GenesisBlockNumber  {
				return true,block
			}
			cs.checkReorg(block)
		}
	}
	return true,block
}