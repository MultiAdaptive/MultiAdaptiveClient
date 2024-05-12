package eth

import (
	"context"
	"domiconexec/common"
	"domiconexec/core"
	"domiconexec/core/types"
	"domiconexec/ethclient"
	"domiconexec/ethdb/db"
	"domiconexec/log"
	"gorm.io/gorm"
	"math/big"
	"time"
)

const (
	forceSyncCycle      = 10 * time.Second // Time interval to force syncs
	SyncChunkSize       = 1024
)

const ScanContractAddress1 string = "0xadd123"
const ScanContractAddress2 string = "0xadd122"

var (
	QuickReqTime time.Duration = 1 * time.Second
	LongReqTime time.Duration = 5 *time.Second
)

type chainSyncer struct {
	ctx         context.Context
	force       *time.Timer
	forced      bool
	ethclient  *ethclient.Client
	handler    *handler
	db         *gorm.DB
	chain      *core.BlockChain
	//stopCh     chan struct{}
	doneCh     chan error   // non-nil when sync is running
}

func newChainSync(ctx context.Context,sqlDb *gorm.DB,url string,handler *handler) *chainSyncer {
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
		if cs.forced == false {
			cs.startSync()
		}

		select {
		case  <-cs.doneCh:
			cs.doneCh = nil
			cs.forced = false
			cs.force.Reset(forceSyncCycle)

		case <-cs.force.C:
			if cs.forced == false {
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
		currentHeader = currentBlock.NumberU64()
	}
	
	l1Num,err := cs.ethclient.BlockNumber(cs.ctx)
	if err != nil {
		return err
	}

	cs.forced = true

	//当前高度为零 可以直接从genesis开始同步
	if currentHeader == 0 {
		requireTime := time.NewTimer(QuickReqTime)
		genesis := cs.chain.Genesis()
		blocks := make([]*types.Block,SyncChunkSize)
		var shouldBreak bool
		//TODO should fix this bug
		for i := genesis.Number().Uint64();true;i += SyncChunkSize {
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
				}
			}
			cs.processBlocks(blocks)
			if shouldBreak {
				break
			}
		}
	}else {
		//当前数据库有数据需要检查是否回滚
		latestBlock := db.GetBlockByNum(cs.db,currentHeader)
		flag,org := cs.checkReorg(*latestBlock)
		switch flag {
		case true:
			//回滚了删除从org开始的数据重新同步
			for i:=latestBlock.BlockNum;i > org.BlockNum;i-- {
				db.DeleteBlockByNum(cs.db,uint64(i))
			}
			db.SetLastBlocNum(cs.db,uint64(org.BlockNum))

		case false:
			//没回滚继续同步
			//cs.startSyncWithNum(uint64(org.BlockNum+1))
		}
		cs.startSyncWithNum(uint64(org.BlockNum+1))
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
			case ScanContractAddress1:
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
func (cs *chainSyncer) checkReorg(block db.Block) (bool,db.Block) {
	var parentHash string
	blockNum := block.BlockNum
	l1Block,err := cs.ethclient.BlockByNumber(cs.ctx,new(big.Int).SetInt64(blockNum))
	if err != nil {
		log.Error("checkReorg------BlockByNumber","num",blockNum)
	}
	if block.BlockHash == l1Block.Hash().String() {
		return false,block
	}else {
		parentHash = block.ParentHash
		block,err := cs.ethclient.BlockByHash(cs.ctx,common.HexToHash(parentHash))
		if err != nil || block == nil {
			block := db.GetBlockByHash(cs.db,common.HexToHash(parentHash))
			//一直找到头了也不对
			//TODO fix this 头应该是genesis
			if block.BlockNum == 0  {
				return true,*block
			}
			cs.checkReorg(*block)
		}
	}
	return true,db.Block{BlockNum: 0}
}