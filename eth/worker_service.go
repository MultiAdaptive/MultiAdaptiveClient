package eth

import (
	"context"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/ethereum/go-ethereum/log"
)

const (
	confirmationBlockNum = 6 //6区块确认
)

var SatoshiToBitcoin = float64(100000000)

type WorkerService struct {
	//db     *persistence.MysqlClient
	btcCli *rpcclient.Client
}

func NewWorkerService(
// db *persistence.MysqlClient,
	btcCli *rpcclient.Client,
) *WorkerService {
	return &WorkerService{
		//db:     db,
		btcCli: btcCli,
	}
}

//func (ws *WorkerService) SetBlockHeight(ctx context.Context, req reqs.SetBlockHeightReq) error {
//	err := ws.UpdateChain(ctx, req.ChainMagicNumber, int64(req.BlockHeight))
//	if err != nil {
//		return err
//	}
//
//	return nil
//}

//func (ws *WorkerService) SyncBlock(ctx context.Context, req reqs.SyncBlockReq) error {
//	syncBlockNumber := req.BlockHeight
//	chainId := req.ChainMagicNumber
//
//	beginBlockNumber := syncBlockNumber
//	endBlockNumber := syncBlockNumber
//
//	// 遍历获取block
//	blockNumberAndBlockMap, blockNumberAndBlockHeaderMap, err := ws.GetBlocks(ctx, beginBlockNumber, endBlockNumber)
//	if err != nil {
//		return err
//	}
//
//	//保存区块
//	err = ws.SaveBlocks(ctx, chainId, blockNumberAndBlockHeaderMap, blockNumberAndBlockMap)
//	if err != nil {
//		return err
//	}
//
//	// 保存交易
//	err = ws.SaveTransactions(ctx, chainId, blockNumberAndBlockMap)
//	if err != nil {
//		return err
//	}
//
//	// 保存文件
//	err = ws.SaveFiles(ctx, chainId, blockNumberAndBlockMap)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}

//func (ws *WorkerService) ShowTransaction(ctx context.Context, req reqs.ShowTransactionReq) (*resp.ShowTransactionData, error) {
//	q := baseQuery.Use(ws.db.GDB())
//
//	transaction, err := q.BaseTransaction.WithContext(ctx).
//		Where(q.BaseTransaction.ChainMagicNumber.Eq(req.ChainMagicNumber), q.BaseTransaction.TransactionHash.Eq(req.TransactionHash)).
//		First()
//	if err != nil {
//		return nil, err
//	}
//
//	isSubmit := domain.TransactionType(uint(transaction.TransactionType)) == domain.SubmitTransactionType
//
//	var fileData string
//	if isSubmit {
//		file, err := q.BaseFile.WithContext(ctx).
//			Where(q.BaseFile.ChainMagicNumber.Eq(req.ChainMagicNumber), q.BaseFile.SourceHash.Eq(transaction.SourceHash)).
//			First()
//		if err != nil {
//			return nil, err
//		}
//		fileData = file.Data
//	}
//
//	data := &resp.ShowTransactionData{
//		ChainID:           transaction.ChainID,
//		TransactionHash:   transaction.TransactionHash,
//		BlockNumber:       transaction.BlockNumber,
//		BlockHash:         transaction.BlockHash,
//		BlockTimestamp:    transaction.BlockTimestamp,
//		TransactionIndex:  transaction.TransactionIndex,
//		TransactionType:   transaction.TransactionType,
//		FromAddress:       transaction.FromAddress,
//		ToAddress:         transaction.ToAddress,
//		TransactionStatus: transaction.TransactionStatus,
//		InputData:         transaction.InputData,
//		TransactionValue:  transaction.TransactionValue,
//		Nonce:             transaction.Nonce,
//		GasPrice:          transaction.GasPrice.String(),
//		GasUsed:           transaction.GasUsed.String(),
//		IsSubmit:          isSubmit,
//		SourceHash:        transaction.SourceHash,
//		FileData:          fileData,
//	}
//
//	return data, nil
//}

//func (ws *WorkerService) Run(ctx context.Context, chainMagicNumber string, chainName string) error {
//	var err error
//
//	// 获取当前区块高度
//	currentBlockNumber, err := ws.GetCurrentBlockNumber(ctx)
//	if err != nil {
//		return err
//	}
//	customlogger.InfoZ(fmt.Sprintf("current block number: %d", currentBlockNumber))
//
//	// 读取数据库中的区块高度
//	presentBlockNumber, err := ws.GetPresentBlockNumber(ctx, chainMagicNumber, chainName)
//	if err != nil {
//		return err
//	}
//	customlogger.Infof("present block number: %v", presentBlockNumber)
//
//	// 如果当前区块高度等于数据库中的区块高度，则不处理
//	if presentBlockNumber >= currentBlockNumber {
//		customlogger.Infof("当前链上区块高度等于数据库中已同步的区块高度")
//		return nil
//	}
//
//	beginBlockNumber := presentBlockNumber + 1
//	endBlockNumber := los.Min([]int64{presentBlockNumber + 6, currentBlockNumber})
//
//	// 遍历获取block
//	blockNumberAndBlockMap, blockNumberAndBlockHeaderMap, err := ws.GetBlocks(ctx, beginBlockNumber, endBlockNumber)
//	if err != nil {
//		return err
//	}
//
//	//保存区块
//	err = ws.SaveBlocks(ctx, chainMagicNumber, blockNumberAndBlockHeaderMap, blockNumberAndBlockMap)
//	if err != nil {
//		return err
//	}
//
//	// 保存交易
//	err = ws.SaveTransactions(ctx, chainMagicNumber, blockNumberAndBlockMap)
//	if err != nil {
//		return err
//	}
//
//	// 保存文件
//	err = ws.SaveFiles(ctx, chainMagicNumber, blockNumberAndBlockMap)
//	if err != nil {
//		return err
//	}
//
//	// 更新当前区块高度
//	err = ws.UpdateChain(ctx, chainMagicNumber, endBlockNumber)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}
//

// 获取链上当前区块高度
func (ws *WorkerService) GetCurrentBlockNumber(ctx context.Context) (int64, error) {
	// 获取最新区块哈希
	blockCount, err := ws.btcCli.GetBlockCount()
	if err != nil {
		log.Error("Error getting block count", "err", err)
		return 0, err
	}

	log.Info("Block Count", "blockCount", blockCount)

	return blockCount, nil
}

//func (ws *WorkerService) GetPresentBlockNumber(ctx context.Context, chainMagicNumber string, chainName string) (int64, error) {
//	q := baseQuery.Use(ws.db.GDB())
//
//	cn, err := q.BaseChain.WithContext(ctx).
//		Where(q.BaseChain.ChainMagicNumber.Eq(chainMagicNumber)).
//		Count()
//
//	if err != nil {
//		return 0, err
//	}
//
//	//不存在,则创建
//	if cn == 0 {
//		now := toolkit.TimeStampNowSecond()
//		bc := baseModel.BaseChain{
//			ChainName:        chainName,
//			ChainMagicNumber: chainMagicNumber,
//			CurrentHeight:    0,
//			CreateAt:         now,
//		}
//		err := q.BaseChain.WithContext(ctx).Save(&bc)
//		if err != nil {
//			return 0, err
//		}
//	}
//
//	chain, err := q.BaseChain.WithContext(ctx).
//		Where(q.BaseChain.ChainMagicNumber.Eq(chainMagicNumber)).
//		First()
//	if err != nil {
//		return 0, err
//	}
//
//	return int64(chain.CurrentHeight), nil
//}
//
//// 更新当前区块高度
//func (ws *WorkerService) UpdateChain(ctx context.Context, chainMagicNumber string, blockNumber int64) error {
//	q := baseQuery.Use(ws.db.GDB())
//
//	chain, err := q.BaseChain.WithContext(ctx).
//		Where(q.BaseChain.ChainMagicNumber.Eq(chainMagicNumber)).
//		First()
//	if err != nil {
//		return err
//	}
//
//	now := toolkit.TimeStampNowSecond()
//
//	chain.CurrentHeight = uint64(blockNumber)
//	chain.CreateAt = now
//	err = q.BaseChain.WithContext(ctx).Save(chain)
//	if err != nil {
//		return err
//	}
//
//	return nil
//}
//
//func (ws *WorkerService) GetBlocks(ctx context.Context, from int64, to int64) (map[int64]*btcjson.GetBlockVerboseResult, map[int64]*wire.BlockHeader, error) {
//	// 遍历获取block
//	blockNumberAndBlockVerboseMap := make(map[int64]*btcjson.GetBlockVerboseResult)
//	blockNumberAndBlockHeaderMap := make(map[int64]*wire.BlockHeader)
//
//	for i := from; i <= to; i++ {
//		blockNumber := i
//		blockVerbose, err := ws.btcCli.BlockVerboseByNumber(ctx, blockNumber)
//		if err != nil {
//			return nil, nil, err
//		}
//		blockNumberAndBlockVerboseMap[i] = blockVerbose
//
//		blockHeader, err := ws.btcCli.BlockHeaderByNumber(ctx, blockNumber)
//		if err != nil {
//			return nil, nil, err
//		}
//		blockNumberAndBlockHeaderMap[i] = blockHeader
//	}
//
//	return blockNumberAndBlockVerboseMap, blockNumberAndBlockHeaderMap, nil
//}
//
//// 保存区块
//func (ws *WorkerService) SaveBlocks(ctx context.Context, chainMagicNumber string, blockNumberAndBlockHeaderMap map[int64]*wire.BlockHeader, blockNumberAndBlockVerboseMap map[int64]*btcjson.GetBlockVerboseResult) error {
//	q := baseQuery.Use(ws.db.GDB())
//
//	// 遍历获取block
//	blockModels := make([]*baseModel.BaseBlock, 0)
//
//	now := toolkit.TimeStampNowSecond()
//
//	for blockNumber, _ := range blockNumberAndBlockHeaderMap {
//		block := blockNumberAndBlockVerboseMap[blockNumber]
//		blockModels = append(blockModels, &baseModel.BaseBlock{
//			ChainMagicNumber: chainMagicNumber,
//			BlockHeight:      block.Height,
//			BlockHash:        block.Hash,
//			Confirmations:    block.Confirmations,
//			StrippedSize:     block.StrippedSize,
//			Size:             block.Size,
//			Weight:           block.Weight,
//			MerkleRoot:       block.MerkleRoot,
//			TransactionCnt:   uint32(len(block.Tx)),
//			BlockTime:        block.Time,
//			Nonce:            block.Nonce,
//			Bits:             block.Bits,
//			Difficulty:       block.Difficulty,
//			PreviousHash:     block.PreviousHash,
//			NextHash:         block.NextHash,
//			CreateAt:         now,
//		})
//	}
//
//	// 保存区块
//	err := q.BaseBlock.WithContext(ctx).Clauses(clause.Insert{Modifier: "IGNORE"}).CreateInBatches(blockModels, 30)
//
//	if err != nil {
//		return err
//	}
//
//	return nil
//}
//
//// 保存交易
//func (ws *WorkerService) SaveTransactions(ctx context.Context, chainMagicNumber string, blockNumberAndBlockVerboseMap map[int64]*btcjson.GetBlockVerboseResult) error {
//	q := baseQuery.Use(ws.db.GDB())
//
//	hashes := make([]string, 0)
//
//	for _, block := range blockNumberAndBlockVerboseMap {
//		for _, tx := range block.Tx {
//			hashes = append(hashes, tx)
//		}
//	}
//
//	transactionModels := make([]*baseModel.BaseTransaction, 0)
//
//	now := toolkit.TimeStampNowSecond()
//
//	// 校验交易内容
//	for _, block := range blockNumberAndBlockVerboseMap {
//		for _, tx := range block.Tx {
//			transactionVerbose, err := ws.btcCli.TransactionVerboseById(ctx, tx)
//			if err != nil {
//				customlogger.ErrorZ(err.Error())
//				continue
//			}
//
//			vinDataBytes, err := json.Marshal(transactionVerbose.Vin)
//			if err != nil {
//				customlogger.Errorf("Error marshaling vin data: %v", err)
//			}
//
//			voutDataBytes, err := json.Marshal(transactionVerbose.Vout)
//			if err != nil {
//				customlogger.Errorf("Error marshaling vout data: %v", err)
//			}
//
//			transactionModels = append(transactionModels, &baseModel.BaseTransaction{
//				ChainMagicNumber: chainMagicNumber,
//				Hex:              transactionVerbose.Hex,
//				Txid:             transactionVerbose.Txid,
//				TransactionHash:  transactionVerbose.Hash,
//				Size:             transactionVerbose.Size,
//				Vsize:            transactionVerbose.Vsize,
//				Weight:           transactionVerbose.Weight,
//				LockTime:         transactionVerbose.LockTime,
//				Vin:              vinDataBytes,
//				Vout:             voutDataBytes,
//				BlockHash:        transactionVerbose.BlockHash,
//				Confirmations:    transactionVerbose.Confirmations,
//				TransactionTime:  transactionVerbose.Time,
//				BlockTime:        transactionVerbose.Blocktime,
//				CreateAt:         now,
//			})
//		}
//	}
//
//	customlogger.Infof("交易数量: %v", len(transactionModels))
//	// 保存交易
//	err := q.BaseTransaction.WithContext(ctx).Clauses(clause.Insert{Modifier: "IGNORE"}).CreateInBatches(transactionModels, 30)
//
//	if err != nil {
//		return err
//	}
//	return nil
//}
//
//// 保存文件
//func (ws *WorkerService) SaveFiles(ctx context.Context, chainMagicNumber string, blockNumberAndBlockMap map[int64]*btcjson.GetBlockVerboseResult) error {
//	q := baseQuery.Use(ws.db.GDB())
//
//	fileModels := make([]*baseModel.BaseFile, 0)
//
//	//now := toolkit.TimeStampNowSecond()
//
//	//for _, block := range blockNumberAndBlockMap {
//	//		for _, tx := range block.Transactions {
//	//			if tx.Type != uint(domain.SubmitTransactionType) {
//	//				continue
//	//			}
//	//			file, err := ws.eth.FileByHash(ctx, tx.SourceHash)
//	//			if err != nil {
//	//				customlogger.ErrorZ(err.Error())
//	//				continue
//	//			}
//	//
//	//			fileModels = append(fileModels, &baseModel.BaseFile{
//	//				ChainID:         chainId,
//	//				SourceHash:      tx.SourceHash.Hex(),
//	//				Sender:          file.Sender.Hex(),
//	//				Submitter:       file.Submitter.Hex(),
//	//				Length:          uint64(file.Length),
//	//				Index:           uint64(file.Index),
//	//				Commitment:      utils.ByteToHex(file.Commitment),
//	//				Data:            utils.ByteToHex(file.Data),
//	//				Sign:            utils.ByteToHex(file.Sign),
//	//				TransactionHash: tx.Hash.Hex(),
//	//				CreateAt:        now,
//	//			})
//	//		}
//	//}
//
//	customlogger.Infof("文件数量: %v", len(fileModels))
//	// 保存文件
//	err := q.BaseFile.WithContext(ctx).Clauses(clause.Insert{Modifier: "IGNORE"}).CreateInBatches(fileModels, 30)
//
//	if err != nil {
//		return err
//	}
//	return nil
//}
