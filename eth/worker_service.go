package eth

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	baseModel "github.com/ethereum/go-ethereum/eth/basemodel"
	"github.com/ethereum/go-ethereum/eth/scriptparser"
	"github.com/ethereum/go-ethereum/eth/tool"
	"github.com/ethereum/go-ethereum/log"
	los "github.com/samber/lo"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	confirmationBlockNum = 6 //6区块确认
)

var SatoshiToBitcoin = float64(100000000)

type WorkerService struct {
	gdb      *gorm.DB
	btcCli   *rpcclient.Client
	startNum uint64
}

func NewWorkerService(
	gdb *gorm.DB,
	btcCli *rpcclient.Client,
	startNum uint64,
) *WorkerService {
	return &WorkerService{
		gdb:      gdb,
		btcCli:   btcCli,
		startNum: startNum,
	}
}

func (ws *WorkerService) SetBlockHeight(ctx context.Context, chainMagicNumber string, blockHeight int64) error {
	err := ws.UpdateChain(ctx, chainMagicNumber, blockHeight)
	if err != nil {
		return err
	}

	return nil
}

func (ws *WorkerService) SyncBlock(ctx context.Context, chainMagicNumber string, blockHeight int64) error {
	beginBlockHeight := blockHeight
	endBlockHeight := blockHeight

	// 遍历获取block
	blockHeightAndBlockMap, blockHeightAndBlockHeaderMap, err := ws.GetBlocks(ctx, beginBlockHeight, endBlockHeight)
	if err != nil {
		return err
	}

	//保存区块
	err = ws.SaveBlocks(ctx, chainMagicNumber, blockHeightAndBlockHeaderMap, blockHeightAndBlockMap)
	if err != nil {
		return err
	}

	// 保存交易
	err = ws.SaveTransactions(ctx, chainMagicNumber, blockHeightAndBlockMap)
	if err != nil {
		return err
	}

	// 保存文件
	err = ws.SaveFiles(ctx, chainMagicNumber, blockHeightAndBlockMap)
	if err != nil {
		return err
	}

	return nil
}

func (ws *WorkerService) RunSync(ctx context.Context, chainMagicNumber string, chainName string) error {
	var err error

	// 获取当前区块高度
	currentBlockHeight, err := ws.GetCurrentBlockHeight(ctx)
	if err != nil {
		log.Error("get current block number fail", "err", err)
		return err
	}
	log.Info("current block number", "currentBlockHeight", currentBlockHeight)

	// 读取数据库中的区块高度
	presentBlockHeight, err := ws.GetPresentBlockHeight(ctx, chainMagicNumber, chainName)
	if err != nil {
		return err
	}
	log.Info("present block number", "presentBlockHeight", presentBlockHeight)

	// 如果当前区块高度等于数据库中的区块高度，则不处理
	if presentBlockHeight >= currentBlockHeight {
		log.Info("The current blockchain height is equal to the height of synchronized blocks in the database")
		return nil
	}

	beginBlockHeight := presentBlockHeight + 1
	endBlockHeight := los.Min([]int64{presentBlockHeight + 6, currentBlockHeight})

	// 遍历获取block
	blockHeightAndBlockMap, blockHeightAndBlockHeaderMap, err := ws.GetBlocks(ctx, beginBlockHeight, endBlockHeight)
	if err != nil {
		return err
	}

	//保存区块
	err = ws.SaveBlocks(ctx, chainMagicNumber, blockHeightAndBlockHeaderMap, blockHeightAndBlockMap)
	if err != nil {
		return err
	}

	// 保存交易
	err = ws.SaveTransactions(ctx, chainMagicNumber, blockHeightAndBlockMap)
	if err != nil {
		return err
	}

	// 保存文件
	err = ws.SaveFiles(ctx, chainMagicNumber, blockHeightAndBlockMap)
	if err != nil {
		return err
	}

	// 更新当前区块高度
	err = ws.UpdateChain(ctx, chainMagicNumber, endBlockHeight)
	if err != nil {
		return err
	}

	return nil
}

// 获取链上当前区块高度
func (ws *WorkerService) GetCurrentBlockHeight(ctx context.Context) (int64, error) {
	// 获取最新区块哈希
	blockCount, err := ws.btcCli.GetBlockCount()
	if err != nil {
		log.Error("Error getting block count", "err", err)
		return 0, err
	}

	log.Info("Block Count", "blockCount", blockCount)

	return blockCount, nil
}

func (ws *WorkerService) GetPresentBlockHeight(ctx context.Context, chainMagicNumber string, chainName string) (int64, error) {
	var gormdb *gorm.DB
	var bc baseModel.BaseChain

	now := tool.TimeStampNowSecond()

	gormdb = ws.gdb.WithContext(ctx).
		Where(baseModel.BaseChain{ChainMagicNumber: chainMagicNumber}).
		Attrs(baseModel.BaseChain{ChainName: chainName, CurrentHeight: ws.startNum, CreateAt: now}).
		FirstOrCreate(&bc)
	if gormdb.Error != nil {
		return int64(ws.startNum), gormdb.Error
	}
	return int64(bc.CurrentHeight), nil
}

// 更新当前区块高度
func (ws *WorkerService) UpdateChain(ctx context.Context, chainMagicNumber string, blockHeight int64) error {
	var gormdb *gorm.DB
	var bc baseModel.BaseChain

	gormdb = ws.gdb.WithContext(ctx).
		Where(baseModel.BaseChain{ChainMagicNumber: chainMagicNumber}).
		First(&bc)
	if gormdb.Error != nil {
		return gormdb.Error
	}

	now := tool.TimeStampNowSecond()

	bc.CurrentHeight = uint64(blockHeight)
	bc.CreateAt = now

	gormdb = ws.gdb.WithContext(ctx).Save(&bc)
	if gormdb.Error != nil {
		return gormdb.Error
	}

	return nil
}

func (ws *WorkerService) GetBlocks(ctx context.Context, from int64, to int64) (map[int64]*btcjson.GetBlockVerboseResult, map[int64]*wire.BlockHeader, error) {
	blockHeightAndBlockVerboseMap := make(map[int64]*btcjson.GetBlockVerboseResult)
	blockHeightAndBlockHeaderMap := make(map[int64]*wire.BlockHeader)

	// 遍历获取block
	for i := from; i <= to; i++ {
		blockHeight := i

		// 根据区块高度获取区块哈希
		blockHash, err := ws.btcCli.GetBlockHash(blockHeight)
		if err != nil {
			log.Error("Error getting block hash by height", "blockHeight", blockHeight, "err", err)
			return nil, nil, errors.New("get block hash by height err:" + err.Error())
		}
		log.Info("get block hash by height", "blockHash", blockHash, "blockHeight", blockHeight)

		// 使用区块哈希获取区块详细信息
		blockVerbose, err := ws.btcCli.GetBlockVerbose(blockHash)
		if err != nil {
			log.Error("Error getting block verbose by hash", "blockHash", blockHash, "err", err)
			return nil, nil, errors.New("get block verbose by hash err:" + err.Error())
		}

		// 打印区块详细信息
		log.Info("get block verbose by hash", "blockHeight", blockHeight, "blockHash", blockHash, "blockTime", blockVerbose.Time, "numberOfTransactions", len(blockVerbose.Tx))

		blockHeightAndBlockVerboseMap[i] = blockVerbose

		// 使用最新区块哈希获取区块详细信息
		blockHeader, err := ws.btcCli.GetBlockHeader(blockHash)
		if err != nil {
			log.Error("Error getting block header by hash", "blockHash", blockHash, "err", err)
			return nil, nil, errors.New("get block header by hash err:" + err.Error())
		}

		// 打印区块详细信息
		log.Info("get block header by hash", "blockHeight", blockHeight, "blockHash", blockHash, "blockTimestamp", blockHeader.Timestamp)

		blockHeightAndBlockHeaderMap[i] = blockHeader
	}

	return blockHeightAndBlockVerboseMap, blockHeightAndBlockHeaderMap, nil
}

// 保存区块
func (ws *WorkerService) SaveBlocks(ctx context.Context, chainMagicNumber string, blockHeightAndBlockHeaderMap map[int64]*wire.BlockHeader, blockHeightAndBlockVerboseMap map[int64]*btcjson.GetBlockVerboseResult) error {
	// 遍历获取block
	blockModels := make([]baseModel.BaseBlock, 0)

	now := tool.TimeStampNowSecond()

	for blockHeight, _ := range blockHeightAndBlockHeaderMap {
		block := blockHeightAndBlockVerboseMap[blockHeight]
		blockModels = append(blockModels, baseModel.BaseBlock{
			ChainMagicNumber: chainMagicNumber,
			BlockHeight:      block.Height,
			BlockHash:        block.Hash,
			Confirmations:    block.Confirmations,
			StrippedSize:     block.StrippedSize,
			Size:             block.Size,
			Weight:           block.Weight,
			MerkleRoot:       block.MerkleRoot,
			TransactionCnt:   uint32(len(block.Tx)),
			BlockTime:        block.Time,
			Nonce:            block.Nonce,
			Bits:             block.Bits,
			Difficulty:       block.Difficulty,
			PreviousHash:     block.PreviousHash,
			NextHash:         block.NextHash,
			CreateAt:         now,
		})
	}

	var gormdb *gorm.DB

	// 保存区块
	gormdb = ws.gdb.WithContext(ctx).
		Clauses(
			clause.OnConflict{DoNothing: true},
			clause.Insert{Modifier: "OR IGNORE"},
		).
		CreateInBatches(&blockModels, 5)

	if gormdb.Error != nil {
		return gormdb.Error
	}

	return nil
}

// 保存交易
func (ws *WorkerService) SaveTransactions(ctx context.Context, chainMagicNumber string, blockHeightAndBlockVerboseMap map[int64]*btcjson.GetBlockVerboseResult) error {
	txHashes := make([]string, 0)

	for _, blockVerbose := range blockHeightAndBlockVerboseMap {
		for _, tx := range blockVerbose.Tx {
			txHashes = append(txHashes, tx)
		}
	}

	transactionModels := make([]baseModel.BaseTransaction, 0)

	now := tool.TimeStampNowSecond()

	// 校验交易内容
	for _, blockVerbose := range blockHeightAndBlockVerboseMap {
		for _, tx := range blockVerbose.Tx {
			txid, err := chainhash.NewHashFromStr(tx)
			if err != nil {
				log.Error("Error converting txid string to hash", "tx", tx, "err", err)
				continue
			}

			transactionVerbose, err := ws.btcCli.GetRawTransactionVerbose(txid)
			if err != nil {
				log.Error("Error getting transaction by hash", "txid", txid, "err", err)
				continue
			}

			log.Info("Transaction Timestamp", "transactionTime", transactionVerbose.Time)

			vinDataBytes, err := json.Marshal(transactionVerbose.Vin)
			if err != nil {
				log.Error("Error marshaling vin data", "err", err)
				continue
			}

			voutDataBytes, err := json.Marshal(transactionVerbose.Vout)
			if err != nil {
				log.Error("Error marshaling vout data", "err", err)
				continue
			}

			transactionModels = append(transactionModels, baseModel.BaseTransaction{
				ChainMagicNumber: chainMagicNumber,
				Hex:              transactionVerbose.Hex,
				Txid:             transactionVerbose.Txid,
				TransactionHash:  transactionVerbose.Hash,
				Size:             transactionVerbose.Size,
				Vsize:            transactionVerbose.Vsize,
				Weight:           transactionVerbose.Weight,
				LockTime:         transactionVerbose.LockTime,
				Vin:              vinDataBytes,
				Vout:             voutDataBytes,
				BlockHash:        transactionVerbose.BlockHash,
				Confirmations:    transactionVerbose.Confirmations,
				TransactionTime:  transactionVerbose.Time,
				BlockTime:        transactionVerbose.Blocktime,
				CreateAt:         now,
			})
		}
	}

	log.Info("number of transactions", "number", len(transactionModels))

	var gormdb *gorm.DB

	// 保存交易
	gormdb = ws.gdb.WithContext(ctx).
		Clauses(
			clause.OnConflict{DoNothing: true},
			clause.Insert{Modifier: "OR IGNORE"},
		).
		CreateInBatches(&transactionModels, 5)

	if gormdb.Error != nil {
		return gormdb.Error
	}

	return nil
}

// 保存文件
func (ws *WorkerService) SaveFiles(ctx context.Context, chainMagicNumber string, blockHeightAndBlockVerboseMap map[int64]*btcjson.GetBlockVerboseResult) error {
	fileModels := make([]baseModel.BaseFile, 0)

	now := tool.TimeStampNowSecond()

	for blockHeight, blockVerbose := range blockHeightAndBlockVerboseMap {
		for _, tx := range blockVerbose.Tx {
			txid, err := chainhash.NewHashFromStr(tx)
			if err != nil {
				log.Error("Error converting txid string to hash", "tx", tx, "err", err)
				continue
			}
			transactionInscriptions, err := ws.ParseTransaction(txid)
			if err != nil {
				log.Error("Error parse transaction", "txid", txid, "err", err)
				continue
			}

			for _, v := range transactionInscriptions {
				ins := v
				contentType := string(ins.Inscription.ContentType)
				contentLength := ins.Inscription.ContentLength
				contentBody := string(ins.Inscription.ContentBody)
				index := ins.TxInIndex
				offset := ins.TxInOffset
				log.Info("INSCRIPTION Verbose", "index", index, "offset", offset, "contentType", contentType, "contentLength", contentLength)

				fileModels = append(fileModels, baseModel.BaseFile{
					ChainMagicNumber: chainMagicNumber,
					BlockHeight:      blockHeight,
					BlockHash:        blockVerbose.Hash,
					TransactionHash:  tx,
					ContentType:      contentType,
					ContentLength:    contentLength,
					ContentBody:      contentBody,
					Index:            index,
					Offset:           offset,
					CreateAt:         now,
				})
			}
		}
	}

	log.Info("number of files", "number", len(fileModels))

	var gormdb *gorm.DB

	// 保存文件
	gormdb = ws.gdb.WithContext(ctx).
		Clauses(
			clause.OnConflict{DoNothing: true},
			clause.Insert{Modifier: "OR IGNORE"},
		).
		CreateInBatches(&fileModels, 5)

	if gormdb.Error != nil {
		return gormdb.Error
	}

	return nil
}

// 解析交易
func (ws *WorkerService) ParseTransaction(txHash *chainhash.Hash) ([]*scriptparser.TransactionInscription, error) {
	rawTx, err := ws.btcCli.GetRawTransaction(txHash)
	if err != nil {
		log.Error("Get raw tx failed", "txHash", txHash, "err", err)
		return nil, err
	}
	transactionInscriptions := scriptparser.ParseInscriptionsFromTransaction(rawTx.MsgTx())
	if len(transactionInscriptions) == 0 {
		log.Info("NO INSCRIPTIONS", "txHash", txHash)
	}
	return transactionInscriptions, nil
}
