package eth

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/ethereum/go-ethereum/common"
	baseModel "github.com/ethereum/go-ethereum/eth/basemodel"
	"github.com/ethereum/go-ethereum/eth/scriptparser"
	"github.com/ethereum/go-ethereum/eth/tool"
	"github.com/ethereum/go-ethereum/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	confirmationBlockNum = 6 //6区块确认
	CUSTOM_CONTENT_TYPE  = "MultiAaptiveCM;charset=utf-8"
)

var SatoshiToBitcoin = float64(100000000)

type WorkerService struct {
	gdb         *gorm.DB
	btcCli      *rpcclient.Client
	magicNumber string
	net         string
	startNum    uint64
}

func NewWorkerService(
	gdb *gorm.DB,
	btcCli *rpcclient.Client,
	magicNumber string,
	net string,
	startNum uint64,
) *WorkerService {
	return &WorkerService{
		gdb:         gdb,
		btcCli:      btcCli,
		magicNumber: magicNumber,
		net:         net,
		startNum:    startNum,
	}
}

func (ws *WorkerService) SetBlockHeight(ctx context.Context, blockHeight int64) error {
	err := ws.UpdateChain(ctx, blockHeight)
	if err != nil {
		return err
	}

	return nil
}

func (ws *WorkerService) SyncBlock(ctx context.Context, blockHeight int64) error {
	beginBlockHeight := blockHeight
	endBlockHeight := blockHeight

	// 遍历获取block
	blockHeightAndBlockMap, blockHeightAndBlockHeaderMap, err := ws.GetBlocks(ctx, beginBlockHeight, endBlockHeight)
	if err != nil {
		return err
	}

	//保存区块
	err = ws.SaveBlocks(ctx, blockHeightAndBlockHeaderMap, blockHeightAndBlockMap)
	if err != nil {
		return err
	}

	// 保存交易
	err = ws.SaveTransactions(ctx, blockHeightAndBlockMap)
	if err != nil {
		return err
	}

	// 保存文件
	_, err = ws.SaveFiles(ctx, blockHeightAndBlockMap)
	if err != nil {
		return err
	}

	return nil
}

func (ws *WorkerService) RunSync(ctx context.Context) (map[string][][]byte, error) {
	var err error

	// 获取当前区块高度
	currentBlockHeight, err := ws.GetCurrentBlockHeight(ctx)
	if err != nil {
		log.Error("get current block number fail", "err", err)
		return nil, err
	}
	log.Info("current block number", "currentBlockHeight", currentBlockHeight)

	// 读取数据库中的区块高度
	presentBlockHeight, err := ws.GetPresentBlockHeight(ctx)
	if err != nil {
		return nil, err
	}
	log.Info("present block number", "presentBlockHeight", presentBlockHeight)

	// 如果当前区块高度等于数据库中的区块高度，则不处理
	if presentBlockHeight >= currentBlockHeight {
		log.Info("The current blockchain height is not greater than the height of synchronized blocks in the database")
		return nil, nil
	}

	beginBlockHeight := presentBlockHeight + 1
	endBlockHeight := currentBlockHeight

	// 遍历获取block
	blockHeightAndBlockMap, blockHeightAndBlockHeaderMap, err := ws.GetBlocks(ctx, beginBlockHeight, endBlockHeight)
	if err != nil {
		return nil, err
	}

	//保存区块
	err = ws.SaveBlocks(ctx, blockHeightAndBlockHeaderMap, blockHeightAndBlockMap)
	if err != nil {
		return nil, err
	}

	// 保存交易
	err = ws.SaveTransactions(ctx, blockHeightAndBlockMap)
	if err != nil {
		return nil, err
	}

	// 保存文件
	transaction2Commitments, err := ws.SaveFiles(ctx, blockHeightAndBlockMap)
	if err != nil {
		return nil, err
	}

	// 更新当前区块高度
	err = ws.UpdateChain(ctx, endBlockHeight)
	if err != nil {
		return nil, err
	}

	return transaction2Commitments, nil
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

func (ws *WorkerService) GetPresentBlockHeight(ctx context.Context) (int64, error) {
	var gormdb *gorm.DB
	var bc baseModel.BaseChain

	now := tool.TimeStampNowSecond()

	gormdb = ws.gdb.WithContext(ctx).
		Where(baseModel.BaseChain{MagicNumber: ws.magicNumber, Net: ws.net}).
		Attrs(baseModel.BaseChain{CurrentHeight: ws.startNum, CreateAt: now}).
		FirstOrCreate(&bc)
	if gormdb.Error != nil {
		return int64(ws.startNum), gormdb.Error
	}
	return int64(bc.CurrentHeight), nil
}

// 更新当前区块高度
func (ws *WorkerService) UpdateChain(ctx context.Context, blockHeight int64) error {
	var gormdb *gorm.DB
	var bc baseModel.BaseChain

	gormdb = ws.gdb.WithContext(ctx).
		Where(baseModel.BaseChain{MagicNumber: ws.magicNumber, Net: ws.net}).
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

		blockHeightAndBlockHeaderMap[i] = blockHeader
	}

	return blockHeightAndBlockVerboseMap, blockHeightAndBlockHeaderMap, nil
}

// 保存区块
func (ws *WorkerService) SaveBlocks(ctx context.Context, blockHeightAndBlockHeaderMap map[int64]*wire.BlockHeader, blockHeightAndBlockVerboseMap map[int64]*btcjson.GetBlockVerboseResult) error {
	// 遍历获取block
	blockModels := make([]baseModel.BaseBlock, 0)

	now := tool.TimeStampNowSecond()

	for blockHeight, _ := range blockHeightAndBlockHeaderMap {
		block := blockHeightAndBlockVerboseMap[blockHeight]
		blockModels = append(blockModels, baseModel.BaseBlock{
			MagicNumber:    ws.magicNumber,
			Net:            ws.net,
			BlockHeight:    block.Height,
			BlockHash:      block.Hash,
			Confirmations:  block.Confirmations,
			StrippedSize:   block.StrippedSize,
			Size:           block.Size,
			Weight:         block.Weight,
			MerkleRoot:     block.MerkleRoot,
			TransactionCnt: uint32(len(block.Tx)),
			BlockTime:      block.Time,
			Nonce:          block.Nonce,
			Bits:           block.Bits,
			Difficulty:     block.Difficulty,
			PreviousHash:   block.PreviousHash,
			NextHash:       block.NextHash,
			CreateAt:       now,
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
func (ws *WorkerService) SaveTransactions(ctx context.Context, blockHeightAndBlockVerboseMap map[int64]*btcjson.GetBlockVerboseResult) error {
	txHashes := make([]string, 0)

	for _, blockVerbose := range blockHeightAndBlockVerboseMap {
		for _, tx := range blockVerbose.Tx {
			txHashes = append(txHashes, tx)
		}
	}

	transactionModels := make([]baseModel.BaseTransaction, 0)

	now := tool.TimeStampNowSecond()

	// 校验交易内容
	for blockHeight, blockVerbose := range blockHeightAndBlockVerboseMap {
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

			fee, err := ws.GetTransactionFee(tx)
			if err != nil {
				log.Debug("Error get transaction fee", "tx", tx, "err", err)
			}

			transactionModels = append(transactionModels, baseModel.BaseTransaction{
				MagicNumber:     ws.magicNumber,
				Net:             ws.net,
				Hex:             transactionVerbose.Hex,
				Txid:            transactionVerbose.Txid,
				TransactionHash: transactionVerbose.Hash,
				Size:            transactionVerbose.Size,
				Vsize:           transactionVerbose.Vsize,
				Weight:          transactionVerbose.Weight,
				LockTime:        transactionVerbose.LockTime,
				Vin:             vinDataBytes,
				Vout:            voutDataBytes,
				BlockHeight:     blockHeight,
				BlockHash:       transactionVerbose.BlockHash,
				Confirmations:   transactionVerbose.Confirmations,
				TransactionTime: transactionVerbose.Time,
				BlockTime:       transactionVerbose.Blocktime,
				Fee:             fee,
				CreateAt:        now,
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
func (ws *WorkerService) SaveFiles(ctx context.Context, blockHeightAndBlockVerboseMap map[int64]*btcjson.GetBlockVerboseResult) (map[string][][]byte, error) {
	fileModels := make([]baseModel.BaseFile, 0)

	transaction2Commitments := make(map[string][][]byte)

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
			log.Info("parse transaction", "tx", tx, "transactionInscriptions", transactionInscriptions)

			commitments := make([][]byte, 0)
			for _, ins := range transactionInscriptions {
				contentType := ins.Inscription.ContentType
				contentLength := ins.Inscription.ContentLength
				contentBody := ins.Inscription.ContentBody
				commitment := contentBody
				index := ins.TxInIndex
				offset := ins.TxInOffset
				log.Info("INSCRIPTION Verbose", "index", index, "offset", offset, "contentType", string(contentType), "contentLength", contentLength, "contentBody", common.Bytes2Hex(contentBody))
				if string(contentType) != CUSTOM_CONTENT_TYPE {
					log.Info("Not custom content", "contentType", string(contentType))
					continue
				}

				fileModels = append(fileModels, baseModel.BaseFile{
					MagicNumber:     ws.magicNumber,
					Net:             ws.net,
					BlockHeight:     blockHeight,
					BlockHash:       blockVerbose.Hash,
					TransactionHash: tx,
					ContentType:     contentType,
					ContentLength:   contentLength,
					ContentBody:     contentBody,
					Index:           index,
					Offset:          offset,
					CreateAt:        now,
				})
				commitments = append(commitments, commitment)
			}

			transaction2Commitments[tx] = commitments
		}
	}

	log.Info("number of files", "number", len(fileModels))
	log.Info("number of commitments", "number", len(transaction2Commitments))

	var gormdb *gorm.DB

	// 保存文件
	gormdb = ws.gdb.WithContext(ctx).
		Clauses(
			clause.OnConflict{DoNothing: true},
			clause.Insert{Modifier: "OR IGNORE"},
		).
		CreateInBatches(&fileModels, 5)

	if gormdb.Error != nil {
		return nil, gormdb.Error
	}

	return transaction2Commitments, nil
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
	log.Info("SOME INSCRIPTIONS", "txHash", txHash, "number", len(transactionInscriptions))
	return transactionInscriptions, nil
}

func (ws *WorkerService) GetTransactionFee(txID string) (float64, error) {
	// 将交易 ID 转换为 ShaHash
	txHash, err := chainhash.NewHashFromStr(txID)
	if err != nil {
		return 0, errors.New("invalid transaction ID:" + err.Error())
	}

	// 获取原始交易
	rawTx, err := ws.btcCli.GetRawTransactionVerbose(txHash)
	if err != nil {
		return 0, err
	}

	// 解析原始交易
	var inputSum, outputSum float64

	for _, vin := range rawTx.Vin {
		vinTxHash, err := chainhash.NewHashFromStr(vin.Txid)
		if err != nil {
			return 0, err
		}

		vinTx, err := ws.btcCli.GetRawTransactionVerbose(vinTxHash)
		if err != nil {
			return 0, err
		}

		inputSum += vinTx.Vout[vin.Vout].Value
	}

	for _, vout := range rawTx.Vout {
		outputSum += vout.Value
	}

	fee := inputSum - outputSum

	return fee, nil
}
