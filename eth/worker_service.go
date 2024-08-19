package eth

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/ethereum/go-ethereum/common"
	baseModel "github.com/ethereum/go-ethereum/eth/basemodel"
	"github.com/ethereum/go-ethereum/eth/scriptparser"
	"github.com/ethereum/go-ethereum/eth/tool"
	"github.com/ethereum/go-ethereum/ethdb/db"
	"github.com/ethereum/go-ethereum/log"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	confirmationBlockNum = 6 //6区块确认
	CUSTOM_CONTENT_TYPE  = "MultiAdaptiveCM;charset=utf-8"
)

var SatoshiToBitcoin = float64(100000000)

type TransactionBrief struct {
	Commitment []byte
	BlockNum   int64
	Addresses  []string
	Signatures []string
}

type WorkerService struct {
	gdb         *gorm.DB
	btcCli      *rpcclient.Client
	magicNumber string
	netParams   *chaincfg.Params
	startNum    uint64
	stateNonce  uint64 //状态nonce
}

func NewWorkerService(
	gdb *gorm.DB,
	btcCli *rpcclient.Client,
	magicNumber string,
	netParams *chaincfg.Params,
	startNum uint64,
) *WorkerService {
	var stateNonce uint64
	if stateNonce == 0 {
		num, err := db.GetMaxIDDANonce(gdb)
		if err != nil {
			stateNonce = 0
		} else {
			stateNonce = num
		}
	}

	return &WorkerService{
		gdb:         gdb,
		btcCli:      btcCli,
		magicNumber: magicNumber,
		netParams:   netParams,
		startNum:    startNum,
		stateNonce:  stateNonce,
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
	err = ws.SaveFiles(ctx, blockHeightAndBlockMap)
	if err != nil {
		return err
	}

	return nil
}

func (ws *WorkerService) RunSync(ctx context.Context) (*btcTxSortCache, error) {
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
		log.Error("get present block number fail", "err", err)
		return nil, err
	}
	log.Info("present block number", "presentBlockHeight", presentBlockHeight)

	// 如果当前区块高度等于数据库中的区块高度，则不处理
	if presentBlockHeight >= currentBlockHeight {
		log.Info("The current blockchain height is not greater than the height of synchronized blocks in the database",
			"presentBlockHeight", presentBlockHeight,
			"currentBlockHeight", currentBlockHeight)
		return nil, nil
	}
	log.Info("The current blockchain height is greater than the height of synchronized blocks in the database",
		"presentBlockHeight", presentBlockHeight,
		"currentBlockHeight", currentBlockHeight)

	beginBlockHeight := presentBlockHeight + 1
	endBlockHeight := currentBlockHeight

	// 遍历获取block
	blockHeightAndBlockMap, blockHeightAndBlockHeaderMap, err := ws.GetBlocks(ctx, beginBlockHeight, endBlockHeight)
	if err != nil {
		log.Error("get blocks fail", "err", err)
		return nil, err
	}
	log.Info("get blocks complete",
		"beginBlockHeight", beginBlockHeight,
		"endBlockHeight", endBlockHeight)

	//保存区块
	err = ws.SaveBlocks(ctx, blockHeightAndBlockHeaderMap, blockHeightAndBlockMap)
	if err != nil {
		log.Error("save blocks fail", "err", err)
		return nil, err
	}
	log.Info("save blocks complete",
		"beginBlockHeight", beginBlockHeight,
		"endBlockHeight", endBlockHeight)

	// 保存交易
	err = ws.SaveTransactions(ctx, blockHeightAndBlockMap)
	if err != nil {
		log.Error("save transactions fail", "err", err)
		return nil, err
	}
	log.Info("save transactions complete",
		"beginBlockHeight", beginBlockHeight,
		"endBlockHeight", endBlockHeight)

	// 保存文件
	err = ws.SaveFiles(ctx, blockHeightAndBlockMap)
	if err != nil {
		log.Error("save files fail", "err", err)
		return nil, err
	}
	log.Info("save files complete",
		"beginBlockHeight", beginBlockHeight,
		"endBlockHeight", endBlockHeight)

	transaction2TransactionBriefs, err := ws.GenerateBrief(ctx, blockHeightAndBlockMap)
	if err != nil {
		log.Error("generate brief fail", "err", err)
		return nil, err
	}
	log.Info("generate brief complete",
		"beginBlockHeight", beginBlockHeight,
		"endBlockHeight", endBlockHeight)

	// 更新当前区块高度
	err = ws.UpdateChain(ctx, endBlockHeight)
	if err != nil {
		log.Error("update chain fail", "err", err)
		return nil, err
	}
	log.Info("update chain complete",
		"beginBlockHeight", beginBlockHeight,
		"endBlockHeight", endBlockHeight)

	return transaction2TransactionBriefs, nil
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
		Where(baseModel.BaseChain{MagicNumber: ws.magicNumber, Net: ws.netParams.Name}).
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
		Where(baseModel.BaseChain{MagicNumber: ws.magicNumber, Net: ws.netParams.Name}).
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

func (ws *WorkerService) GetBlocks(ctx context.Context, from int64, to int64) (*btcSortCache, *btcSortCache, error) {
	//blockHeightAndBlockVerboseMap := make(map[int64]*btcjson.GetBlockVerboseResult)
	//blockHeightAndBlockHeaderMap := make(map[int64]*wire.BlockHeader)
	blockHeightAndBlockVerboseMap := NewBtcSortCache()
	blockHeightAndBlockHeaderMap := NewBtcSortCache()
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
		blockHeightAndBlockVerboseMap.Set(i, blockVerbose)
		//blockHeightAndBlockVerboseMap[i] = blockVerbose

		// 使用最新区块哈希获取区块详细信息
		blockHeader, err := ws.btcCli.GetBlockHeader(blockHash)
		if err != nil {
			log.Error("Error getting block header by hash", "blockHash", blockHash, "err", err)
			return nil, nil, errors.New("get block header by hash err:" + err.Error())
		}
		blockHeightAndBlockHeaderMap.Set(i, blockHeader)
		//blockHeightAndBlockHeaderMap[i] = blockHeader
	}

	return blockHeightAndBlockVerboseMap, blockHeightAndBlockHeaderMap, nil
}

// 保存区块
func (ws *WorkerService) SaveBlocks(ctx context.Context, blockHeightAndBlockHeaderMap *btcSortCache, blockHeightAndBlockVerboseMap *btcSortCache) error {
	// 遍历获取block
	blockModels := make([]baseModel.BaseBlock, 0)

	now := tool.TimeStampNowSecond()
	//blockHeightAndBlockHeaderMap map[int64]*wire.BlockHeader,
	//blockHeightAndBlockVerboseMap map[int64]*btcjson.GetBlockVerboseResult
	for _, blockHeight := range blockHeightAndBlockHeaderMap.Keys() {
		value := blockHeightAndBlockVerboseMap.Get(blockHeight)
		block, ok := value.(*btcjson.GetBlockVerboseResult)
		if ok {
			blockModels = append(blockModels, baseModel.BaseBlock{
				MagicNumber:    ws.magicNumber,
				Net:            ws.netParams.Name,
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
		//block := blockHeightAndBlockVerboseMap[blockHeight]
	}

	log.Info("number of blocks", "number", len(blockModels))

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
func (ws *WorkerService) SaveTransactions(ctx context.Context, blockHeightAndBlockVerboseMap *btcSortCache) error {
	//blockHeightAndBlockVerboseMap map[int64]*btcjson.GetBlockVerboseResult
	txHashes := make([]string, 0)

	//for _, blockVerbose := range blockHeightAndBlockVerboseMap {
	//	for _, tx := range blockVerbose.Tx {
	//		txHashes = append(txHashes, tx)
	//	}
	//}
	for _, height := range blockHeightAndBlockVerboseMap.keyList {
		value := blockHeightAndBlockVerboseMap.Get(height)
		blockVerbose, ok := value.(*btcjson.GetBlockVerboseResult)
		if ok {
			for _, tx := range blockVerbose.Tx {
				txHashes = append(txHashes, tx)
			}
		}
	}

	transactionModels := make([]baseModel.BaseTransaction, 0)

	now := tool.TimeStampNowSecond()

	//// 校验交易内容
	//for blockHeight, blockVerbose := range blockHeightAndBlockVerboseMap {
	//	for _, tx := range blockVerbose.Tx {
	//		txid, err := chainhash.NewHashFromStr(tx)
	//		if err != nil {
	//			log.Error("Error converting txid string to hash", "tx", tx, "err", err)
	//			continue
	//		}
	//
	//		transactionVerbose, err := ws.btcCli.GetRawTransactionVerbose(txid)
	//		if err != nil {
	//			log.Error("Error getting transaction by hash", "txid", txid, "err", err)
	//			continue
	//		}
	//
	//		vinDataBytes, err := json.Marshal(transactionVerbose.Vin)
	//		if err != nil {
	//			log.Error("Error marshaling vin data", "err", err)
	//			continue
	//		}
	//
	//		voutDataBytes, err := json.Marshal(transactionVerbose.Vout)
	//		if err != nil {
	//			log.Error("Error marshaling vout data", "err", err)
	//			continue
	//		}
	//
	//		fee, err := ws.GetTransactionFee(tx)
	//		if err != nil {
	//			log.Debug("Error get transaction fee", "tx", tx, "err", err)
	//		}
	//
	//		transactionModels = append(transactionModels, baseModel.BaseTransaction{
	//			MagicNumber:     ws.magicNumber,
	//			Net:             ws.netParams.Name,
	//			Hex:             transactionVerbose.Hex,
	//			Txid:            transactionVerbose.Txid,
	//			TransactionHash: transactionVerbose.Hash,
	//			Size:            transactionVerbose.Size,
	//			Vsize:           transactionVerbose.Vsize,
	//			Weight:          transactionVerbose.Weight,
	//			LockTime:        transactionVerbose.LockTime,
	//			Vin:             vinDataBytes,
	//			Vout:            voutDataBytes,
	//			BlockHeight:     blockHeight,
	//			BlockHash:       transactionVerbose.BlockHash,
	//			Confirmations:   transactionVerbose.Confirmations,
	//			TransactionTime: transactionVerbose.Time,
	//			BlockTime:       transactionVerbose.Blocktime,
	//			Fee:             fee,
	//			CreateAt:        now,
	//		})
	//	}
	//}

	// 校验交易内容
	for _, blockHeight := range blockHeightAndBlockVerboseMap.Keys() {
		value := blockHeightAndBlockVerboseMap.Get(blockHeight)
		blockVerbose, ok := value.(*btcjson.GetBlockVerboseResult)
		if ok {
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
					Net:             ws.netParams.Name,
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
func (ws *WorkerService) SaveFiles(ctx context.Context, blockHeightAndBlockVerboseMap *btcSortCache) error {
	//blockHeightAndBlockVerboseMap map[int64]*btcjson.GetBlockVerboseResult
	fileModels := make([]baseModel.BaseFile, 0)

	now := tool.TimeStampNowSecond()

	//for blockHeight, blockVerbose := range blockHeightAndBlockVerboseMap {
	//	for _, tx := range blockVerbose.Tx {
	//		transactionInscriptions, err := ws.ParseTransaction(tx)
	//		if err != nil {
	//			log.Error("Error parse transaction", "tx", tx, "err", err)
	//			continue
	//		}
	//		log.Info("parse transaction", "tx", tx, "transactionInscriptions", transactionInscriptions)
	//
	//		for _, ins := range transactionInscriptions {
	//			contentType := ins.Inscription.ContentType
	//			contentLength := ins.Inscription.ContentLength
	//			contentBody := ins.Inscription.ContentBody
	//			index := ins.TxInIndex
	//			offset := ins.TxInOffset
	//			log.Info("INSCRIPTION Verbose", "index", index, "offset", offset, "contentType", string(contentType), "contentLength", contentLength, "contentBody", common.Bytes2Hex(contentBody))
	//			if string(contentType) != CUSTOM_CONTENT_TYPE {
	//				log.Info("Not custom content", "contentType", string(contentType))
	//				continue
	//			}
	//
	//			fileModels = append(fileModels, baseModel.BaseFile{
	//				MagicNumber:     ws.magicNumber,
	//				Net:             ws.netParams.Name,
	//				BlockHeight:     blockHeight,
	//				BlockHash:       blockVerbose.Hash,
	//				TransactionHash: tx,
	//				ContentType:     contentType,
	//				ContentLength:   contentLength,
	//				ContentBody:     contentBody,
	//				Index:           index,
	//				Offset:          offset,
	//				CreateAt:        now,
	//			})
	//		}
	//	}
	//}

	for _, blockHeight := range blockHeightAndBlockVerboseMap.Keys() {
		value := blockHeightAndBlockVerboseMap.Get(blockHeight)
		blockVerbose, ok := value.(*btcjson.GetBlockVerboseResult)
		if ok {
			for _, tx := range blockVerbose.Tx {
				transactionInscriptions, err := ws.ParseTransaction(tx)
				if err != nil {
					log.Error("Error parse transaction", "tx", tx, "err", err)
					continue
				}
				log.Info("parse transaction", "tx", tx, "transactionInscriptions", transactionInscriptions)

				for _, ins := range transactionInscriptions {
					contentType := ins.Inscription.ContentType
					contentLength := ins.Inscription.ContentLength
					contentBody := ins.Inscription.ContentBody
					index := ins.TxInIndex
					offset := ins.TxInOffset
					log.Info("INSCRIPTION Verbose", "index", index, "offset", offset, "contentType", string(contentType), "contentLength", contentLength, "contentBody", common.Bytes2Hex(contentBody))
					if string(contentType) != CUSTOM_CONTENT_TYPE {
						log.Info("Not custom content", "contentType", string(contentType))
						continue
					}

					fileModels = append(fileModels, baseModel.BaseFile{
						MagicNumber:     ws.magicNumber,
						Net:             ws.netParams.Name,
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
				}
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

// 生成返回数据: 交易哈希、区块号、地址、签名
func (ws *WorkerService) GenerateBrief(ctx context.Context, blockHeightAndBlockVerboseMap *btcSortCache) (*btcTxSortCache, error) {
	//blockHeightAndBlockVerboseMap map[int64]*btcjson.GetBlockVerboseResult
	//transaction2TransactionBriefs := make(map[string][]TransactionBrief)
	transaction2TransactionBriefs := NewBtcTxSortCache()
	//for blockHeight, blockVerbose := range blockHeightAndBlockVerboseMap {
	//	for _, tx := range blockVerbose.Tx {
	//		transactionInscriptions, err := ws.ParseTransaction(tx)
	//		if err != nil {
	//			log.Error("Error parse transaction", "tx", tx, "err", err)
	//			continue
	//		}
	//		log.Info("parse transaction", "tx", tx, "transactionInscriptions", transactionInscriptions)
	//
	//		transactionSignature, err := ws.GetTransactionSignature(tx)
	//		if err != nil {
	//			log.Error("Error get transaction signature", "tx", tx, "err", err)
	//			continue
	//		}
	//		log.Info("get transaction signature", "tx", tx, "transactionSignature", transactionSignature)
	//
	//		transactionBriefs := make([]TransactionBrief, 0)
	//		for _, ins := range transactionInscriptions {
	//			contentType := ins.Inscription.ContentType
	//			contentLength := ins.Inscription.ContentLength
	//			contentBody := ins.Inscription.ContentBody
	//			validatorAddresses := ins.Validator.ValidatorAddresses
	//			commitment := contentBody
	//			index := ins.TxInIndex
	//			offset := ins.TxInOffset
	//			log.Info("INSCRIPTION Verbose", "index", index, "offset", offset, "contentType", string(contentType), "contentLength", contentLength, "contentBody", common.Bytes2Hex(contentBody))
	//			if string(contentType) != CUSTOM_CONTENT_TYPE {
	//				log.Info("Not custom content", "contentType", string(contentType))
	//				continue
	//			}
	//
	//			transactionBrief := TransactionBrief{
	//				Commitment: commitment,
	//				BlockNum:   blockHeight,
	//				Addresses:  validatorAddresses,
	//				Signatures: []string{transactionSignature},
	//			}
	//			transactionBriefs = append(transactionBriefs, transactionBrief)
	//		}
	//
	//		transaction2TransactionBriefs[tx] = transactionBriefs
	//	}
	//}
	for _, blockHeight := range blockHeightAndBlockVerboseMap.Keys() {
		value := blockHeightAndBlockVerboseMap.Get(blockHeight)
		blockVerbose, ok := value.(*btcjson.GetBlockVerboseResult)
		if ok {
			for _, tx := range blockVerbose.Tx {
				transactionInscriptions, err := ws.ParseTransaction(tx)
				if err != nil {
					log.Error("Error parse transaction", "tx", tx, "err", err)
					continue
				}
				log.Info("parse transaction", "tx", tx, "transactionInscriptions", transactionInscriptions)

				transactionSignature, err := ws.GetTransactionSignature(tx)
				if err != nil {
					log.Error("Error get transaction signature", "tx", tx, "err", err)
					continue
				}
				log.Info("get transaction signature", "tx", tx, "transactionSignature", transactionSignature)

				transactionBriefs := make([]TransactionBrief, 0)
				for _, ins := range transactionInscriptions {
					contentType := ins.Inscription.ContentType
					contentLength := ins.Inscription.ContentLength
					contentBody := ins.Inscription.ContentBody
					validatorAddresses := ins.Validator.ValidatorAddresses
					commitment := contentBody
					index := ins.TxInIndex
					offset := ins.TxInOffset
					log.Info("INSCRIPTION Verbose", "index", index, "offset", offset, "contentType", string(contentType), "contentLength", contentLength, "contentBody", common.Bytes2Hex(contentBody))
					if string(contentType) != CUSTOM_CONTENT_TYPE {
						log.Info("Not custom content", "contentType", string(contentType))
						continue
					}

					transactionBrief := TransactionBrief{
						Commitment: commitment,
						BlockNum:   blockHeight,
						Addresses:  validatorAddresses,
						Signatures: []string{transactionSignature},
					}
					transactionBriefs = append(transactionBriefs, transactionBrief)
				}

				//transaction2TransactionBriefs[tx] = transactionBriefs
				transaction2TransactionBriefs.Set(tx, transactionBriefs)
			}
		}
	}

	log.Info("number of commitments", "number", len(transaction2TransactionBriefs.Keys()))

	return transaction2TransactionBriefs, nil
}


func (ws *WorkerService) ParseTransaction(txID string) ([]*scriptparser.TransactionInscription, error) {
	txHash, err := chainhash.NewHashFromStr(txID)
	if err != nil {
		return nil, errors.New("invalid transaction ID:" + err.Error())
	}

	rawTx, err := ws.btcCli.GetRawTransaction(txHash)
	if err != nil {
		log.Error("Get raw tx failed", "txHash", txHash, "err", err)
		return nil, err
	}
	transactionInscriptions := scriptparser.ParseInscriptionsFromTransaction(rawTx.MsgTx(), ws.netParams)
	if len(transactionInscriptions) == 0 {
		log.Info("NO INSCRIPTIONS", "txHash", txHash)
	}
	log.Info("SOME INSCRIPTIONS", "txHash", txHash, "number", len(transactionInscriptions))

	return transactionInscriptions, nil
}

func (ws *WorkerService) GetTransactionFee(txID string) (float64, error) {
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

func (ws *WorkerService) GetTransactionSignature(txID string) (string, error) {
	txHash, err := chainhash.NewHashFromStr(txID)
	if err != nil {
		log.Error("Invalid transaction ID", "txID", txID, "err", err)
		return "", err
	}

	rawTx, err := ws.btcCli.GetRawTransactionVerbose(txHash)
	if err != nil {
		log.Error("Error getting raw transaction", "txHash", txHash, "err", err)
		return "", err
	}

	log.Info("Get Transaction Signatures", "TransactionID", txID, "Hex", rawTx.Hex)

	return rawTx.Hex, nil
}
