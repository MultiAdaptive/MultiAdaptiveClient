package db

import (
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"gorm.io/gorm"
	"strconv"
)

// 创建区块表格模型
type Block struct {
	gorm.Model
	BlockNum   int64  `gorm:"unique"`
	BlockHash  string `gorm:"not null"`
	ParentHash string
	EncodeData string
	ReceivedAt string `gorm:"type:timestamp with time zone; not null"`
}

func AddBlock(tx *gorm.DB, block *types.Block) error {
	data, err := rlp.EncodeToBytes(block)
	if err != nil {
		log.Info("AddBlock----encode", "err", err.Error())
	}
	wb := Block{
		BlockNum:   block.Number().Int64(),
		BlockHash:  block.Hash().Hex(),
		ParentHash: block.ParentHash().Hex(),
		ReceivedAt: block.ReceivedAt.String(),
		EncodeData: common.Bytes2Hex(data),
	}
	result := tx.Create(&wb)
	if result.Error != nil {
		// 插入失败，回滚事务并返回错误
		tx.Rollback()
		return result.Error
	}
	return nil
}

func AddBatchBlocks(tx *gorm.DB, blocks []*types.Block) error {
	// 遍历每个区块，依次插入数据库
	for _, block := range blocks {
		if block != nil {
			data, err := rlp.EncodeToBytes(block)
			if err != nil {
				log.Info("AddBlock----encode", "err", err.Error())
			}
			wb := Block{
				BlockNum:   block.Number().Int64(),
				BlockHash:  block.Hash().String(),
				ParentHash: block.ParentHash().String(),
				ReceivedAt: strconv.FormatUint(block.Time(), 10),
				EncodeData: common.Bytes2Hex(data),
			}
			result := tx.Create(&wb)
			if result.Error != nil {
				// 插入失败，回滚事务并返回错误
				tx.Rollback()
				return result.Error
			}
		}
	}
	return nil
}

func GetBlockByHash(db *gorm.DB, blockHash common.Hash) (*types.Block, error) {
	var block Block
	tx := db.First(&block, "block_hash = ?", blockHash)
	if tx.Error == nil {
		var roiBlock types.Block
		err := rlp.DecodeBytes(common.Hex2Bytes(block.EncodeData), roiBlock)
		return &roiBlock, err
	}
	errstr := fmt.Sprintf("can not find block with given blockHash :%s", blockHash.Hex())
	return nil, errors.New(errstr)
}

func GetBlockByNum(db *gorm.DB, blockNum uint64) (*types.Block, error) {
	var gormdb *gorm.DB

	var count int64
	gormdb = db.Model(&Block{}).Count(&count)
	if gormdb.Error != nil {
		log.Error("Error count Block", "err", gormdb.Error)
		return nil, gormdb.Error
	}
	if count == 0 {
		msg := fmt.Sprintf("Block table is empty")
		log.Info(msg)
		return nil, errors.New(msg)
	}

	var block Block
	gormdb = db.First(&block, "block_num = ?", blockNum)
	if gormdb.Error != nil {
		log.Error("can not find block with given block number", "blockNum", blockNum, "err", gormdb.Error)
		return nil, gormdb.Error
	}

	var roiBlock types.Block
	err := rlp.DecodeBytes(common.Hex2Bytes(block.EncodeData), &roiBlock)
	if err != nil {
		log.Error("Decode block data fail", "err", err)
		return nil, err
	}
	return &roiBlock, nil
}

func DeleteBlockByHash(db *gorm.DB, blockHash common.Hash) error {
	var block Block
	err := db.Where("block_num = ?", blockHash).Delete(&block).Error
	if err != nil {
		db.Rollback()
		return err
	}
	return nil
}

func DeleteBlockByNum(db *gorm.DB, blockNum uint64) error {
	var block Block
	err := db.Where("block_num", blockNum).Delete(&block).Error
	if err != nil {
		db.Rollback()
		return err
	}
	return nil
}
