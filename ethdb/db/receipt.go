package db

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"gorm.io/gorm"
)

// 创建交易表格收据表格模型
type Receipt struct {
	gorm.Model
	TxHash            string `gorm:"unique"`
	TxType            int
	PostState         []byte
	Status            int64
	CumulativeGasUsed int64
	GasUsed           int64
	BlockNum          int64 `gorm:"not null"`
	TxIndex           int
	ContractAddress   string
}

func AddReceipt(tx *gorm.DB, receipt Receipt) error {
	res := tx.Create(&receipt)
	if res.Error != nil {
		tx.Rollback()
		return res.Error
	}
	return nil
}

func AddBatchReceipts(tx *gorm.DB, receipts []*types.Receipt) error {
	// 遍历每个区块，依次插入数据库
	for _, rec := range receipts {
		wr := Receipt{
			TxHash:            rec.TxHash.String(),
			TxType:            int(rec.Type),
			Status:            int64(rec.Status),
			CumulativeGasUsed: int64(rec.CumulativeGasUsed),
			GasUsed:           int64(rec.GasUsed),
			BlockNum:          rec.BlockNumber.Int64(),
			ContractAddress:   rec.ContractAddress.String(),
		}
		result := tx.Create(&wr)
		if result.Error != nil {
			// 插入失败，回滚事务并返回错误
			tx.Rollback()
			return result.Error
		}
	}
	return nil
}

func DeleteReceiptByHash(db *gorm.DB, txHash common.Hash) error {
	var receipt Receipt
	err := db.Where("tx_hash = ?", txHash.Hex()).Delete(&receipt).Error
	if err != nil {
		db.Rollback()
		return err
	}
	return nil
}

func DeleteReceiptByNum(db *gorm.DB, num uint64) error {
	var receipt Receipt
	err := db.Where("block_num = ?", num).Delete(&receipt).Error
	if err != nil {
		db.Rollback()
		return err
	}
	return nil
}
