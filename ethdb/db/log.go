package db

import (
	"github.com/ethereum/go-ethereum/common"
	"gorm.io/gorm"
)

// 创建日志表格模型
type Log struct {
	gorm.Model
	TxHash   string `gorm:"unique"`
	LogIndex int
	Address  string `gorm:"not null"`
	Data     string
	Topic0   string `gorm:"not null"`
	Topic1   string
	Topic2   string
	Topic3   string
}

func AddLog(tx *gorm.DB, log Log) error {
	res := tx.Create(&log)
	if res.Error != nil {
		tx.Rollback()
		return res.Error
	}
	return nil
}

func AddBatchLogs(tx *gorm.DB, logs []Log) error {
	// 遍历每个区块，依次插入数据库
	for _, logIns := range logs {
		result := tx.Create(&logIns)
		if result.Error != nil {
			// 插入失败，回滚事务并返回错误
			tx.Rollback()
			return result.Error
		}
	}
	return nil
}

func DeleteLogWithTxHash(db *gorm.DB, txHash common.Hash) error {
	var log Log
	err := db.Where("tx_hash", txHash).Delete(&log).Error
	if err != nil {
		db.Rollback()
		return err
	}
	return nil
}
