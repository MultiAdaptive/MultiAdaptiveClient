package db

import (
	"github.com/ethereum/go-ethereum/log"
	"gorm.io/gorm"
)

type SyncInfo struct {
	LastBlockNum uint64 `gorm:"primaryKey"`
}

func UpDataLastBlocNum(tx *gorm.DB, orgNum, blockNum uint64) error {
	// 更新SyncInfo表格的值
	result := tx.Model(&SyncInfo{}).Where("last_block_num = ?", orgNum).Updates(SyncInfo{LastBlockNum: blockNum})
	if result.Error != nil {
		// 更新失败，回滚事务并返回错误
		tx.Rollback()
		return result.Error
	}
	return nil
}

func AddLastBlockNum(tx *gorm.DB, num uint64) error {
	sy := SyncInfo{
		LastBlockNum: num,
	}
	result := tx.Create(&sy)
	if result.Error != nil {
		// 插入失败，回滚事务并返回错误
		tx.Rollback()
		return result.Error
	}
	return nil
}

func GetLastBlockNum(db *gorm.DB) (uint64, error) {
	var gormdb *gorm.DB

	var count int64
	gormdb = db.Model(&SyncInfo{}).Count(&count)
	if gormdb.Error != nil {
		log.Error("Error count SyncInfo", "err", gormdb.Error)
		return 0, gormdb.Error
	}
	if count == 0 {
		log.Info("SyncInfo is empty")
		return 0, nil
	}

	var syncInfo SyncInfo
	gormdb = db.Last(&syncInfo)
	if gormdb.Error != nil {
		log.Error("Error Last SyncInfo", "err", gormdb.Error)
		return 0, gormdb.Error
	}
	return syncInfo.LastBlockNum, nil
}
