package db

import "gorm.io/gorm"

type SyncInfo struct {
	LastBlockNum uint64 `gorm:"primaryKey"`
}

func UpDataLastBlocNum(tx *gorm.DB,orgNum,blockNum uint64) error {
	// 更新SyncInfo表格的值
	result := tx.Model(&SyncInfo{}).Where("last_block_num = ?", orgNum).Updates(SyncInfo{LastBlockNum: blockNum})
	if result.Error != nil {
		// 更新失败，回滚事务并返回错误
		tx.Rollback()
		return result.Error
	}
	return nil
}

func AddLastBlockNum(tx *gorm.DB,num uint64) error {
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

func GetLastBlockNum(db *gorm.DB) (uint64,error) {
	var syncInfo SyncInfo
	result := db.Last(&syncInfo)
	if result.Error != nil {
		return 0, result.Error
	}
	return syncInfo.LastBlockNum, nil
}


