package db

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"gorm.io/gorm"
)

// 创建交易表格模型
type Transaction struct {
	gorm.Model
	Hash     string `gorm:"unique"`
	Encoded  string `gorm:"not null"`
	BlockNum int64  `gorm:"not null"`
}

func AddTransaction(tx *gorm.DB, trans Transaction) error {
	res := tx.Create(&trans)
	if res.Error != nil {
		tx.Rollback()
		return res.Error
	}
	return nil
}

func AddBatchTransactions(tx *gorm.DB, txs []*types.Transaction, num int64) error {
	// 遍历每个区块，依次插入数据库
	for _, txIn := range txs {
		data, _ := txIn.MarshalBinary()
		wt := Transaction{
			Hash:     txIn.Hash().String(),
			Encoded:  common.Bytes2Hex(data),
			BlockNum: num,
		}
		result := tx.Create(&wt)
		if result.Error != nil {
			// 插入失败，回滚事务并返回错误
			tx.Rollback()
			return result.Error
		}
	}
	// 提交事务
	return nil
}

func GetTransactionByHash(db *gorm.DB, txHash common.Hash) *Transaction {
	var trans Transaction
	db.First(&trans, "hash = ?", txHash)
	return nil
}

func DeleteTransactionByHash(db *gorm.DB, txHash common.Hash) error {
	var tx Transaction
	err := db.Where("hash", txHash).Delete(&tx).Error
	if err != nil {
		db.Rollback()
		return err
	}
	return nil
}

func DeleteTransactionByNum(db *gorm.DB, num uint64) error {
	var tx Transaction
	err := db.Where("block_num", num).Delete(&tx).Error
	if err != nil {
		db.Rollback()
		return err
	}
	return nil
}
