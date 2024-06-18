package db

import (
	"fmt"
	baseModel "github.com/ethereum/go-ethereum/eth/basemodel"
	"github.com/ethereum/go-ethereum/log"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func NewSqlDB(path string) (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(path+"/state1.db"), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	return db, nil
}

func MigrateUp(db *gorm.DB) error {
	return db.AutoMigrate(
		&Transaction{},
		&Block{},
		&Receipt{},
		&Log{},
		&SyncInfo{},
		&DA{},
		&baseModel.BaseChain{},
		&baseModel.BaseBlock{},
		&baseModel.BaseTransaction{},
		&baseModel.BaseFile{},
	)
}

var Tx *gorm.DB

func Begin(db *gorm.DB) *gorm.DB {
	Tx = db.Begin()
	return Tx
}

func Commit(db *gorm.DB) error {
	return db.Commit().Error
}

func CloseDB(db *gorm.DB) error {
	dbSQL, err := db.DB()
	if err != nil {
		log.Error("CloseDB --err;failed to get DB connection", "err", err.Error())
		return err
	}
	_ = dbSQL.Close()
	return nil
}

func CleanUpDB(db *gorm.DB, num uint64) error {
	log.Info(fmt.Sprintf("clean db where block_num > %v", num))

	var block Block
	db.Where("block_num > ?", num).Delete(&block)

	var tx Transaction
	db.Where("block_num > ?", num).Delete(&tx)

	var receipt Receipt
	db.Where("block_num > ?", num).Delete(&receipt)

	var da DA
	db.Where("f_block_num > ?", num).Delete(&da)

	return nil
}
