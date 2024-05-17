package db

import (
	"github.com/ethereum/go-ethereum/log"
	//"github.com/go-sql-driver/mysql"
	//"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func NewSqlDB(path string) (*gorm.DB,error) {
	db, err := gorm.Open(sqlite.Open(path+"/state1.db"), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	return db,nil
}

func MigrateUp(db *gorm.DB) error {
	return db.AutoMigrate(&Transaction{},&Block{}, &Receipt{}, &Log{}, &SyncInfo{}, &DA{})
}

var Tx *gorm.DB

func Begin(db *gorm.DB)  *gorm.DB {
	Tx = db.Begin()
	return Tx
}

func Commit(db *gorm.DB) error {
	return db.Commit().Error
}

func CloseDB(db *gorm.DB) error {
	dbSQL, err := db.DB()
	if err != nil {
		log.Error("CloseDB --err;failed to get DB connection","err",err.Error())
		return err
	}
	dbSQL.Close()
	return nil
}

func CleanUpDB(db *gorm.DB,num uint64) error {
	var block Block
	db.Where("block_num >",num).Delete(&block)
	var tx Transaction
	db.Where("block_num >",num).Delete(&tx)
	var receipt Receipt
	db.Where("block_num >",num).Delete(&receipt)
	var da DA
	db.Where("block_num >",num).Delete(&da)
	return nil
}
