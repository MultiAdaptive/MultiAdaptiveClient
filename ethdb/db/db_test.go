package db

import (
	"github.com/ethereum/go-ethereum/common"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"testing"
)

func TestNewSqlDB(t *testing.T) {

	sql, err := gorm.Open(sqlite.Open("/Users/wuxinyang/Desktop/domictest/state1.db"), &gorm.Config{})
	if err != nil {
		println("err",err.Error())
	}

	sql.AutoMigrate(&DA{})

	txHash := common.HexToHash("0x09f747f43ad5ad9ce2036e68fa1b82c786d43e57183c1757c6052ce32b571ab9")

	dat,err := GetCommitmentByTxHash(sql,txHash)
	if err != nil {
		println("err")
	}

	println("da----",dat.TxHash.Hex())
	//GetTransactionByHash()

}