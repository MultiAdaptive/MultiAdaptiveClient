package db

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"testing"
)

func TestNewSqlDB(t *testing.T) {

	sql, err := gorm.Open(sqlite.Open("./state1.db"), &gorm.Config{})
	if err != nil {
		println("err",err.Error())
	}

	sql.AutoMigrate(&Transaction{},&Block{})
	txSql := sql.Begin()

	blocks := []Block{
		Block{BlockNum: 1,BlockHash: "0x000001",ParentHash: ""},
		Block{BlockNum: 2,BlockHash: "0x000002",ParentHash: "0x00001"},
		Block{BlockNum: 3,BlockHash: "0x000003",ParentHash: "0x00002"},
	}
	for _,block := range blocks{
		txSql.Create(&block)
	}
	//txSql.Commit()

	txs := []Transaction{
		Transaction{Hash: "0x000000011",BlockNum: 1},
		Transaction{Hash: "0x000000022",BlockNum: 2},
		Transaction{Hash: "0x000000033",BlockNum: 3},
	}

	for _,tx := range txs{
		res := txSql.Create(&tx)
		if res.Error != nil {
			txSql.Rollback()
			//continue
		}
	}
	//txSql.Commit()


	blocks = []Block{
		Block{BlockNum: 4,BlockHash: "0x000004",ParentHash: "0x00003"},
		Block{BlockNum: 5,BlockHash: "0x000005",ParentHash: "0x00004"},
		Block{BlockNum: 6,BlockHash: "0x000006",ParentHash: "0x00005"},
	}
	for _,block := range blocks{
		txSql.Create(&block)
	}
	//txSql.Commit()

	txs = []Transaction{
		Transaction{Hash: "0x000000044",BlockNum: 4},
		Transaction{Hash: "0x000000055",BlockNum: 5},
		Transaction{Hash: "0x000000066",BlockNum: 6},
	}

	for _,tx := range txs{
		res := txSql.Create(&tx)
		if res.Error != nil {
			txSql.Rollback()
			//continue
		}
	}
	txSql.Commit()
	//GetTransactionByHash()

}