package db

import (
	"domiconexec/common"
	"domiconexec/core/types"
	"domiconexec/log"
	"strconv"

	//"github.com/go-sql-driver/mysql"
	//"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"os"
)


// 创建交易表格模型
type Transaction struct {
	gorm.Model
	Hash     string `gorm:"primaryKey"`
	Encoded  string `gorm:"not null"`
	BlockNum int64    `gorm:"not null"`
}

// 创建区块表格模型
type Block struct {
	gorm.Model
	BlockNum    int64    `gorm:"primaryKey"`
	BlockHash   string   `gorm:"not null"`
	ParentHash  string
	ReceivedAt  string   `gorm:"type:timestamp with time zone; not null"`
}

// 创建交易表格收据表格模型
type Receipt struct {
	gorm.Model
	TxHash             string `gorm:"primaryKey"`
	TxType             int
	PostState          []byte
	Status             int64
	CumulativeGasUsed  int64
	GasUsed            int64
	BlockNum           int64 `gorm:"not null"`
	TxIndex            int
	ContractAddress    string
}

// 创建日志表格模型
type Log struct {
	gorm.Model
	TxHash   string `gorm:"primaryKey"`
	LogIndex int
	Address  string `gorm:"not null"`
	Data     string
	Topic0   string `gorm:"not null"`
	Topic1   string
	Topic2   string
	Topic3   string
}

// 创建commitment表格模型
type Commitment struct {
	gorm.Model
	TxHash     string `gorm:"primaryKey;column:tx_hash"`
	Commitment string
	Hash       string
	Data       string
}

type SyncInfo struct {
	LastBlockNum uint64 `gorm:"primaryKey"`
}

func NewSqlDB(path string) (*gorm.DB,error) {
	db, err := gorm.Open(sqlite.Open(path+"/state.db"), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	return db,nil
}

func MigrateUp(db *gorm.DB) error {
	return db.AutoMigrate(&Transaction{},&Block{}, &Receipt{}, &Log{}, &SyncInfo{})
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

func Begin(db *gorm.DB)  *gorm.DB {
	return db.Begin()
}

func SetLastBlocNum(db *gorm.DB,blockNum uint64) error {
	// 开启事务
	tx := db.Begin()
	defer func() {
		// 如果发生错误，回滚事务
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 更新SyncInfo表格的值
	result := tx.Model(&SyncInfo{}).Where("last_block_num = ?", blockNum).Updates(SyncInfo{LastBlockNum: blockNum})
	if result.Error != nil {
		// 更新失败，回滚事务并返回错误
		tx.Rollback()
		return result.Error
	}

	// 提交事务
	return tx.Commit().Error
}

func GetLastBlockNum(db *gorm.DB) (uint64,error) {
	var syncInfo SyncInfo
	result := db.Last(&syncInfo)
	if result.Error != nil {
		return 0, result.Error
	}
	return syncInfo.LastBlockNum, nil
}

func AddBlock(db *gorm.DB,block Block) error {
	tx := db.Create(&block)
	return tx.Commit().Error
}

func TransToSaveBlock(blocks []*types.Block) []Block {
	wbcs := make([]Block, len(blocks))
	for i, bc := range blocks  {
		wbc := Block{
			BlockNum: bc.Number().Int64(),
			BlockHash: bc.Hash().String(),
			ParentHash: bc.ParentHash().String(),
			ReceivedAt: strconv.FormatUint(bc.Time(),10),
		}
		wbcs[i] = wbc
	}
	return wbcs
}


func AddBatchBlocks(db *gorm.DB,blocks []*types.Block) error {
	// 开启事务
	tx := db.Begin()
	defer func() {
		// 如果发生错误，回滚事务
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 遍历每个区块，依次插入数据库
	for _, block := range blocks {
		wb := Block{
			BlockNum: block.Number().Int64(),
			BlockHash: block.Hash().String(),
			ParentHash: block.ParentHash().String(),
			ReceivedAt: strconv.FormatUint(block.Time(),10),
		}
		result := tx.Create(&wb)
		if result.Error != nil {
			// 插入失败，回滚事务并返回错误
			tx.Rollback()
			return result.Error
		}
	}

	// 提交事务
	return tx.Commit().Error
}

func GetBlockByHash(db *gorm.DB,blockHash common.Hash) *Block {
	var block Block
	db.First(&block, "block_hash = ?", blockHash)
	return &block
}

func GetBlockByNum(db *gorm.DB,blockNum uint64) *Block {
	var block Block
	db.First(&block,"block_num = ?",blockNum)
	return &block
}

func DeleteBlockByHash(db *gorm.DB,blockHash common.Hash) error {
	var block Block
	err := db.Where("block_num = ?",blockHash).Delete(&block).Error
	if err != nil {
		db.Rollback()
		return err
	}
	return nil
}

func DeleteBlockByNum(db *gorm.DB,blockNum uint64) error {
	var block Block
	err := db.Where("block_num",blockNum).Delete(&block).Error
	if err != nil {
		db.Rollback()
		return err
	}
	return nil
}

func AddTransaction(db *gorm.DB,trans Transaction) error {
	tx := db.Create(&trans)
	return tx.Commit().Error
}

func TransToSaveTransactions(txs []*types.Transaction,blockNum int64) []Transaction  {
	wtxs := make([]Transaction,len(txs))
	for i,tx := range txs{
		data,_ := tx.MarshalBinary()
		encodeData := common.Bytes2Hex(data)
		wtxs[i] = Transaction{
			Hash: tx.Hash().String(),
			Encoded: encodeData,
			BlockNum: blockNum,
		}
	}
	return wtxs
}

func AddBatchTransactions(db *gorm.DB,txs []*types.Transaction,num int64) error {
	// 开启事务
	tx := db.Begin()
	defer func() {
		// 如果发生错误，回滚事务
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 遍历每个区块，依次插入数据库
	for _, txIn := range txs {
		data,_ := txIn.MarshalBinary()
		wt := Transaction{
			Hash: txIn.Hash().String(),
			Encoded: common.Bytes2Hex(data),
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
	return tx.Commit().Error
}

func GetTransactionByHash(db *gorm.DB,txHash common.Hash) *Transaction {
	var trans Transaction
	db.First(&trans,"hash = ?",txHash)
	return nil
}

func DeleteTransactionByHash(db *gorm.DB,txHash common.Hash) error {
	var tx Transaction
	err := db.Where("hash",txHash).Delete(&tx).Error
	if err != nil {
		db.Rollback()
		return err
	}
	return nil
}

func AddLog(db *gorm.DB,log Log) error {
	db.Create(&log)
	return db.Commit().Error
}

func AddBatchLogs(db *gorm.DB,logs []Log) error {
	// 开启事务
	tx := db.Begin()
	defer func() {
		// 如果发生错误，回滚事务
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 遍历每个区块，依次插入数据库
	for _, logIns := range logs {
		result := tx.Create(&logIns)
		if result.Error != nil {
			// 插入失败，回滚事务并返回错误
			tx.Rollback()
			return result.Error
		}
	}

	// 提交事务
	return tx.Commit().Error
}

func DeleteLogWithTxHash(db *gorm.DB,txHash common.Hash) error {
	var log Log
	err := db.Where("tx_hash",txHash).Delete(&log).Error
	if err != nil {
		db.Rollback()
		return err
	}
	return nil
}

func AddReceipt(db *gorm.DB,receipt Receipt) error {
	tx := db.Create(&receipt)
	return tx.Commit().Error
}

func AddBatchReceipts(db *gorm.DB,receipts []*types.Receipt) error{
	// 开启事务
	tx := db.Begin()
	defer func() {
		// 如果发生错误，回滚事务
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// 遍历每个区块，依次插入数据库
	for _, rec := range receipts {
		wr := Receipt{
			TxHash: rec.TxHash.String(),
			TxType: int(rec.Type),
			Status: int64(rec.Status),
			CumulativeGasUsed: int64(rec.CumulativeGasUsed),
			GasUsed: int64(rec.GasUsed),
			BlockNum: rec.BlockNumber.Int64(),
			ContractAddress: rec.ContractAddress.String(),
		}
		result := tx.Create(&wr)
		if result.Error != nil {
			// 插入失败，回滚事务并返回错误
			tx.Rollback()
			return result.Error
		}
	}

	// 提交事务
	return tx.Commit().Error
}

func DeleteReceiptByHash(db *gorm.DB,txHash common.Hash) error {
	var receipt Receipt
	err := db.Where("tx_hash",txHash).Delete(&receipt).Error
	if err != nil {
		db.Rollback()
		return err
	}
	return nil
}

//func AddBatchCommitment(db *gorm.DB,)  {
//
//}

//
//func CreatOrOpenDB(path string) (*sql.DB, error) {
//	db, err := sql.Open("sqlite3", "file:"+path+"/state.db?_journal_mode=WAL&_cache_size=8"+
//		"&_synchronous=0&mode=rwc")
//	if err != nil {
//		log.Error("create sqlit db failed", "err", err.Error())
//	}
//	db.SetMaxOpenConns(2000)
//	db.SetMaxIdleConns(1000)
//	db.Ping()
//	return db, err
//}
//
////close data base
//func CloseDB(db *sql.DB) error {
//	return db.Close()
//}

////create table with given name
//func CreateTableWithTableName(db *sql.DB, tableName string) error {
//	var tableInfo string
//	//var indexInfo string
//	switch tableName {
//
//	case BLOCKTYPE:
//		tableInfo = tableName + ` (
//			block_num     INTEGER PRIMARY KEY,
//			block_hash    VARCHAR NOT NULL,
//			parent_hash   VARCHAR,
//                  received_at   TIMESTAMP WITH TIME ZONE NOT NULL
//		);`
//		//block 类型
//		//indexInfo = `CREATE INDEX index_b` + ` ON ` + tableName + `(block_num);`
//
//	case RECEIPTTYPE:
//		//receipt 类型
//		tableInfo = tableName + ` (
//			tx_hash             VARCHAR NOT NULL PRIMARY KEY REFERENCES transaction (hash) ON DELETE CASCADE,
//                  tx_type             integer,
//			post_state          BYTEA,
//                  status              BIGINT,
//                  cumulative_gas_used BIGINT,
//                  gas_used            BIGINT,
//                  block_num           BIGINT  NOT NULL REFERENCES block (block_num) ON DELETE CASCADE,
//                  tx_index            integer,
//                  contract_address    VARCHAR
//            );`
//		//indexInfo = `CREATE INDEX index_t` + ` ON ` + tableName + `(tx_hash,block_num);`
//
//	case LOGTYPE:
//		//transaction 类型
//		tableInfo = tableName + ` (
//			tx_hash   VARCHAR NOT NULL REFERENCES transaction (hash) ON DELETE CASCADE,
//			log_index integer,
//			address   VARCHAR NOT NULL,
//                  data      VARCHAR,
//                  topic0    VARCHAR NOT NULL,
//                  topic1    VARCHAR,
//                  topic2    VARCHAR,
//                  topic3    VARCHAR,
//                  PRIMARY KEY (tx_hash, log_index)
//            );`
//
//	case TRANSATIONTYPE:
//		//transaction 类型
//		tableInfo = tableName + ` (
//			hash         VARCHAR PRIMARY KEY,
//                  encoded      VARCHAR NOT NULL,
//			block_num    INTEGER  NOT NULL REFERENCES block (block_num) ON DELETE CASCADE
//            );`
//		//indexInfo = `CREATE INDEX index_r` +` ON ` + tableName + `(block_num,hash);`
//
//	case SYNCINFOTYPE:
//		//所有domain下key的记录
//		tableInfo = tableName + ` (
//			last_num_seen         INTEGER
//            );`
//		//indexInfo = `CREATE INDEX index_s` + ` ON ` + tableName + `(last_num_seen);`
//	}
//
//	sql_table := `CREATE TABLE IF NOT EXISTS ` + tableInfo
//	_, err := db.Exec(sql_table)
//	if err != nil {
//		log.Error("CreateTableWithTableName create table failed", "err", err.Error())
//		return err
//	}
//
//	return nil
//}

// create or open db with path
func LocalPathExist(path string) error {
	if flag, err := pathExists(path); !flag || err != nil {
		//log.Error("creat or open db file fail without path:", "path", path)
		return err
	}
	return nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

//func AddBlock(db *sql.DB,block *Block) error {
//	insertSql := "INSERT INTO block (block_num, block_hash, parent_hash, received_at) VALUES (?,?,?,?);"
//	stmt,err := db.Prepare(insertSql)
//	if err != nil {
//		return err
//	}
//	defer stmt.Close()
//	_,err = stmt.Exec(block.Block_num,block.Block_hash,block.Parent_hash,block.Receive_time)
//	if err != nil {
//		return err
//	}
//	return nil
//}
//
//func GetBlockByNum(db *sql.DB,num uint64) (block *Block,err error)  {
//	querySql := "SELECT * FROM block WHERE block_num = ? LIMIT 1;"
//	var blc *Block
//	err = db.QueryRow(querySql,num).Scan(&blc.Block_num,&blc.Block_hash,&blc.Parent_hash,&blc.Receive_time)
//	if err != nil {
//		return nil, err
//	}
//	return blc,nil
//}
//
//func GetBlockByHash(db *sql.DB,hash common.Hash) (block *Block,err error) {
//	querySql := "SELECT * FROM block WHERE block_hash = ? LIMIT 1;"
//	var blc *Block
//	err = db.QueryRow(querySql,hash).Scan(&blc.Block_num,&blc.Block_hash,&blc.Parent_hash,&blc.Receive_time)
//	if err != nil {
//		return nil, err
//	}
//	return blc,nil
//}
//
//func DeleteBlockByNum(db *sql.DB,num uint64) error {
//	delSql := "DELETE FROM block WHERE block_num = ?;"
//	stmt,err := db.Prepare(delSql)
//	if err != nil {
//		return err
//	}
//	defer stmt.Close()
//	_,err = stmt.Exec(num)
//	if err != nil {
//		return err
//	}
//	return nil
//}
//
//func AddBatchBlocks(db *sql.DB,bcs []*Block) error {
//	tx ,err := db.Begin()
//	if err != nil {
//		return err
//	}
//	insSql := "INSERT INTO block (block_num, block_hash, parent_hash, received_at) VALUES (?,?,?,?);"
//	stmt,err := tx.Prepare(insSql)
//	if err != nil {
//		return err
//	}
//	defer stmt.Close()
//
//	for _,blc := range bcs{
//		_,err	= stmt.Exec(blc.Block_num,blc.Block_hash,blc.Parent_hash,blc.Receive_time)
//		if err != nil {
//			tx.Rollback()
//		}
//	}
//
//	err = tx.Commit()
//	if err != nil {
//		errStr := fmt.Sprintf("AddBatchBlocks commit err:%v",err)
//		println(errStr)
//	}
//	return nil
//}
//
///*
//hash         VARCHAR PRIMARY KEY,
//encoded      VARCHAR NOT NULL,
//block_num    INTEGER  NO
//*/
//func AddBatchTransactions(db *sql.DB,trans []*Transaction) error {
//	tx ,err := db.Begin()
//	if err != nil {
//		return err
//	}
//	insSql := "INSERT INTO transaction (hash, encoded, block_num) VALUES (?,?,?);"
//	stmt,err := tx.Prepare(insSql)
//	if err != nil {
//		return err
//	}
//	defer stmt.Close()
//	for _,tran := range trans{
//		_,err	= stmt.Exec(tran.Hash,tran.Data,tran.BlockNum)
//		if err != nil {
//			tx.Rollback()
//		}
//	}
//
//	err = tx.Commit()
//	if err != nil {
//		errStr := fmt.Sprintf("AddBatchTransactions commit err:%v",err)
//		println(errStr)
//	}
//	return nil
//}
//
//
//func AddBatchReceipt(db *sql.DB,res []*Receipt) error {
//	tx ,err := db.Begin()
//	if err != nil {
//		return err
//	}
//	insSql := "INSERT INTO receipt (tx_hash, tx_type, post_state, status,cumulative_gas_used,block_num,tx_index,contract_address) VALUES (?,?,?,?,?,?,?,?);"
//	stmt,err := tx.Prepare(insSql)
//	if err != nil {
//		return err
//	}
//	defer stmt.Close()
//
//	for _,re := range res{
//		_,err	= stmt.Exec(re.TxHash,re.Type,re.PostState,re.Status,re.CumulativeGasUsed,re.BlockNumber,re.TransactionIndex,re.ContractAddress)
//		if err != nil {
//			tx.Rollback()
//		}
//	}
//
//	err = tx.Commit()
//	if err != nil {
//		errStr := fmt.Sprintf("AddBatchReceipt commit err:%v",err)
//		println(errStr)
//	}
//	return nil
//}
//
//
//func AddBatchLogs(db *sql.DB,logs []*Log) error {
//	tx ,err := db.Begin()
//	if err != nil {
//		return err
//	}
//	insSql := "INSERT INTO log (tx_hash, log_index, address, data,topic0,topic1,topic2,topic3) VALUES (?,?,?,?,?,?,?,?);"
//	stmt,err := tx.Prepare(insSql)
//	if err != nil {
//		return err
//	}
//	defer stmt.Close()
//	for _,log := range logs{
//		_,err	= stmt.Exec(log.TxHash,log.Index,log.Address,log.Data,log.Topics[0],log.Topics[1],log.Topics[2],log.Topics[3])
//		if err != nil {
//			tx.Rollback()
//		}
//	}
//	err = tx.Commit()
//	if err != nil {
//		errStr := fmt.Sprintf("AddBatchLogs commit err:%v",err)
//		println(errStr)
//	}
//	return nil
//}