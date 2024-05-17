package db

import (
	"fmt"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"gorm.io/gorm"
)

// 创建commitment表格模型
type DA struct {
	gorm.Model
	Sender     string
	Index      int64
	Length     int64
	TxHash     string `gorm:"primaryKey;column:tx_hash"`
	Commitment string
	Data       string
	DAsKey     string
	SignData   string
	ParentStateHash string  //parent Commit Data Hash
	StateHash  string       //latest commit Data hash
	BlockNum    int64
}


func AddCommitment(tx *gorm.DB,da *types.DA,parentHash common.Hash) error {
	currentParentHash := parentHash
	dataCollect := make([]byte,0)
	dataCollect = append(dataCollect,da.Commitment...)
	dataCollect = append(dataCollect,da.Sender.Bytes()...)
	dataCollect = append(dataCollect,currentParentHash.Bytes()...)
	stateHash := common.BytesToHash(dataCollect)
	wd := DA{
		Sender: da.Sender.Hex(),
		Index: int64(da.Index),
		Length: int64(da.Length),
		TxHash: da.TxHash.Hex(),
		Commitment: common.Bytes2Hex(da.Commitment),
		Data: common.Bytes2Hex(da.Data),
		SignData: common.Bytes2Hex(da.SignData),
		ParentStateHash: currentParentHash.Hex(),
		StateHash: stateHash.Hex(),
	}
	res := tx.Create(&wd)
	return res.Error
}

func AddBatchCommitment(tx *gorm.DB,das []*types.DA,parentHash common.Hash) error {
	currentParentHash := parentHash
	dataCollect := make([]byte,0)
	// 遍历每个区块，依次插入数据库
	for _, da := range das {
		dataCollect = append(dataCollect,da.Commitment...)
		dataCollect = append(dataCollect,da.Sender.Bytes()...)
		dataCollect = append(dataCollect,currentParentHash.Bytes()...)
		stateHash := common.BytesToHash(dataCollect)
		wda := DA{
			Sender: da.Sender.Hex(),
			TxHash: da.TxHash.String(),
			Index: int64(da.Index),
			Length: int64(da.Length),
			Data: common.Bytes2Hex(da.Data),
			Commitment: common.Bytes2Hex(da.Commitment),
			SignData: common.Bytes2Hex(da.SignData),
			ParentStateHash: currentParentHash.String(),
			StateHash: stateHash.Hex(),
		}
		result := tx.Create(&wda)
		if result.Error != nil {
			// 插入失败，回滚事务并返回错误
			tx.Rollback()
			return result.Error
		}
		currentParentHash = stateHash
	}
	// 提交事务
	return nil
}

func GetCommitmentByHash(db *gorm.DB,txHash common.Hash) (*types.DA,error){
	var da DA
	tx := db.First(&da,"tx_hash = ?",txHash)
	if tx.Error == nil {
		return &types.DA{
			Sender: common.HexToAddress(da.Sender),
			Index: uint64(da.Index),
			Length: uint64(da.Length),
			Commitment: common.Hex2Bytes(da.Commitment),
			Data: common.Hex2Bytes(da.Data),
			SignData: common.Hex2Bytes(da.SignData),
			TxHash: common.HexToHash(da.TxHash),
		},tx.Error
	}
	errstr := fmt.Sprintf("can not find DA with given txHash :%d",txHash.Hex())
	return nil,errors.New(errstr)
}


