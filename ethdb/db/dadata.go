package db

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"gorm.io/gorm"
	"math/big"
	"strings"
	"time"
)

const TableNameDA = "t_das"

const JoinString = ","

// 创建commitment表格模型
type DA struct {
	ID              int32  `gorm:"column:f_id;primaryKey;autoIncrement:true;comment:ID" json:"id"`                                      // ID
	Nonce           int64  `gorm:"column:f_nonce;not null;comment:发送号" json:"nonce"`                                                    // 发送号
	Sender          string `gorm:"column:f_sender;not null;comment:发送者;index:idx_das_sender" json:"sender"`                             // 发送者
	Index           int64  `gorm:"column:f_index;not null;comment:序号;index:idx_das_index" json:"index"`                                 // 序号
	Length          int64  `gorm:"column:f_length;not null;comment:长度" json:"length"`                                                   // 长度
	TxHash          string `gorm:"column:f_tx_hash;not null;comment:交易哈希;uniqueIndex:uniq_das_tx_hash" json:"tx_hash"`                  // 交易哈希
	Commitment      string `gorm:"column:f_commitment;not null;comment:承诺;index:idx_das_commitment" json:"commitment"`                  // 承诺
	CommitmentHash  string `gorm:"column:f_commitment_hash;not null;comment:承诺哈希;index:idx_das_commitment_hash" json:"commitment_hash"` // 承诺哈希
	Data            string `gorm:"column:f_data;not null;comment:数据;index:idx_das_data" json:"data"`                                    // 数据
	DAsKey          string `gorm:"column:f_d_as_key;not null;comment:钥" json:"d_as_key"`                                                // 钥
	SignData        string `gorm:"column:f_sign_data;not null;comment:签名数据" json:"sign_data"`                                           // 签名数据
	SignAddr        string `gorm:"column:f_sign_address;not null;comment:签名地址" json:"sign_addr"`
	ParentStateHash string `gorm:"column:f_parent_state_hash;not null;comment:父提交数据哈希;index:idx_das_parent_state_hash" json:"parent_state_hash"` // 父提交数据哈希
	StateHash       string `gorm:"column:f_state_hash;not null;comment:最新数据哈希;index:idx_das_state_hash" json:"state_hash"`                       // 最新数据哈希
	BlockNum        int64  `gorm:"column:f_block_num;not null;comment:区块号;index:idx_das_block_num" json:"block_num"`                             // 区块号
	ReceiveAt       string `gorm:"column:f_receive_at;not null;comment:接收时间" json:"receive_at"`                                                  // 接收时间
	CreateAt        int64  `gorm:"column:f_create_at;not null;comment:创建时间" json:"create_at"`                                                    // 创建时间
	NameSpaceID     int64  `gorm:"column:f_name_space_id;not null;comment:命名空间" json:"name_space_id"`
}

func (*DA) TableName() string {
	return TableNameDA
}

func SaveDACommit(db *gorm.DB, da *types.DA, shouldSave bool, parentHash common.Hash) (common.Hash, error) {
	if shouldSave {
		currentParentHash := parentHash
		dataCollect := make([]byte, 0)
		dataCollect = append(dataCollect, da.Commitment.X.Marshal()...)
		dataCollect = append(dataCollect, da.Commitment.Y.Marshal()...)
		dataCollect = append(dataCollect, da.Sender.Bytes()...)
		dataCollect = append(dataCollect, currentParentHash.Bytes()...)
		stateHash := common.BytesToHash(dataCollect)

		sigDatStr := make([]string, len(da.SignData))
		for i, data := range da.SignData {
			sigDatStr[i] = common.Bytes2Hex(data)
		}
		result := strings.Join(sigDatStr, JoinString)

		addrStr := make([]string, len(da.SignerAddr))
		for i, addr := range da.SignerAddr {
			addrStr[i] = addr.Hex()
		}
		addrRes := strings.Join(addrStr, JoinString)

		wd := DA{
			Sender:          da.Sender.Hex(),
			Nonce:           int64(da.Nonce),
			Index:           int64(da.Index),
			Length:          int64(da.Length),
			TxHash:          da.TxHash.Hex(),
			BlockNum:        int64(da.BlockNum),
			Commitment:      common.Bytes2Hex(da.Commitment.Marshal()),
			Data:            common.Bytes2Hex(da.Data),
			SignData:        result,
			SignAddr:        addrRes,
			ParentStateHash: currentParentHash.Hex(),
			StateHash:       stateHash.Hex(),
			ReceiveAt:       da.ReceiveAt.Format(time.RFC3339),
			NameSpaceID:     da.NameSpaceID.Int64(),
		}
		res := db.Create(&wd)
		return stateHash, res.Error
	}
	return common.Hash{}, nil
}

func SaveBatchCommitment(db *gorm.DB, das []*types.DA, parentHash common.Hash) error {
	currentParentHash := parentHash
	dataCollect := make([]byte, 0)
	wdas := make([]DA, 0)

	// 遍历每个区块，依次插入数据库
	for _, da := range das {
		dataCollect = append(dataCollect, da.Commitment.X.Marshal()...)
		dataCollect = append(dataCollect, da.Commitment.Y.Marshal()...)
		dataCollect = append(dataCollect, da.Sender.Bytes()...)
		dataCollect = append(dataCollect, currentParentHash.Bytes()...)
		stateHash := common.BytesToHash(dataCollect)
		commitData := da.Commitment.Marshal()
		sigDatStr := make([]string, len(da.SignData))
		for i, data := range da.SignData {
			sigDatStr[i] = common.Bytes2Hex(data)
		}
		result := strings.Join(sigDatStr, JoinString)
		addrStr := make([]string, len(da.SignerAddr))
		for i, addr := range da.SignerAddr {
			addrStr[i] = addr.Hex()
		}
		addrRes := strings.Join(addrStr, JoinString)
		wda := DA{
			Sender:          da.Sender.Hex(),
			Nonce:           int64(da.Nonce),
			TxHash:          da.TxHash.String(),
			Index:           int64(da.Index),
			Length:          int64(da.Length),
			BlockNum:        int64(da.BlockNum),
			Data:            common.Bytes2Hex(da.Data),
			Commitment:      common.Bytes2Hex(commitData),
			CommitmentHash:  common.BytesToHash(commitData).Hex(),
			SignData:        result,
			SignAddr:        addrRes,
			ParentStateHash: currentParentHash.String(),
			StateHash:       stateHash.Hex(),
			ReceiveAt:       da.ReceiveAt.Format(time.RFC3339),
			//NameSpaceID:     da.NameSpaceID.Int64(),
		}
		wdas = append(wdas, wda)
		currentParentHash = stateHash
	}

	result := db.Create(&wdas)
	if result.Error != nil {
		return result.Error
	}

	return nil
}

func AddBatchCommitment(db *gorm.DB, das []*types.DA, parentHash common.Hash) error {
	currentParentHash := parentHash
	dataCollect := make([]byte, 0)
	// 遍历每个区块，依次插入数据库
	for _, da := range das {
		dataCollect = append(dataCollect, da.Commitment.X.Marshal()...)
		dataCollect = append(dataCollect, da.Commitment.Y.Marshal()...)
		dataCollect = append(dataCollect, da.Sender.Bytes()...)
		dataCollect = append(dataCollect, currentParentHash.Bytes()...)
		stateHash := common.BytesToHash(dataCollect)

		commitData := da.Commitment.Marshal()
		sigDatStr := make([]string, len(da.SignData))
		for i, data := range da.SignData {
			sigDatStr[i] = common.Bytes2Hex(data)
		}
		result := strings.Join(sigDatStr, JoinString)
		addrStr := make([]string, len(da.SignerAddr))
		for i, addr := range da.SignerAddr {
			addrStr[i] = addr.Hex()
		}
		addrRes := strings.Join(addrStr, JoinString)
		wda := DA{
			Sender:          da.Sender.Hex(),
			Nonce:           int64(da.Nonce),
			TxHash:          da.TxHash.String(),
			Index:           int64(da.Index),
			Length:          int64(da.Length),
			Data:            common.Bytes2Hex(da.Data),
			Commitment:      common.Bytes2Hex(commitData),
			CommitmentHash:  common.BytesToHash(commitData).Hex(),
			SignData:        result,
			SignAddr:        addrRes,
			BlockNum:        int64(da.BlockNum),
			ParentStateHash: currentParentHash.String(),
			StateHash:       stateHash.Hex(),
			ReceiveAt:       da.ReceiveAt.Format(time.RFC3339),
			NameSpaceID:     da.NameSpaceID.Int64(),
		}
		resul := db.Create(&wda)
		if resul.Error != nil {
			// 插入失败，回滚事务并返回错误
			db.Rollback()
			return resul.Error
		}
		currentParentHash = stateHash
	}
	// 提交事务
	return nil
}

func GetDAByCommitment(db *gorm.DB, commitment []byte) (*types.DA, error) {
	var gormdb *gorm.DB
	var count int64
	gormdb = db.Model(&DA{}).Count(&count)
	if gormdb.Error != nil {
		log.Error("Error count DA", "err", gormdb.Error)
		return nil, gormdb.Error
	}
	if count == 0 {
		msg := fmt.Sprintf("DA table is empty")
		log.Info(msg)
		return nil, errors.New(msg)
	}

	var digest kzg.Digest
	digest.SetBytes(commitment)
	var da DA
	gormdb = db.First(&da, "commitment = ?", common.Bytes2Hex(digest.Marshal()))
	if gormdb.Error != nil {
		log.Error("can not find DA with given commitment", "commitment", common.Bytes2Hex(commitment), "err", gormdb.Error)
		return nil, gormdb.Error
	}

	str, err := hex.DecodeString(da.Commitment)
	if err != nil {
		return nil, err
	}
	_, err = digest.SetBytes(str)
	if err != nil {
		return nil, err
	}
	parsedTime, err := time.Parse(time.RFC3339, da.ReceiveAt)
	if err != nil {
		log.Debug("Error parsing time", "err", err)
		return nil, err
	}
	signData := make([][]byte, len(da.SignData))
	for i, sg := range strings.Split(da.SignData, JoinString) {
		signData[i] = common.Hex2Bytes(sg)
	}

	signAdd := make([]common.Address, len(da.SignAddr))
	for i, add := range strings.Split(da.SignAddr, JoinString) {
		signAdd[i] = common.HexToAddress(add)
	}

	return &types.DA{
		Sender:      common.HexToAddress(da.Sender),
		Nonce:       uint64(da.Nonce),
		Index:       uint64(da.Index),
		Length:      uint64(da.Length),
		Commitment:  digest,
		Data:        common.Hex2Bytes(da.Data),
		SignData:    signData,
		SignerAddr:  signAdd,
		TxHash:      common.HexToHash(da.TxHash),
		BlockNum:    uint64(da.BlockNum),
		ReceiveAt:   parsedTime,
		NameSpaceID: new(big.Int).SetInt64(da.NameSpaceID),
	}, nil
}

func GetDAByCommitmentHash(db *gorm.DB, cmHash common.Hash) (*types.DA, error) {
	var gormdb *gorm.DB
	var count int64
	gormdb = db.Model(&DA{}).Count(&count)
	if gormdb.Error != nil {
		log.Error("Error count DA", "err", gormdb.Error)
		return nil, gormdb.Error
	}
	if count == 0 {
		msg := fmt.Sprintf("DA table is empty")
		log.Info(msg)
		return nil, errors.New(msg)
	}
	var da DA
	gormdb = db.First(&da, "commitment_hash = ?", cmHash.Hex())
	if gormdb.Error != nil {
		log.Error("can not find DA with given commitment_hash", "commitment_hash", cmHash.Hex(), "err", gormdb.Error)
		return nil, gormdb.Error
	}

	var digest kzg.Digest
	str, err := hex.DecodeString(da.Commitment)
	if err != nil {
		return nil, err
	}
	_, err = digest.SetBytes(str)
	if err != nil {
		return nil, err
	}
	parsedTime, err := time.Parse(time.RFC3339, da.ReceiveAt)
	if err != nil {
		log.Debug("Error parsing time", "err", err)
		return nil, err
	}
	signData := make([][]byte, len(da.SignData))
	for i, sg := range strings.Split(da.SignData, JoinString) {
		signData[i] = common.Hex2Bytes(sg)
	}

	signAdd := make([]common.Address, len(da.SignAddr))
	for i, add := range strings.Split(da.SignAddr, JoinString) {
		signAdd[i] = common.HexToAddress(add)
	}
	return &types.DA{
		Sender:      common.HexToAddress(da.Sender),
		Nonce:       uint64(da.Nonce),
		Index:       uint64(da.Index),
		Length:      uint64(da.Length),
		Commitment:  digest,
		Data:        common.Hex2Bytes(da.Data),
		SignData:    signData,
		SignerAddr:  signAdd,
		BlockNum:    uint64(da.BlockNum),
		TxHash:      common.HexToHash(da.TxHash),
		ReceiveAt:   parsedTime,
		NameSpaceID: new(big.Int).SetInt64(da.NameSpaceID),
	}, nil
}

func GetCommitmentByTxHash(db *gorm.DB, txHash common.Hash) (*types.DA, error) {
	var gormdb *gorm.DB

	var count int64
	gormdb = db.Model(&DA{}).Count(&count)
	if gormdb.Error != nil {
		log.Error("Error count DA", "err", gormdb.Error)
		return nil, gormdb.Error
	}
	if count == 0 {
		msg := fmt.Sprintf("DA table is empty")
		log.Info(msg)
		return nil, errors.New(msg)
	}
	var da DA
	gormdb = db.First(&da, "f_tx_hash = ?", txHash.Hex())
	if gormdb.Error != nil {
		log.Error("can not find DA with given txHash", "txHash", txHash.Hex(), "err", gormdb.Error)
		return nil, gormdb.Error
	}

	var digest kzg.Digest
	str, err := hex.DecodeString(da.Commitment)
	if err != nil {
		return nil, err
	}
	_, err = digest.SetBytes(str)
	if err != nil {
		return nil, err
	}
	parsedTime, err := time.Parse(time.RFC3339, da.ReceiveAt)
	if err != nil {
		log.Debug("Error parsing time", "err", err)
		return nil, err
	}
	signData := make([][]byte, len(da.SignData))
	for i, sg := range strings.Split(da.SignData, JoinString) {
		signData[i] = common.Hex2Bytes(sg)
	}

	signAdd := make([]common.Address, len(da.SignAddr))
	for i, add := range strings.Split(da.SignAddr, JoinString) {
		signAdd[i] = common.HexToAddress(add)
	}
	return &types.DA{
		Sender:      common.HexToAddress(da.Sender),
		Nonce:       uint64(da.Nonce),
		Index:       uint64(da.Index),
		Length:      uint64(da.Length),
		Commitment:  digest,
		Data:        common.Hex2Bytes(da.Data),
		BlockNum:    uint64(da.BlockNum),
		SignData:    signData,
		SignerAddr:  signAdd,
		TxHash:      common.HexToHash(da.TxHash),
		ReceiveAt:   parsedTime,
		NameSpaceID: new(big.Int).SetInt64(da.NameSpaceID),
	}, nil
}

// 获取ID最大的DA记录
func GetMaxIDDAStateHash(db *gorm.DB) (string, error) {
	var da DA
	if err := db.Order("f_id DESC").First(&da).Error; err != nil {
		return "", err
	}
	return da.StateHash, nil
}

func DeleteDAByHash(db *gorm.DB, hash common.Hash) error {
	var da DA
	tx := db.Where("f_tx_hash = ?", hash)
	if tx.Error != nil {
		tx = db.Where("f_commitment = ?", hash)
	}
	err := tx.Delete(&da).Error
	if err != nil {
		db.Rollback()
		return err
	}
	return nil
}

func GetAllDARecords(db *gorm.DB) ([]*types.DA, error) {
	var daRecords []DA
	tx := db.Select("f_tx_hash", "f_commitment").Find(&daRecords)
	if tx.Error != nil {
		return nil, tx.Error
	}

	var das []*types.DA
	for _, da := range daRecords {
		var digest kzg.Digest
		str, _ := hex.DecodeString(da.Commitment)
		digest.SetBytes(str)
		parsedTime, err := time.Parse(time.RFC3339, da.ReceiveAt)
		if err != nil {
			fmt.Println("Error parsing time:", err)
		}
		das = append(das, &types.DA{
			TxHash:     common.HexToHash(da.TxHash),
			Commitment: digest,
			ReceiveAt:  parsedTime,
		})
	}
	return das, nil
}
