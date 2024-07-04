package db

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"gorm.io/gorm"
	"math/big"
	"strings"
)

type NameSpace struct {
	gorm.Model
	NameSpaceKey  int64
	Creater      string
	StorageList  string
}

func AddNameSpace(db *gorm.DB, ns *types.NameSpace,nsId *big.Int) error {
	stlist := make([]string,len(ns.StorageList))
	for i, addr := range ns.StorageList{
		stlist[i] = addr.Hex()
	}
	strList := strings.Join(stlist,JoinString)
	nsW := NameSpace{
		NameSpaceKey: nsId.Int64(),
		Creater: ns.Creater.Hex(),
		StorageList: strList,
	}
	result := db.Create(&nsW)
	if result.Error != nil {
		// 插入失败，回滚事务并返回错误
		db.Rollback()
		return result.Error
	}
	return nil
}

func GetNameSpace(db *gorm.DB,nsId *big.Int) *types.NameSpace {
	var ns NameSpace
	tx := db.First(&ns,"name_space_id = ?",nsId.Int64())
	if tx.Error !=  nil {
		return nil
	}

	addrList := make([]common.Address,len(ns.StorageList))
	for i,addr := range strings.Split(ns.StorageList,JoinString) {
		addrList[i] = common.HexToAddress(addr)
	}

	rns := types.NameSpace{
		ID: uint64(ns.ID),
		Creater: common.HexToAddress(ns.Creater),
		StorageList: addrList,
	}
	return &rns
}

/**
func GetBlockByHash(db *gorm.DB, blockHash common.Hash) (*types.Block, error) {
	var block Block
	tx := db.First(&block, "block_hash = ?", blockHash.Hex())
	if tx.Error == nil {
		var roiBlock types.Block
		err := rlp.DecodeBytes(common.Hex2Bytes(block.EncodeData), roiBlock)
		return &roiBlock, err
	}
	errstr := fmt.Sprintf("can not find block with given blockHash :%s", blockHash.Hex())
	return nil, errors.New(errstr)
}
**/