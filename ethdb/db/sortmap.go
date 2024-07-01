package db

import (
	"github.com/ethereum/go-ethereum/common"
	"math/big"
	"time"
)

type CommitDetail struct {
	Nonce    uint64
	Index    uint64
	BlockNum uint64
	Commit   []byte
	TxHash   common.Hash
	SigData  [][]byte
	NameSpaceId *big.Int
	SignAddress []string
	Time     time.Time
	OutOfTime time.Time
	Root     common.Hash
}

// OrderedMap 代表有序的 Map 结构
type OrderedMap struct {
	keys   []string
	values map[string]*CommitDetail
}

// NewOrderedMap 创建一个新的有序 Map
func NewOrderedMap() *OrderedMap {
	return &OrderedMap{
		keys:   make([]string, 0),
		values: make(map[string]*CommitDetail),
	}
}

// Set 设置键值对
func (om *OrderedMap) Set(key string, cbn *CommitDetail) {
	_, exists := om.values[key]
	if !exists {
		om.keys = append(om.keys, key)
	}
	om.values[key] = cbn
}

// Get 获取键对应的值
func (om *OrderedMap) Get(key string) (*CommitDetail, bool) {
	value, exists := om.values[key]
	return value, exists
}

// Keys 返回有序的键列表
func (om *OrderedMap) Keys() []string {
	return om.keys
}

// Values 返回值的切片
func (om *OrderedMap) Values() []*CommitDetail{
	values := make([]*CommitDetail, len(om.keys))
	for i, key := range om.keys {
		values[i] = om.values[key]
	}
	return values
}

func (om *OrderedMap) Del(key string) {
	delete(om.values,key)
	for i,k := range om.keys {
		if k == key {
			om.keys = append(om.keys[:i],om.keys[i+1:]...)
		}
	}
}