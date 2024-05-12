package db


// OrderedMap 代表有序的 Map 结构
type OrderedMap struct {
	keys   []string
	values map[string][]byte
}

// NewOrderedMap 创建一个新的有序 Map
func NewOrderedMap() *OrderedMap {
	return &OrderedMap{
		keys:   make([]string, 0),
		values: make(map[string][]byte),
	}
}

// Set 设置键值对
func (om *OrderedMap) Set(key string, value []byte) {
	_, exists := om.values[key]
	if !exists {
		om.keys = append(om.keys, key)
	}
	om.values[key] = value
}

// Get 获取键对应的值
func (om *OrderedMap) Get(key string) ([]byte, bool) {
	value, exists := om.values[key]
	return value, exists
}

// Keys 返回有序的键列表
func (om *OrderedMap) Keys() []string {
	return om.keys
}

// Values 返回值的切片
func (om *OrderedMap) Values() [][]byte {
	values := make([][]byte, len(om.keys))
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