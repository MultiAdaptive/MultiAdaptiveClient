package eth

type btcTxSortCache struct {
	keyList []string
	cache   map[string]interface{}
}

func NewBtcTxSortCache() *btcTxSortCache {
	return &btcTxSortCache{
		keyList: make([]string,0),
		cache: make(map[string]interface{}),
	}
}

func (b *btcTxSortCache) Set(tx string,val interface{}) {
	_,flag := b.cache[tx]
	if !flag {
		b.keyList = append(b.keyList,tx)
	}
	b.cache[tx] = val
}

func (b *btcTxSortCache) Get(tx string) interface{} {
	return b.cache[tx]
}

func (b *btcTxSortCache) Keys() []string {
	if len(b.keyList) == 0 {
		return []string{}
	}
	return b.keyList
}

//func (b *btcSortCache) Sort()  {
//	quickSort(b.keyList,0,int64(len(b.keyList) - 1))
//}

//func quickSort(arr []int64, left int64, right int64) {
//	if left < right {
//		pivot := partition(arr, left, right)
//		quickSort(arr, left, pivot-1)
//		quickSort(arr, pivot+1, right)
//	}
//}
//
//func partition(arr []int64, left int64, right int64) int64 {
//	pivot := arr[right]
//	i := left - 1
//
//	for j := left; j < right; j++ {
//		if arr[j] < pivot {
//			i++
//			arr[i], arr[j] = arr[j], arr[i]
//		}
//	}
//	arr[i+1], arr[right] = arr[right], arr[i+1]
//	return i + 1
//}