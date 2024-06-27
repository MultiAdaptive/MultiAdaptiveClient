package eth

type btcSortCache struct {
	keyList []int64
	cache   map[int64]interface{}
}

func NewBtcSortCache() *btcSortCache {
	return &btcSortCache{
		keyList: make([]int64,0),
		cache: make(map[int64]interface{}),
	}
}

func (b *btcSortCache) Set(index int64,val interface{}) {
	_,flag := b.cache[index]
	if !flag {
		b.keyList = append(b.keyList,index)
	}
	b.cache[index] = val
}

func (b *btcSortCache) Get(index int64) interface{} {
	return b.cache[index]
}

func (b *btcSortCache) Keys() []int64 {
	return b.keyList
}

func (b *btcSortCache) Sort()  {
	quickSort(b.keyList,0,int64(len(b.keyList) - 1))
}

func quickSort(arr []int64, left int64, right int64) {
	if left < right {
		pivot := partition(arr, left, right)
		quickSort(arr, left, pivot-1)
		quickSort(arr, pivot+1, right)
	}
}

func partition(arr []int64, left int64, right int64) int64 {
	pivot := arr[right]
	i := left - 1

	for j := left; j < right; j++ {
		if arr[j] < pivot {
			i++
			arr[i], arr[j] = arr[j], arr[i]
		}
	}
	arr[i+1], arr[right] = arr[right], arr[i+1]
	return i + 1
}