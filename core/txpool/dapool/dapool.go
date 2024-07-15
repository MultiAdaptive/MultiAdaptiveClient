package dapool

import (
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethdb/db"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/params"
	kzgSdk "github.com/multiAdaptive/kzg-sdk"
	"gorm.io/gorm"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrAlreadyKnown is returned if the DA is already contained
	// within the pool.
	ErrAlreadyKnown = errors.New("already known")

	// ErrDAPoolOverflow is returned if the DA pool is full and can't accept
	// another remote DA.
	ErrDAPoolOverflow = errors.New("DA pool is full")
)

var (
	evictionInterval = time.Minute // Time interval to check for evictable DA
)

var (
	knownDAMeter       = metrics.NewRegisteredMeter("DA/known", nil)
	invalidDAMeter     = metrics.NewRegisteredMeter("DA/invalid", nil)

	slotsGauge   = metrics.NewRegisteredGauge("DA/slots", nil)
)

var (
	HashListKey = []byte("HashListKey")  //disk hash and disk time
)

const WaitTime = 500

type Config struct {
	Journal   string           // Journal of local file to survive node restarts
	Locals    []common.Address // Addresses that should be treated by default as local

	Rejournal time.Duration    // Time interval to regenerate the local DA journal
	// JournalRemote controls whether journaling includes remote DA or not.
	// When true, all DA loaded from the journal are treated as remote.
	JournalRemote bool
	Lifetime      time.Duration
	GlobalSlots   uint64 // Maximum number of executable DA slots for all accounts
}

var DefaultConfig = Config{
	Journal:  "DA.rlp",
	Lifetime: 10 * time.Second,
	Rejournal: time.Hour,
	JournalRemote: true,
	GlobalSlots: 4096,
}

type BlockChain interface {
	// Config retrieves the chain's fork configuration.
	Config() *params.ChainConfig

	// CurrentBlock returns the current head of the chain.
	CurrentBlock() *types.Header

	// GetBlock retrieves a specific block, used during pool resets.
	GetBlock(hash common.Hash, number uint64) *types.Block

	// SqlDB() returns the blockchain sql db
	SqlDB() *gorm.DB
}

type DiskDetail struct {
	TxHash        common.Hash 				`json:"TxHash"`
	TimeRecord    time.Time					`json:"TimeRecord"`
	Data          types.DA			           `json:"Data"`
}

type HashCollect struct {
	Hashes   map[common.Hash]time.Time  `json:"Hashes"`
}

func newHashCollect() *HashCollect{
	return &HashCollect{
		Hashes: make(map[common.Hash]time.Time),
	}
}

type DAPool struct {
	config          Config
	chainconfig     *params.ChainConfig
	client           *ethclient.Client
	chain            BlockChain
	DAFeed            event.Feed
	DAHashFeed        event.Feed
	mu              sync.RWMutex
	signer          types.DASigner
	journal         *journal                // Journal of local DA to back up to disk
	subs            event.SubscriptionScope // Subscription scope to unsubscribe all on shutdown
	all             *lookup
	nodeType        string
	diskCache	    *HashCollect  //
	collector       map[common.Hash]*types.DA
	beats           map[common.Hash]time.Time // Last heartbeat from each known account
	reorgDoneCh     chan chan struct{}
	reorgShutdownCh chan struct{}  // requests shutdown of scheduleReorgLoop
	wg              sync.WaitGroup // tracks loop
	initDoneCh      chan struct{}  // is closed once the pool is initialized (for tests)
	currentBlock     atomic.Pointer[types.Header] // Current head of the blockchain
}

func New(config Config, chain BlockChain,nodeType string) *DAPool {
	dp := &DAPool{
		config:          config,
		chain:	     chain,
		chainconfig:     chain.Config(),
		signer:          types.LatestDASigner(chain.Config()),
		all:             newLookup(),
		diskCache:	     newHashCollect(),
		nodeType:        nodeType,
		collector:       make(map[common.Hash]*types.DA),
		beats:           make(map[common.Hash]time.Time),
		reorgDoneCh:     make(chan chan struct{}),
		reorgShutdownCh: make(chan struct{}),
		initDoneCh:      make(chan struct{}),
	}

	if (config.JournalRemote) && config.Journal != "" {
		dp.journal = newDAJournal(config.Journal)
	}

	dp.Init(chain.CurrentBlock())
	return dp
}

func (dp *DAPool) SetClient(url string) {
	client,err := ethclient.Dial(url)
	if err == nil {
		dp.client = client
	}
}

func (dp *DAPool) Init(head *types.Header) error {
	// Initialize the state with head block, or fallback to empty one in
	// case the head state is not available(might occur when node is not
	// fully synced).
	currentBlock := dp.chain.CurrentBlock()
	dp.currentBlock.Store(currentBlock)

	// If local DA and journaling is enabled, load from disk
	if dp.journal != nil {
		add := dp.addLocals
		if dp.config.JournalRemote {
			add = dp.addRemotesSync // Use sync version to match pool.AddLocals
		}
		if err := dp.journal.load(add); err != nil {
			log.Warn("Failed to load transaction journal", "err", err)
		}
		if err := dp.journal.rotate(dp.toJournal()); err != nil {
			log.Warn("Failed to rotate transaction journal", "err", err)
		}
	}
	dp.wg.Add(1)

	if dp.nodeType == "b" {
		das,err := db.GetAllDARecords(dp.chain.SqlDB())
		if err != nil {
			log.Info("DAPool init","err",err.Error())
		}else {
			for _,da := range das{
				dp.mu.Lock()
				dp.diskCache.Hashes[da.TxHash] = da.ReceiveAt
				hashData := common.BytesToHash(da.Commitment.Marshal())
				dp.diskCache.Hashes[hashData] = da.ReceiveAt
				dp.mu.Unlock()
			}
		}
	}

	go dp.loop()
	return nil
}

func (dp *DAPool) loop() {
	defer dp.wg.Done()

	var (
		// Start the stats reporting and DA eviction tickers
		evict   = time.NewTicker(evictionInterval)
		journal = time.NewTicker(dp.config.Rejournal)
		remove  = time.NewTicker(dp.config.Lifetime)
	)
	defer evict.Stop()
	defer journal.Stop()

	// Notify tests that the init phase is done
	close(dp.initDoneCh)
	for {
		select {
		// Handle pool shutdown
		case <-dp.reorgShutdownCh:
			return

		case <- remove.C:
			dp.mu.Lock()
			for hash,receive := range dp.diskCache.Hashes {
				if receive.Add(14*24*time.Hour).Before(time.Now()) {
					db.DeleteDAByHash(dp.chain.SqlDB(),hash)
					delete(dp.diskCache.Hashes,hash)
				}
			}
			dp.mu.Unlock()
			remove.Reset(dp.config.Lifetime)
		// Handle inactive Hash DA eviction
		case <-evict.C:
			dp.mu.Lock()
			for hash := range dp.collector {
				// Any non-locals old enough should be removed
				if time.Since(dp.beats[hash]) > 24 * time.Hour {
					for txHash := range dp.collector {
						for hash,_ := range dp.diskCache.Hashes {
							if hash == txHash {
								delete(dp.diskCache.Hashes,hash)
							}
						}
						dp.removeDA(txHash)
					}
				}
			}
			dp.mu.Unlock()

		// Handle local DA journal rotation
		case <-journal.C:
			if dp.journal != nil {
				dp.mu.Lock()
				if err := dp.journal.rotate(dp.toJournal()); err != nil {
					log.Warn("Failed to rotate local DA journal", "err", err)
				}
				dp.mu.Unlock()
			}
		}
	}
}

func (dp *DAPool) AddInToDisk(hash common.Hash,receive time.Time)  {
	dp.diskCache.Hashes[hash] = receive
}

// SubscribeDAs registers a subscription for new DA events,
// supporting feeding only newly seen or also resurrected DA.
func (dp *DAPool) SubscribenDAS(ch chan<- core.NewDAEvent) event.Subscription {
	// The legacy pool has a very messed up internal shuffling, so it's kind of
	// hard to separate newly discovered DA from resurrected ones. This
	// is because the new DA are added to , resurrected ones too and
	// reorgs run lazily, so separating the two would need a marker.
	return dp.DAFeed.Subscribe(ch)
}

// SubscribenDAsHash registers a subscription for get unknow DA by txHash.
func (dp *DAPool) SubscribenDASHash(ch chan<- core.DAHashEvent) event.Subscription {
	return dp.DAHashFeed.Subscribe(ch)
}


func (dp *DAPool) removeDA(hash common.Hash) error {
	fd := dp.all.Get(hash)
	if fd == nil {
		return errors.New("DA with that da hash not exist")
	}
	delete(dp.beats, hash)
	dp.all.Remove(hash)
	delete(dp.collector, hash)
	return nil
}

// cached with the given hash.
func (dp *DAPool) Has(hash common.Hash) bool{
	fd := dp.get(hash)
	return fd != nil
}

func (dp *DAPool) GetSender(signData [][]byte) ([]common.Address,[]error) {
	da := new(types.DA)
	da.SignData = signData
	recoverAddr,err := types.FdSender(dp.signer,da)
	return recoverAddr,err
}

func (dp *DAPool) GetDAByCommit(commit []byte) (*types.DA,error){
	dp.mu.RLock()
	defer dp.mu.RUnlock()
	var digest kzg.Digest
	digest.SetBytes(commit)
	cmHash := common.BytesToHash(digest.Marshal())
	log.Info("GetDAByCommit-----","cmHash",cmHash.Hex())
	var getTimes uint64
Lable:
	fd := dp.get(cmHash)
	if fd != nil {
		return fd,nil
	}
	da,err := db.GetDAByCommitment(dp.chain.SqlDB(),commit)
	if err != nil || da == nil {
		log.Info("本地节点没有从需要从远端要--------", "cmHash", cmHash.String())
		if getTimes < 1 {
			dp.DAHashFeed.Send(core.DAHashEvent{Hashes: []common.Hash{cmHash}})
			log.Info("本地节点没有从需要从远端要---进来了么")
		}
		time.Sleep(WaitTime * time.Millisecond)
		getTimes++
		if getTimes <= 1 {
			goto Lable
		}
	}
	return da,nil
}

// Get retrieves the DA from local DAPool with given
// hash.
func (dp *DAPool) Get(hash common.Hash) (*types.DA,error){
	dp.mu.RLock()
	defer dp.mu.RUnlock()
	var getTimes uint64
Lable:
	fd := dp.get(hash)
	if fd == nil {
		da,err := db.GetCommitmentByTxHash(dp.chain.SqlDB(),hash)
		if err != nil || da == nil {
			if getTimes < 1 {
				da,err = db.GetDAByCommitmentHash(dp.chain.SqlDB(),hash)
				if da == nil || err != nil{
					dp.DAHashFeed.Send(core.DAHashEvent{Hashes: []common.Hash{hash}})
					log.Info("本地节点没有从需要从远端要--------","hash",hash.String())
					return nil,nil
				}else {
					return da,nil
				}
			}
			time.Sleep(WaitTime * time.Millisecond)
			getTimes ++
			if getTimes <= 1 {
				goto Lable
			}
			currentPath, _ := os.Getwd()
			file, _ := os.OpenFile(currentPath+"/unknowTxHash.txt", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
			str := fmt.Sprintf("can not find DA by TxHash is： %s time to ask ： %s",hash.Hex(),time.Now().String())
			writeStr := str + "\n"
			if _, err := file.WriteString(writeStr); err != nil {
				log.Info("WriteString unknowTxHash err",err.Error())
			}
			file.Close()
		}else {
			return da,nil
		}
	}else {
		return fd,nil
	}
	return nil,nil
}

func (dp *DAPool) GetDA(hash common.Hash) (*types.DA,error) {
	dp.mu.RLock()
	defer dp.mu.RUnlock()
	var getTimes uint64
Lable:
	fd := dp.get(hash)
	if fd == nil {
		da,err := db.GetCommitmentByTxHash(dp.chain.SqlDB(),hash)
		if err != nil || da.Data == nil || len(da.Data) == 0 {
			if getTimes < 1 {
				da,err = db.GetDAByCommitmentHash(dp.chain.SqlDB(),hash)
				if da == nil || err != nil{
					return nil,nil
				}else {
					return da,nil
				}
			}
			daLength := da.Length
			index := daLength / 1000
			d := time.Duration(index)
			wait := d * WaitTime * time.Millisecond
			time.Sleep(wait)
			getTimes ++
			if getTimes <= 1 {
				goto Lable
			}
		}else {
			return da,nil
		}
	}else {
		return fd,nil
	}
	return nil,nil
}


// get returns a DA if it is contained in the pool and nil otherwise.
func (dp *DAPool) get(hash common.Hash) *types.DA {
	return dp.all.Get(hash)
}


// addRemotesSync is like addRemotes, but waits for pool reorganization. Tests use this method.
func (dp *DAPool) addRemotesSync(fds []*types.DA) []error {
	return dp.Add(fds, false, true)
}

// toJournal retrieves all DA that should be included in the journal,
// grouped by origin account and sorted by nonce.
// The returned DA set is a copy and can be freely modified by calling code.
func (dp *DAPool) toJournal() map[common.Hash]*types.DA {
	fds := make(map[common.Hash]*types.DA)
	for hash, fd := range dp.collector {
		fds[hash] = fd
	}
	return fds
}

// addLocals enqueues a batch of DA into the pool if they are valid, marking the
// senders as local ones, ensuring they go around the local pricing constraints.
//
// This method is used to add DA from the RPC API and performs synchronous pool
// reorganization and event propagation.
func (dp *DAPool) addLocals(fds []*types.DA) []error {
	return dp.Add(fds, true, true)
}

// Add enqueues a batch of DA into the pool if they are valid. Depending
// on the local flag, full pricing constraints will or will not be applied.
//
// If sync is set, the method will block until all internal maintenance related
// to the add is finished. Only use this during tests for determinism!
func (dp *DAPool) Add(fds []*types.DA, local, sync bool) []error {
	dp.mu.Lock()
	defer dp.mu.Unlock()
	// Filter out known ones without obtaining the pool lock or recovering signatures
	var (
		errs = make([]error, len(fds))
		news = make([]*types.DA, 0, len(fds))
	)
	for i, fd := range fds {
		// If the DA is known, pre-set the error slot
		var hashData  common.Hash

		flag,err := dp.validateDASignature(fd,local)
		if !flag || err != nil {
			errs = append(errs,err)
		}

		if fd.TxHash.Cmp(common.Hash{}) != 0 {
			hashData = fd.TxHash
			txHash := fd.TxHash.String()
			log.Info("DAPool----Add","txHash",txHash)
		}else {
			hashData = common.BytesToHash(fd.Commitment.Marshal())
			log.Info("DAPool----Add","commitHash",hashData.Hex())
		}

		if dp.nodeType == "b" {
			dp.AddInToDisk(hashData,fd.ReceiveAt)
		}

		if dp.all.Get(hashData) != nil {
			errs[i] = ErrAlreadyKnown
			knownDAMeter.Mark(1)
			continue
		}
		news = append(news, fd)
	}
	if len(news) == 0 {
		return errs
	}

	newErrs := dp.addDAsLocked(news, local)
	var nilSlot = 0
	var final = make([]*types.DA, 0)
	for index, err := range newErrs {
		if err == nil {
			final = append(final,news[index])
		}
		for errs[nilSlot] != nil {
			nilSlot++
		}
		errs[nilSlot] = err
		nilSlot++
	}
	if len(final) != 0 {
		dp.DAFeed.Send(core.NewDAEvent{Fileds: final})
	}
	return errs
}

func (dp *DAPool) SendNewDAEvent(DA []*types.DA) {
	if len(DA) != 0 {
		dp.DAFeed.Send(core.NewDAEvent{Fileds: DA})
	}
}

func (dp *DAPool) RemoveDA(das []*types.DA) {
	dp.mu.Lock()
	defer dp.mu.Unlock()
	for _,da := range das{
		if len(da.TxHash) != 0 {
			delete(dp.all.collector, da.TxHash)
		}
		delete(dp.all.collector, common.BytesToHash(da.Commitment.Marshal()))
	}
}

// addDAsLocked attempts to queue a batch of DAs if they are valid.
// The DA pool lock must be held.
func (dp *DAPool) addDAsLocked(fds []*types.DA, local bool) []error {
	errs := make([]error, len(fds))
	for i, fd := range fds {
		_, err := dp.add(fd, local)
		errs[i] = err
	}
	return errs
}

// add validates a DA and inserts it into the non-executable queue for later
// saved.
func (dp *DAPool) add(fd *types.DA, local bool) (replaced bool, err error) {
	var hash common.Hash
	// If the DA is already known, discard it
	if fd.TxHash.Cmp(common.Hash{}) != 0 {
		hash = fd.TxHash
		log.Info("DAPool----add","TxHash---hash",hash.Hex())
	}else {
		hash = common.BytesToHash(fd.Commitment.Marshal())
		log.Info("DAPool----add","Commitment --hash",hash.Hex())
	}
	if dp.all.Get(hash) != nil {
		log.Trace("Discarding already known DA", "hash", hash)
		knownDAMeter.Mark(1)
		return false, ErrAlreadyKnown
	}

	if uint64(dp.all.Slots()+1) > dp.config.GlobalSlots {
		return false,ErrDAPoolOverflow
	}

	dp.journalFd(hash, fd)
	dp.all.Add(fd)
	dp.beats[hash] = time.Now()
	log.Trace("Pooled new future transaction", "hash", hash)
	return replaced, nil
}

// journalFd adds the specified DA to the local disk journal if it is
// deemed to have been sent from a local account.
func (dp *DAPool) journalFd(txHash common.Hash, fd *types.DA) {
	// Only journal if it's enabled and the DA is local
	_, flag := dp.collector[txHash]
	if dp.journal == nil || (!dp.config.JournalRemote && !flag) {
		return
	}
	if err := dp.journal.insert(fd); err != nil {
		log.Warn("Failed to journal local DA", "err", err)
	}
}

// Close terminates the DA pool.
func (dp *DAPool) Close() error {
	// Terminate the pool reorger and return
	close(dp.reorgShutdownCh)
	dp.wg.Wait()

	dp.subs.Close()

	if dp.journal != nil {
		dp.journal.close()
	}
	log.Info("DAPool pool stopped")
	return nil
}

// validateDASignature checks whether a DA is valid according to the consensus
// rules, but does not check state-dependent validation such as sufficient balance.
// This check is meant as an early check which only needs to be performed once,
// and does not require the pool mutex to be held.
func (dp *DAPool) validateDASignature(da *types.DA, local bool) (bool,error) {
	if local {
		return true,nil
	}
	if da.Length != uint64(len(da.Data)) {
		return false,errors.New("DA data length not match legth")
	}
	if len(da.SignData) == 0  {
		return false,errors.New("DA signature is empty")
	}

	currentPath, _ := os.Getwd()
	path := strings.Split(currentPath,"/build")[0] + "/srs"
	domiconSDK, err := kzgSdk.InitMultiAdaptiveSdk(path)
	if err != nil {
		return false, err
	}
	commit := da.Commitment.Marshal()
	_, err = domiconSDK.VerifyCommitWithProof(commit, da.Proof, da.ClaimedValue)
	if err != nil {
		return false, err
	}
	return true,nil
}



type lookup struct {
	slots   int
	lock      sync.RWMutex
	collector map[common.Hash]*types.DA
}

// newLookup returns a new lookup structure.
func newLookup() *lookup {
	return &lookup{
		collector: make(map[common.Hash]*types.DA),
	}
}

// Range calls f on each key and value present in the map. The callback passed
// should return the indicator whether the iteration needs to be continued.
// Callers need to specify which set (or both) to be iterated.
func (t *lookup) Range(f func(hash common.Hash, fd *types.DA) bool) {
	t.lock.RLock()
	defer t.lock.RUnlock()
	for key, value := range t.collector {
		if !f(key, value) {
			return
		}
	}
}

// Get returns a DA if it exists in the lookup, or nil if not found.
func (t *lookup) Get(hash common.Hash) *types.DA {
	t.lock.RLock()
	defer t.lock.RUnlock()

	if fd := t.collector[hash]; fd != nil {
		return fd
	}
	return nil
}

// Count returns the current number of DA in the lookup.
func (t *lookup) Count() int {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return len(t.collector)
}

// Add adds a DA to the lookup.
func (t *lookup) Add(fd *types.DA) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.slots += 1
	slotsGauge.Update(int64(t.slots))
	log.Info("Add-----加进来了")
	var commitIsEmpty bool
	if fd.Commitment.X.IsZero() && fd.Commitment.Y.IsZero() {
		commitIsEmpty = true
	}

	if fd.TxHash.Cmp(common.Hash{}) != 0 && commitIsEmpty  {
		t.collector[fd.TxHash] = fd
	}else if fd.TxHash.Cmp(common.Hash{}) != 0 && !commitIsEmpty{
		t.collector[fd.TxHash] = fd
		hash := common.BytesToHash(fd.Commitment.Marshal())
		t.collector[hash] = fd
	}else if fd.TxHash.Cmp(common.Hash{}) == 0 && !commitIsEmpty{
		hash := common.BytesToHash(fd.Commitment.Marshal())
		t.collector[hash] = fd
	}else if fd.TxHash.Cmp(common.Hash{}) == 0 && commitIsEmpty{
		return
	}
}

// Slots returns the current number of slots used in the lookup.
func (t *lookup) Slots() int {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.slots
}


// Remove removes a DA from the lookup.
func (t *lookup) Remove(hash common.Hash) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.slots -= 1
	slotsGauge.Update(int64(t.slots))
	delete(t.collector, hash)
}
