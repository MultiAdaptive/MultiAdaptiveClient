package node

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/contract"
	baseModel "github.com/ethereum/go-ethereum/eth/basemodel"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethdb/db"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/gorilla/mux"
	los "github.com/samber/lo"
	"github.com/spf13/cast"
	"gorm.io/gorm"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Database 实例
var askUrl string
var stateSqlDB *gorm.DB
var privateKey *ecdsa.PrivateKey
var l1Conf *params.L1Config
var chainId uint64

type explorerServer struct {
	log     log.Logger
	server  *http.Server
	host    string
	port    int
	datadir string
}

func newExplorerServer(log log.Logger, datadir string) *explorerServer {
	h := &explorerServer{
		log:     log,
		datadir: datadir,
	}
	return h
}

func (h *explorerServer) setPrivateKey(key *ecdsa.PrivateKey) {
	privateKey = key
}

func (h *explorerServer) SetAskUrl(url string) {
	askUrl = url
}

func (h *explorerServer) SetL1Conf(conf *params.L1Config) {
	l1Conf = conf
}

func (h *explorerServer) SetChainId(chainID uint64) {
	chainId = chainID
}

func (h *explorerServer) setListenAddr(host string, port int) error {
	h.host, h.port = host, port
	return nil
}

type BlobBrief struct {
	BlobID         int64    `json:"blob_id"`
	Commitment     string   `json:"commitment"`
	CommitmentHash string   `json:"commitment_hash"`
	TxHash         string   `json:"tx_hash"`
	BlockNum       int64    `json:"block_num"`
	ReceiveAt      string   `json:"receive_at"`
	Length         int64    `json:"length"`
	Validators     []string `json:"validators"`
	Fee            string   `json:"fee"`
}

type BlobFilter struct {
	Index          int64    `json:"index"`
	Length         int64    `json:"length"`
	TxHash         string   `json:"tx_hash"`
	CommitmentHash string   `json:"commitment_hash"`
	BlockNum       int64    `json:"block_num"`
	ReceiveAt      string   `json:"receive_at"`
	Fee            string   `json:"fee"`
	Validators     []string `json:"validators"`
}

type BlobShow struct {
	BlobID         int64    `json:"blob_id"`
	CommitmentHash string   `json:"commitment_hash"`
	BlockNum       int64    `json:"block_num"`
	ReceiveAt      string   `json:"receive_at"`
	Fee            string   `json:"fee"`
	Length         int64    `json:"length"`
	Validators     []string `json:"validators"`
	TxHash         string   `json:"tx_hash"`
}

type Blob struct {
	Sender         string `json:"sender"`
	Index          int64  `json:"index"`
	Length         int64  `json:"length"`
	TxHash         string `json:"tx_hash"`
	Commitment     string `json:"commitment"`
	CommitmentHash string `json:"commitment_hash"`
	//Proof           string    `json:"proof"`
	Data            string   `json:"data"`
	DAsKey          string   `json:"das_key"`
	SignData        string   `json:"sign_data"`
	ParentStateHash string   `json:"parent_state_hash"`
	StateHash       string   `json:"state_hash"`
	BlockNum        int64    `json:"block_num"`
	ReceiveAt       string   `json:"receive_at"`
	Fee             string   `json:"fee"`
	Validators      []string `json:"validators"`
}

type Pagination struct {
	Total   int `json:"total"`
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
}

type PageBlobFilters struct {
	Data       []BlobFilter `json:"data"`
	Pagination Pagination   `json:"pagination"`
}

type PageBlobShows struct {
	Data       []BlobShow `json:"data"`
	Pagination Pagination `json:"pagination"`
}

type PageBlobs struct {
	Data       []Blob     `json:"data"`
	Pagination Pagination `json:"pagination"`
}

// Node represents the node data structure
type NodeInfo struct {
	Name         string `json:"name"`
	Url          string `json:"url"`
	NodeAddress  string `json:"node_address"`
	StakedTokens uint64 `json:"staked_tokens"`
	Chain        string `json:"chain"`
	Location     string `json:"location"`
	NodeType     string `json:"node_type"`
}

type CommitmentCoordinate struct {
	X string `json:"x"`
	Y string `json:"y"`
}

type BlobDetail struct {
	BlobID         int64                `json:"blob_id"`
	Commitment     string               `json:"commitment"`
	CommitmentHash string               `json:"commitment_hash"`
	TxHash         string               `json:"tx_hash"`
	BlockNum       int64                `json:"block_num"`
	Timestamp      string               `json:"timestamp"`
	Size           int64                `json:"size"`
	StorageState   string               `json:"storage_state"`
	CommitmentXY   CommitmentCoordinate `json:"commitment_xy"`
	Data           string               `json:"data"`
	Validators     []string             `json:"validators"`
	Fee            string               `json:"fee"`
	Proof          string               `json:"proof"`
}

// Validator represents the validator data structure
type Validator struct {
	ValidatorName         string  `json:"validator_name"`
	ValidatorAddress      string  `json:"validator_address"`
	ValidatorStatus       string  `json:"validator_status"`
	TotalStakedAmount     float64 `json:"total_staked_amount"`
	AvailableStakedAmount float64 `json:"available_staked_amount"`
	CommissionRate        float64 `json:"commission_rate"`
	VotingPower           float64 `json:"voting_power"`
}

// InfoHandler 处理 /info 请求
func InfoHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Server is alive!"))
}

// HomeDataHandler handles the GET /api/home-data endpoint
func HomeDataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		var gormdb *gorm.DB
		var das []db.DA
		gormdb = stateSqlDB.
			Model(&db.DA{}).
			Select("f_nonce, f_tx_hash, f_commitment, f_commitment_hash, f_block_num, f_length, f_sign_address, f_receive_at").
			Order("f_nonce desc").
			Limit(5).
			Find(&das)

		if gormdb.Error != nil {
			log.Error("can not find DA", "err", gormdb.Error)
		}

		txHashs := los.Map(das, func(da db.DA, index int) string {
			return da.TxHash
		})

		var baseTransactions []baseModel.BaseTransaction
		gormdb = stateSqlDB.
			Model(&baseModel.BaseTransaction{}).
			Select("f_transaction_hash, f_fee").
			Where("f_transaction_hash IN ?", txHashs).
			Find(&baseTransactions)
		if gormdb.Error != nil {
			log.Error("can not find BaseTransaction", "txHashs", txHashs, "err", gormdb.Error)
		}

		blobs := make([]BlobBrief, 0)
		for _, da := range das {

			item, found := los.Find(baseTransactions, func(baseTransaction baseModel.BaseTransaction) bool {
				return strings.ToLower(baseTransaction.TransactionHash) == strings.ToLower(da.TxHash)
			})

			fee := 0.0
			if found {
				fee = item.Fee
			}

			blob := BlobBrief{
				BlobID:         da.Nonce,
				Commitment:     da.Commitment,
				CommitmentHash: da.CommitmentHash,
				TxHash:         da.TxHash,
				BlockNum:       da.BlockNum,
				Length:         da.Length,
				ReceiveAt:      da.ReceiveAt,
				Validators:     strings.Split(da.SignAddr, SEPARATOR_COMMA),
				Fee:            cast.ToString(fee),
			}
			blobs = append(blobs, blob)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(blobs)
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// CreateBlobHandler handles the POST /api/create-blob endpoint
func CreateBlobHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var newBlob Blob
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Error("read body fail", "err", err)
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		err = json.Unmarshal(body, &newBlob)
		if err != nil {
			log.Error("body to blob fail", "body", string(body), "err", err)
			http.Error(w, "Invalid JSON format", http.StatusBadRequest)
			return
		}

		var gormdb *gorm.DB
		da := db.DA{
			Sender:          newBlob.Sender,
			Index:           newBlob.Index,
			Length:          newBlob.Length,
			TxHash:          newBlob.TxHash,
			Commitment:      newBlob.Commitment,
			CommitmentHash:  newBlob.CommitmentHash,
			Data:            newBlob.Data,
			DAsKey:          newBlob.DAsKey,
			SignData:        newBlob.SignData,
			ParentStateHash: newBlob.ParentStateHash,
			//StateHash:       newBlob.StateHash,
			BlockNum:        newBlob.BlockNum,
			ReceiveAt:       newBlob.ReceiveAt,
		}

		gormdb = stateSqlDB.Save(&da)
		if gormdb.Error != nil {
			log.Error("save fail", "err", err)
			http.Error(w, "save fail", http.StatusOK)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(newBlob)
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// SearchHandler handles the GET /api/search-blob endpoint with query parameters
func SearchBlobHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		query := r.URL.Query().Get("q")
		category := r.URL.Query().Get("category")
		dataSize := r.URL.Query().Get("data_size")

		if query == "" {
			http.Error(w, "Missing query or category parameter", http.StatusBadRequest)
			return
		}
		var gormdb *gorm.DB
		var das []db.DA
		var blobs []Blob

		switch strings.ToLower(category) {
		case "sender":
			gormdb = stateSqlDB.
				Where(db.DA{Sender: query}).
				Find(&das)

		case "txhash":
			gormdb = stateSqlDB.
				Where(db.DA{TxHash: query}).
				Find(&das)
		case "commitmenthash":
			gormdb = stateSqlDB.
				Where(db.DA{CommitmentHash: query}).
				Find(&das)
		case "blocknum":
			num, _ := strconv.Atoi(query)
			gormdb = stateSqlDB.
				Where(db.DA{BlockNum: int64(num)}).
				Find(&das)
		default:
			http.Error(w, "Invalid category parameter", http.StatusBadRequest)
			return
		}

		if gormdb != nil && gormdb.Error != nil {
			log.Error("can not find DA", "query", query, "category", category, "err", gormdb.Error)
		}

		txHashs := los.Map(das, func(da db.DA, index int) string {
			return da.TxHash
		})

		var baseTransactions []baseModel.BaseTransaction
		gormdb = stateSqlDB.
			Model(&baseModel.BaseTransaction{}).
			Select("f_transaction_hash, f_fee").
			Where("f_transaction_hash IN ?", txHashs).
			Find(&baseTransactions)
		if gormdb.Error != nil {
			log.Error("can not find BaseTransaction", "txHashs", txHashs, "err", gormdb.Error)
		}

		for _, da := range das {
			dataLimit := los.Min([]int{cast.ToInt(dataSize), len(da.Data)})

			item, found := los.Find(baseTransactions, func(baseTransaction baseModel.BaseTransaction) bool {
				return strings.ToLower(baseTransaction.TransactionHash) == strings.ToLower(da.TxHash)
			})

			fee := 0.0
			if found {
				fee = item.Fee
			}

			blob := Blob{
				Sender:         da.Sender,
				Index:          da.Index,
				Length:         da.Length,
				TxHash:         da.TxHash,
				Commitment:     da.Commitment,
				CommitmentHash: da.CommitmentHash,
				//Proof:           da.Proof,
				Data:            da.Data[0:dataLimit],
				DAsKey:          da.DAsKey,
				SignData:        da.SignData,
				ParentStateHash: da.ParentStateHash,
				//StateHash:       da.StateHash,
				BlockNum:        da.BlockNum,
				ReceiveAt:       da.ReceiveAt,
				Validators:      strings.Split(da.SignAddr, SEPARATOR_COMMA),
				Fee:             cast.ToString(fee),
			}
			blobs = append(blobs, blob)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(blobs)
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// FilterBlobHandler handles the GET /api/filter-blob endpoint with pagination and filtering
func FilterBlobHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		filter := r.URL.Query().Get("filter")
		pageStr := r.URL.Query().Get("page")
		perPageStr := r.URL.Query().Get("per_page")

		if pageStr == "" || perPageStr == "" {
			http.Error(w, "Missing page or per_page parameter", http.StatusBadRequest)
			return
		}

		page := cast.ToInt64(pageStr)
		perPage := cast.ToInt64(perPageStr)

		if page < 1 || perPage == 0 {
			http.Error(w, "Invalid page or perPage parameter", http.StatusBadRequest)
			return
		}

		var filteredBlobs []BlobFilter

		var gormdb *gorm.DB
		var das []db.DA
		var count int64

		offset := (page - 1) * perPage

		if len(filter) == 0 {
			gormdb = stateSqlDB.
				Model(&db.DA{}).
				Count(&count)

			gormdb = stateSqlDB.
				Select("f_index, f_nonce, f_tx_hash, f_commitment_hash, f_block_num, f_length, f_sign_address, f_receive_at").
				Order("f_receive_at desc").
				Offset(int(offset)).
				Limit(int(perPage)).
				Find(&das)
		} else {
			gormdb = stateSqlDB.
				Model(&db.DA{}).
				Where("f_commitment LIKE ?", "%"+filter+"%").
				Or("f_sender LIKE ?", "%"+filter+"%").
				Or("f_tx_hash LIKE ?", "%"+filter+"%").
				Or("f_nonce LIKE ?", "%"+filter+"%").
				Or("f_sign_address LIKE ?", "%"+filter+"%").
				Count(&count)

			gormdb = stateSqlDB.
				Select("f_index, f_nonce, f_tx_hash, f_commitment_hash, f_block_num, f_length, f_sign_address, f_receive_at").
				Where("f_commitment LIKE ?", "%"+filter+"%").
				Or("f_sender LIKE ?", "%"+filter+"%").
				Or("f_tx_hash LIKE ?", "%"+filter+"%").
				Or("f_nonce LIKE ?", "%"+filter+"%").
				Or("f_sign_address LIKE ?", "%"+filter+"%").
				Order("f_receive_at desc").
				Offset(int(offset)).
				Limit(int(perPage)).
				Find(&das)
		}
		if gormdb.Error != nil {
			log.Error("can not find DA", "err", gormdb.Error)
		}

		txHashs := los.Map(das, func(da db.DA, index int) string {
			return da.TxHash
		})

		var baseTransactions []baseModel.BaseTransaction
		gormdb = stateSqlDB.
			Model(&baseModel.BaseTransaction{}).
			Select("f_transaction_hash, f_fee").
			Where("f_transaction_hash IN ?", txHashs).
			Find(&baseTransactions)
		if gormdb.Error != nil {
			log.Error("can not find BaseTransaction", "txHashs", txHashs, "err", gormdb.Error)
		}

		for _, da := range das {
			item, found := los.Find(baseTransactions, func(baseTransaction baseModel.BaseTransaction) bool {
				return strings.ToLower(baseTransaction.TransactionHash) == strings.ToLower(da.TxHash)
			})

			fee := 0.0
			if found {
				fee = item.Fee
			}

			blob := BlobFilter{
				Index:          da.Index,
				Length:         da.Length,
				TxHash:         da.TxHash,
				CommitmentHash: da.CommitmentHash,
				BlockNum:       da.BlockNum,
				ReceiveAt:      da.ReceiveAt,
				Validators:     strings.Split(da.SignAddr, SEPARATOR_COMMA),
				Fee:            cast.ToString(fee),
			}
			filteredBlobs = append(filteredBlobs, blob)
		}

		response := PageBlobFilters{
			Data: filteredBlobs,
			Pagination: Pagination{
				Total:   int(count),
				Page:    int(page),
				PerPage: int(perPage),
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func ShowBlobHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		pageStr := r.URL.Query().Get("page")
		perPageStr := r.URL.Query().Get("per_page")

		if pageStr == "" || perPageStr == "" {
			http.Error(w, "Missing page or per_page parameter", http.StatusBadRequest)
			return
		}

		page := cast.ToInt64(pageStr)
		perPage := cast.ToInt64(perPageStr)

		if page < 1 || perPage == 0 {
			http.Error(w, "Invalid page or perPage parameter", http.StatusBadRequest)
			return
		}

		var showBlobs []BlobShow

		var gormdb *gorm.DB
		var das []db.DA
		var count int64

		offset := (page - 1) * perPage

		gormdb = stateSqlDB.
			Model(&db.DA{}).
			Count(&count)

		gormdb = stateSqlDB.
			Select("f_index, f_nonce, f_tx_hash, f_commitment_hash, f_block_num, f_length, f_sign_address, f_receive_at").
			Order("f_receive_at desc").
			Offset(int(offset)).
			Limit(int(perPage)).
			Find(&das)

		if gormdb.Error != nil {
			log.Error("can not find DA", "err", gormdb.Error)
		}

		txHashs := los.Map(das, func(da db.DA, index int) string {
			return da.TxHash
		})

		var baseTransactions []baseModel.BaseTransaction
		gormdb = stateSqlDB.
			Model(&baseModel.BaseTransaction{}).
			Select("f_transaction_hash, f_fee").
			Where("f_transaction_hash IN ?", txHashs).
			Find(&baseTransactions)
		if gormdb.Error != nil {
			log.Error("can not find BaseTransaction", "txHashs", txHashs, "err", gormdb.Error)
		}

		for _, da := range das {
			item, found := los.Find(baseTransactions, func(baseTransaction baseModel.BaseTransaction) bool {
				return strings.ToLower(baseTransaction.TransactionHash) == strings.ToLower(da.TxHash)
			})

			fee := 0.0
			if found {
				fee = item.Fee
			}

			blob := BlobShow{
				BlobID:         da.Nonce,
				Length:         da.Length,
				TxHash:         da.TxHash,
				CommitmentHash: da.CommitmentHash,
				BlockNum:       da.BlockNum,
				ReceiveAt:      da.ReceiveAt,
				Validators:     strings.Split(da.SignAddr, SEPARATOR_COMMA),
				Fee:            cast.ToString(fee),
			}
			showBlobs = append(showBlobs, blob)
		}

		response := PageBlobShows{
			Data: showBlobs,
			Pagination: Pagination{
				Total:   int(count),
				Page:    int(page),
				PerPage: int(perPage),
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func BlobDetailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		txHash := r.URL.Query().Get("tx_hash")
		commitmentHash := r.URL.Query().Get("commitment_hash")
		dataSize := r.URL.Query().Get("data_size")

		if txHash == "" && commitmentHash == "" {
			log.Error("parameter error", "txHash", txHash, "commitmentHash", commitmentHash)
			http.Error(w, "Invalid parameter", http.StatusBadRequest)
			return
		}

		var gormdb *gorm.DB
		var da db.DA

		gormdb = stateSqlDB.
			Where(db.DA{TxHash: txHash}).
			Or(db.DA{CommitmentHash: commitmentHash}).
			First(&da)

		if gormdb.Error != nil {
			log.Error("can not find DA", "err", gormdb.Error)
			http.Error(w, "Blob not found", http.StatusNotFound)
			return
		}

		var baseTransaction baseModel.BaseTransaction
		gormdb = stateSqlDB.
			Model(&baseModel.BaseTransaction{}).
			Select("f_transaction_hash, f_fee").
			Where(baseModel.BaseTransaction{TransactionHash: da.TxHash}).
			First(&baseTransaction)
		if gormdb.Error != nil {
			log.Error("can not find BaseTransaction", "txHash", txHash, "err", gormdb.Error)
		}

		fee := baseTransaction.Fee

		commitment := common.Hex2Bytes(da.Commitment)
		var digest kzg.Digest
		digest.SetBytes(commitment)

		dataLimit := los.Min([]int{cast.ToInt(dataSize), len(da.Data)})

		foundBlob := BlobDetail{
			BlobID:         da.Nonce,
			Commitment:     da.Commitment,
			CommitmentHash: da.CommitmentHash,
			TxHash:         da.TxHash,
			BlockNum:       da.BlockNum,
			Timestamp:      da.ReceiveAt,
			Size:           da.Length,
			//StorageState:   da.StateHash,
			CommitmentXY: CommitmentCoordinate{
				X: digest.X.String(),
				Y: digest.Y.String(),
			},
			Data:       da.Data[0:dataLimit],
			Validators: strings.Split(da.SignAddr, SEPARATOR_COMMA),
			Fee:        cast.ToString(fee),
			Proof:      da.Proof,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(foundBlob)
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// NodesHandler handles the GET /api/nodes endpoint
func NodesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		chain := r.URL.Query().Get("chain")
		filteredNodes := make([]NodeInfo, 0)
		switch {
		case chain == "btc" || chain == "bitcoin":
			break
		case chain == "eth" || chain == "ethereum":
			client, err := ethclient.Dial(askUrl)
			if err != nil {
				http.Error(w, "No Node Info found", http.StatusNotFound)
				return
			}
			contractAddress := common.HexToAddress(l1Conf.NodeManagerProxy)
			instance, err := contract.NewNodeManager(contractAddress, client)
			if err != nil {
				http.Error(w, "No Node Info found", http.StatusNotFound)
				return
			}
			result := make([]contract.NodeManagerNodeInfo, 0)
			storResult := make([]contract.NodeManagerNodeInfo, 0)
			nodes, err := instance.GetBroadcastingNodes(nil)
			if err != nil {
				log.Info("GetBroadcastingNodes-----", "err", err.Error())
				http.Error(w, "No Node Info found", http.StatusNotFound)
				return
			}
			log.Info("GetBroadcastingNodes-----", "nodes", len(nodes))
			result = append(result, nodes...)
			strNodes, err := instance.GetBroadcastingNodes(nil)
			storResult = append(storResult, strNodes...)
			for _, node := range result {
				filNode := NodeInfo{
					Name:         node.Name,
					Url:          node.Url,
					NodeAddress:  node.Addr.Hex(),
					StakedTokens: node.StakedTokens.Uint64(),
					Chain:        "eth",
					Location:     node.Location,
					NodeType:     "BroadCast Node",
				}
				if filNode.StakedTokens > 0 {
					filteredNodes = append(filteredNodes, filNode)
				}

			}

			for _, node := range storResult {
				filNode := NodeInfo{
					Name:         node.Name,
					Url:          node.Url,
					NodeAddress:  node.Addr.Hex(),
					StakedTokens: node.StakedTokens.Uint64(),
					Chain:        "eth",
					Location:     node.Location,
					NodeType:     "Storage Node",
				}
				if filNode.StakedTokens > 0 {
					filteredNodes = append(filteredNodes, filNode)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(filteredNodes)
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// start starts the HTTP server if it is enabled and not already running.
func (h *explorerServer) start() error {
	var err error
	stateSqlDB, err = db.NewSqlDB(h.datadir)
	if err != nil {
		log.Error("create sql db failed:", "err", err.Error())
	}

	// 创建一个新的 mux 路由器
	router := mux.NewRouter()

	// 注册 /info 路径和处理器
	router.HandleFunc("/info", InfoHandler).Methods("GET")
	router.HandleFunc("/api/home-data", HomeDataHandler).Methods("GET")
	router.HandleFunc("/api/create-blob", CreateBlobHandler).Methods("POST")
	router.HandleFunc("/api/search-blob", SearchBlobHandler).Methods("GET")
	router.HandleFunc("/api/filter-blob", FilterBlobHandler).Methods("GET")
	router.HandleFunc("/api/show-blob", ShowBlobHandler).Methods("GET")
	router.HandleFunc("/api/blob-detail", BlobDetailHandler).Methods("GET")
	router.HandleFunc("/api/nodes", NodesHandler).Methods("GET")

	// Initialize the server.
	h.server = &http.Server{
		Addr:    h.host + ":" + strconv.Itoa(h.port),
		Handler: router,
	}

	// 启动服务器
	go func(host string, port int) {
		log.Info("Explorer Server is listening", "host", host, "port", port)
		if err := h.server.ListenAndServe(); err != nil {
			log.Error("Server failed to start", "err", err)
		}
	}(h.host, h.port)

	return nil
}

// stop shuts down the HTTP server.
func (h *explorerServer) stop() {
	h.doStop()
}

func (h *explorerServer) doStop() {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	err := h.server.Shutdown(ctx)
	if err != nil && err == ctx.Err() {
		h.log.Warn("HTTP server graceful shutdown timed out")
		h.server.Close()
	}

	// Clear out everything to allow re-configuring it later.
	h.host, h.port = "", 0
	h.server = nil
}
