package node

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/ethdb/db"
	"github.com/ethereum/go-ethereum/log"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
	"io"
	"net/http"
	"strconv"
)

// Database 实例
var stateSqlDB *gorm.DB

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

func (h *explorerServer) setListenAddr(host string, port int) error {
	h.host, h.port = host, port
	return nil
}

// InfoHandler 处理 /info 请求
func InfoHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Server is alive!"))
}

// Blob represents the blob data structure
type Blob struct {
	Sender          string `json:"sender"`
	Index           int64  `json:"index"`
	Length          int64  `json:"length"`
	TxHash          string `json:"tx_hash"`
	Commitment      string `json:"commitment"`
	CommitmentHash  string `json:"commitment_hash"`
	Data            string `json:"data"`
	DAsKey          string `json:"das_key"`
	SignData        string `json:"sign_data"`
	ParentStateHash string `json:"parent_state_hash"`
	StateHash       string `json:"state_hash"`
	BlockNum        int64  `json:"block_num"`
	ReceiveAt       string `json:"receive_at"`
}

type ChainBlobs struct {
	Chain string `json:"chain"`
	Blobs []Blob `json:"blobs"`
}

// Node represents the node data structure
type NodeInfo struct {
	NodeString  string `json:"node_string"`
	NodeAddress string `json:"node_address"`
	Chain       string `json:"chain"`
	NodeType    string `json:"node_type"`
}

type BlobDetail struct {
	BlobID       string  `json:"BlobID"`
	Status       string  `json:"Status"`
	Commitment   string  `json:"Commitment"`
	BlockNum     int     `json:"BlockNum"`
	Timestamp    string  `json:"Timestamp"`
	Fee          float64 `json:"Fee"`
	Validator    string  `json:"Validator"`
	Size         int     `json:"Size,omitempty"`
	StorageState string  `json:"StorageState,omitempty"`
	CommitmentXY struct {
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"Commitment_xy,omitempty"`
	Proof string `json:"Proof,omitempty"`
	Data  string `json:"Data,omitempty"`
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

// Sample data for demonstration
//var blobs = []Blob{
//	{"1", "Confirmed", "Commit1", 100, "2024-06-01T12:00:00Z", 0.01, "Validator1", "0x0000001", "Valid"},
//	{"2", "Pending", "Commit2", 101, "2024-06-02T12:00:00Z", 0.02, "Validator2", "0x0000002", "Valid"},
//	{"3", "Failed", "Commit3", 102, "2024-06-01T12:00:00Z", 0.01, "Validator1", "0x0000003", "Valid"},
//	{"4", "Confirmed", "Commit4", 103, "2024-06-01T12:00:00Z", 0.01, "Validator3", "0x0000004", "Valid"},
//	{"5", "Confirmed", "Commit5", 104, "2024-06-01T12:00:00Z", 0.01, "Validator4", "0x0000005", "Valid"},
//	{"6", "Confirmed", "Commit6", 105, "2024-06-01T12:00:00Z", 0.01, "Validator5", "0x0000006", "Valid"},
//}

//var btc_blobs = []Blob{
//	{"1", "Confirmed", "Commit1", 100, "2024-06-01T12:00:00Z", 0.01, "Validator1", "0x0000001", "Valid"},
//	{"2", "Pending", "Commit2", 101, "2024-06-02T12:00:00Z", 0.02, "Validator2", "0x0000002", "Valid"},
//	{"3", "Failed", "Commit3", 102, "2024-06-01T12:00:00Z", 0.01, "Validator1", "0x0000003", "Valid"},
//	{"4", "Confirmed", "Commit4", 103, "2024-06-01T12:00:00Z", 0.01, "Validator3", "0x0000004", "Valid"},
//	{"5", "Confirmed", "Commit5", 104, "2024-06-01T12:00:00Z", 0.01, "Validator4", "0x0000005", "Valid"},
//	{"6", "Confirmed", "Commit6", 105, "2024-06-01T12:00:00Z", 0.01, "Validator5", "0x0000006", "Valid"},
//	{"7", "Confirmed", "Commit7", 106, "2024-06-01T12:00:00Z", 0.01, "Validator1", "0x0000007", "Valid"},
//	{"8", "Confirmed", "Commit8", 107, "2024-06-01T12:00:00Z", 0.01, "Validator5", "0x0000008", "Valid"},
//	{"9", "Confirmed", "Commit9", 108, "2024-06-01T12:00:00Z", 0.01, "Validator2", "0x0000009", "Valid"},
//	{"10", "Confirmed", "Commit10", 109, "2024-06-01T12:00:00Z", 0.01, "Validator6", "0x0000010", "Valid"},
//	{"11", "Confirmed", "Commit11", 110, "2024-06-01T12:00:00Z", 0.01, "Validator3", "0x0000011", "Valid"},
//	{"12", "Confirmed", "Commit12", 111, "2024-06-01T12:00:00Z", 0.01, "Validator1", "0x0000012", "Valid"},
//	{"13", "Confirmed", "Commit13", 112, "2024-06-01T12:00:00Z", 0.01, "Validator2", "0x0000013", "Valid"},
//	{"14", "Confirmed", "Commit14", 113, "2024-06-01T12:00:00Z", 0.01, "Validator7", "0x0000014", "Valid"},
//	{"15", "Confirmed", "Commit15", 114, "2024-06-01T12:00:00Z", 0.01, "Validator7", "0x0000015", "Valid"},
//	{"16", "Confirmed", "Commit16", 115, "2024-06-01T12:00:00Z", 0.01, "Validator7", "0x0000016", "Inalid"},
//	{"17", "Confirmed", "Commit17", 116, "2024-06-01T12:00:00Z", 0.01, "Validator5", "0x0000017", "Inalid"},
//	{"18", "Confirmed", "Commit18", 117, "2024-06-01T12:00:00Z", 0.01, "Validator2", "0x0000018", "Inalid"},
//	{"19", "Confirmed", "Commit19", 118, "2024-06-01T12:00:00Z", 0.01, "Validator1", "0x0000019", "Inalid"},
//	{"20", "Confirmed", "Commit20", 119, "2024-06-01T12:00:00Z", 0.01, "Validator1", "0x0000020", "Inalid"},
//}

// Sample data for demonstration
var blobDetails = []BlobDetail{
	{"1", "Confirmed", "0x1234567890abcdef", 100, "2024-06-01T12:00:00Z", 0.01, "Validator1", 1024, "valid", struct {
		X string `json:"x"`
		Y string `json:"y"`
	}{
		X: "13258099556300711131786106409830610145994596628458885637226012245852998915913",
		Y: "11868554521347503492532980178914472193409060128712507356093850651849176305797",
	}, "0x1234567890abcdef", "https://example.com/image1.jpg"},
	{"2", "Pending", "0xabcdef1234567891", 101, "2024-06-02T12:00:00Z", 0.02, "Validator2", 2048, "valid", struct {
		X string `json:"x"`
		Y string `json:"y"`
	}{
		X: "0987654321098765432109876543210987654321098765432109876543210987654321",
		Y: "1234567890123456789012345678901234567890123456789012345678901234567890",
	}, "0xabcdef1234567890", "https://example.com/image2.jpg"},
	{"3", "Confirmed", "0x1234567891abcdef", 102, "2024-06-01T12:00:00Z", 0.01, "Validator1", 1024, "valid", struct {
		X string `json:"x"`
		Y string `json:"y"`
	}{
		X: "13258099556300711131786106409830610145994596628458885637226012245852998915913",
		Y: "11868554521347503492532980178914472193409060128712507356093850651849176305797",
	}, "0x1234567890abcdef", "https://example.com/image1.jpg"},
	{"4", "Pending", "0xabcdef1234567892", 103, "2024-06-02T12:00:00Z", 0.02, "Validator3", 2048, "valid", struct {
		X string `json:"x"`
		Y string `json:"y"`
	}{
		X: "0987654321098765432109876543210987654321098765432109876543210987654321",
		Y: "1234567890123456789012345678901234567890123456789012345678901234567890",
	}, "0xabcdef1234567890", "https://example.com/image2.jpg"},
	{"5", "Confirmed", "0x1234567892abcdef", 104, "2024-06-01T12:00:00Z", 0.01, "Validator2", 1024, "valid", struct {
		X string `json:"x"`
		Y string `json:"y"`
	}{
		X: "13258099556300711131786106409830610145994596628458885637226012245852998915913",
		Y: "11868554521347503492532980178914472193409060128712507356093850651849176305797",
	}, "0x1234567890abcdef", "https://example.com/image1.jpg"},
	{"6", "Pending", "0xabcdef1234567893", 105, "2024-06-02T12:00:00Z", 0.02, "Validator1", 2048, "valid", struct {
		X string `json:"x"`
		Y string `json:"y"`
	}{
		X: "0987654321098765432109876543210987654321098765432109876543210987654321",
		Y: "1234567890123456789012345678901234567890123456789012345678901234567890",
	}, "0xabcdef1234567890", "https://example.com/image2.jpg"},
	{"7", "Confirmed", "0x1234567893abcdef", 106, "2024-06-01T12:00:00Z", 0.01, "Validator1", 1024, "valid", struct {
		X string `json:"x"`
		Y string `json:"y"`
	}{
		X: "13258099556300711131786106409830610145994596628458885637226012245852998915913",
		Y: "11868554521347503492532980178914472193409060128712507356093850651849176305797",
	}, "0x1234567890abcdef", "https://example.com/image1.jpg"},
	{"8", "Pending", "0xabcdef1234567894", 107, "2024-06-02T12:00:00Z", 0.02, "Validator2", 2048, "valid", struct {
		X string `json:"x"`
		Y string `json:"y"`
	}{
		X: "0987654321098765432109876543210987654321098765432109876543210987654321",
		Y: "1234567890123456789012345678901234567890123456789012345678901234567890",
	}, "0xabcdef1234567890", "https://example.com/image2.jpg"},
}

var nodes = []NodeInfo{
	{"Node 1", "0xdjshfdcnvnk324fvf7v78vb89bu98vbv8b", "btc", "Broadcast"},
	{"Node 2", "0xdjshfdcnvnk324fvf7v78vb89bu98vbv8b", "btc", "Storage"},
	{"Node 3", "0xdjshfdcnvnk324fvf7v78vb89bu98vbv11", "eth", "Storage"},
	{"Node 4", "0x123sdsfdcnvnk324fvf7v78v89buvbv812", "eth", "Broadcast"},
}

var validators = []Validator{
	{"Validator1", "0x1234567890abcdef1234567890abcdef", "Active", 1000, 800, 0.1, 50},
	{"Validator2", "0xabcdef1234567890abcdef1234567890", "Inactive", 500, 300, 0.2, 20},
}

// HomeDataHandler handles the GET /api/home-data endpoint
func HomeDataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		var gormdb *gorm.DB
		var das []db.DA
		gormdb = stateSqlDB.Find(&das)
		if gormdb.Error != nil {
			log.Error("can not find DA", "err", gormdb.Error)
		}

		btcBlobs := make([]Blob, 0)
		ethBlobs := make([]Blob, 0)
		for _, da := range das {
			blob := Blob{
				Sender:          da.Sender,
				Index:           da.Index,
				Length:          da.Length,
				TxHash:          da.TxHash,
				Commitment:      da.Commitment,
				CommitmentHash:  da.CommitmentHash,
				Data:            da.Data,
				DAsKey:          da.DAsKey,
				SignData:        da.SignData,
				ParentStateHash: da.ParentStateHash,
				StateHash:       da.StateHash,
				BlockNum:        da.BlockNum,
				ReceiveAt:       da.ReceiveAt,
			}
			btcBlobs = append(btcBlobs, blob)
			ethBlobs = append(ethBlobs, blob)
		}

		response := map[string]interface{}{
			"result": []ChainBlobs{
				{
					Chain: "btc",
					Blobs: btcBlobs,
				},
				{
					Chain: "eth",
					Blobs: ethBlobs,
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
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
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		err = json.Unmarshal(body, &newBlob)
		if err != nil {
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
			StateHash:       newBlob.StateHash,
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

// SearchHandler handles the GET /api/search endpoint with query parameters
func SearchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		query := r.URL.Query().Get("q")
		category := r.URL.Query().Get("category")

		if query == "" {
			http.Error(w, "Missing query or category parameter", http.StatusBadRequest)
			return
		}
		var gormdb *gorm.DB
		var das []db.DA
		var results []Blob

		switch category {
		case "Sender":
			gormdb = stateSqlDB.
				Where(db.DA{Sender: query}).
				Find(&das)

		case "TxHash":
			gormdb = stateSqlDB.
				Where(db.DA{TxHash: query}).
				Find(&das)
		case "Commitment":
			gormdb = stateSqlDB.
				Where(db.DA{Commitment: query}).
				Find(&das)
		case "BlockNum":
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

		for _, da := range das {
			blob := Blob{
				Sender:          da.Sender,
				Index:           da.Index,
				Length:          da.Length,
				TxHash:          da.TxHash,
				Commitment:      da.Commitment,
				CommitmentHash:  da.CommitmentHash,
				Data:            da.Data,
				DAsKey:          da.DAsKey,
				SignData:        da.SignData,
				ParentStateHash: da.ParentStateHash,
				StateHash:       da.StateHash,
				BlockNum:        da.BlockNum,
				ReceiveAt:       da.ReceiveAt,
			}
			results = append(results, blob)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(results)
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

// BtcBlobsHandler handles the GET /api/btc-blobs endpoint with pagination and filtering
//func BtcBlobsHandler(w http.ResponseWriter, r *http.Request) {
//	if r.Method == http.MethodGet {
//		chain := r.URL.Query().Get("chain")
//		if chain != "btc" {
//			http.Error(w, "Invalid or missing chain parameter", http.StatusBadRequest)
//			return
//		}
//
//		pageStr := r.URL.Query().Get("page")
//		page, err := strconv.Atoi(pageStr)
//		if err != nil || page < 1 {
//			http.Error(w, "Invalid page parameter", http.StatusBadRequest)
//			return
//		}
//
//		if chain == "" || pageStr == "" {
//			http.Error(w, "Missing chain or pageStr parameter", http.StatusBadRequest)
//			return
//		}
//
//		filter := r.URL.Query().Get("filter")
//
//		// Filter blobs based on the provided filter parameter
//		var filteredBlobs []Blob
//		for _, blob := range blobs {
//			if filter == "" || strings.Contains(blob.BlobID, filter) || strings.Contains(blob.Commitment, filter) ||
//				strings.Contains(blob.Status, filter) || strings.Contains(blob.Validator, filter) ||
//				strings.Contains(blob.TxHash, filter) {
//				filteredBlobs = append(filteredBlobs, blob)
//			}
//		}
//
//		// Pagination
//		const perPage = 10
//		total := len(filteredBlobs)
//		start := (page - 1) * perPage
//		end := start + perPage
//		if start > total {
//			start = total
//		}
//		if end > total {
//			end = total
//		}
//		paginatedBlobs := filteredBlobs[start:end]
//
//		// Response
//		response := struct {
//			Data       []Blob `json:"data"`
//			Pagination struct {
//				Total   int `json:"total"`
//				Page    int `json:"page"`
//				PerPage int `json:"perPage"`
//			} `json:"pagination"`
//		}{
//			Data: paginatedBlobs,
//			Pagination: struct {
//				Total   int `json:"total"`
//				Page    int `json:"page"`
//				PerPage int `json:"perPage"`
//			}{
//				Total:   total,
//				Page:    page,
//				PerPage: perPage,
//			},
//		}
//
//		w.Header().Set("Content-Type", "application/json")
//		w.WriteHeader(http.StatusOK)
//		json.NewEncoder(w).Encode(response)
//	} else {
//		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
//	}
//}

// BtcBlobsHandler handles the GET /api/btc-blobs endpoint with pagination and filtering
//func EthBlobsHandler(w http.ResponseWriter, r *http.Request) {
//	if r.Method == http.MethodGet {
//		chain := r.URL.Query().Get("chain")
//		if chain != "eth" {
//			http.Error(w, "Invalid or missing chain parameter", http.StatusBadRequest)
//			return
//		}
//
//		pageStr := r.URL.Query().Get("page")
//		page, err := strconv.Atoi(pageStr)
//		if err != nil || page < 1 {
//			http.Error(w, "Invalid page parameter", http.StatusBadRequest)
//			return
//		}
//
//		if chain == "" || pageStr == "" {
//			http.Error(w, "Missing chain or pageStr parameter", http.StatusBadRequest)
//			return
//		}
//
//		filter := r.URL.Query().Get("filter")
//
//		// Filter blobs based on the provided filter parameter
//		var filteredBlobs []Blob
//		for _, blob := range blobs {
//			if filter == "" || strings.Contains(blob.BlobID, filter) || strings.Contains(blob.Commitment, filter) ||
//				strings.Contains(blob.Status, filter) || strings.Contains(blob.Validator, filter) ||
//				strings.Contains(blob.TxHash, filter) {
//				filteredBlobs = append(filteredBlobs, blob)
//			}
//		}
//
//		// Pagination
//		const perPage = 10
//		total := len(filteredBlobs)
//		start := (page - 1) * perPage
//		end := start + perPage
//		if start > total {
//			start = total
//		}
//		if end > total {
//			end = total
//		}
//		paginatedBlobs := filteredBlobs[start:end]
//
//		// Response
//		response := struct {
//			Data       []Blob `json:"data"`
//			Pagination struct {
//				Total   int `json:"total"`
//				Page    int `json:"page"`
//				PerPage int `json:"perPage"`
//			} `json:"pagination"`
//		}{
//			Data: paginatedBlobs,
//			Pagination: struct {
//				Total   int `json:"total"`
//				Page    int `json:"page"`
//				PerPage int `json:"perPage"`
//			}{
//				Total:   total,
//				Page:    page,
//				PerPage: perPage,
//			},
//		}
//
//		w.Header().Set("Content-Type", "application/json")
//		w.WriteHeader(http.StatusOK)
//		json.NewEncoder(w).Encode(response)
//	} else {
//		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
//	}
//}

func BlobDetailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		blobID := r.URL.Query().Get("blobID")
		chain := r.URL.Query().Get("chain")
		fmt.Println(fmt.Sprintf("*********** %v %v", blobID, chain))

		if chain != "btc" && chain != "eth" {
			fmt.Println("parameter error")
			http.Error(w, "Invalid chain parameter", http.StatusBadRequest)
			return
		}

		var foundBlob *BlobDetail
		for _, blob := range blobDetails {
			if blob.BlobID == blobID {
				foundBlob = &blob
				break
			}
		}

		if foundBlob == nil {
			http.Error(w, "Blob not found", http.StatusNotFound)
			return
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

		var filteredNodes []NodeInfo
		if chain == "" {
			filteredNodes = nodes
		} else {
			for _, node := range nodes {
				if node.Chain == chain {
					filteredNodes = append(filteredNodes, node)
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

// GetValidatorHandler handles the GET /api/getValidator endpoint
func GetValidatorHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if len(validators) == 0 {
			http.Error(w, "No validators found", http.StatusNotFound)
			return
		}
		validator := validators // Assuming a single validator for simplicity
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(validator)
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
	router.HandleFunc("/api/search", SearchHandler).Methods("GET")
	//router.HandleFunc("/api/btc-blobs", BtcBlobsHandler)
	//router.HandleFunc("/api/eth-blobs", EthBlobsHandler)
	router.HandleFunc("/api/blob-detail", BlobDetailHandler)
	router.HandleFunc("/api/nodes", NodesHandler)
	router.HandleFunc("/api/getValidator", GetValidatorHandler)

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
