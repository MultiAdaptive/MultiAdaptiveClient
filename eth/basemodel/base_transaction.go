package basemodel

const TableNameBaseTransaction = "t_base_transaction"

// BaseTransaction mapped from table <t_base_transaction>
type BaseTransaction struct {
	ID              int32   `gorm:"column:f_id;primaryKey;autoIncrement:true" json:"id"`
	Net             string  `gorm:"column:f_net;not null;comment:链网络" json:"net"`                            // 链网络
	MagicNumber     string  `gorm:"column:f_magic_number;not null;comment:链魔数" json:"magic_number"`          // 链魔数
	Hex             string  `gorm:"column:f_hex;not null;comment:交易" json:"hex"`                             //交易
	Txid            string  `gorm:"column:f_txid;not null;comment:交易编号" json:"txid"`                         //交易编号
	TransactionHash string  `gorm:"column:f_transaction_hash;not null;comment:交易哈希" json:"transaction_hash"` // 交易哈希
	Size            int32   `gorm:"column:f_size;not null;comment:交易大小" json:"size"`                         //交易大小
	Vsize           int32   `gorm:"column:f_vsize;not null;comment:交易虚拟大小" json:"vsize"`                     //交易虚拟大小
	Weight          int32   `gorm:"column:f_weight;not null;comment:交易权重" json:"weight"`                     //交易权重
	LockTime        uint32  `gorm:"column:f_locktime;not null;comment:交易锁定时间" json:"locktime"`               //交易锁定时间
	Vin             []byte  `gorm:"column:f_vin;not null;comment:交易输入" json:"vin"`                           //交易输入
	Vout            []byte  `gorm:"column:f_vout;not null;comment:交易输出" json:"vout"`                         //交易输出
	BlockHash       string  `gorm:"column:f_block_hash;not null;comment:区块哈希" json:"block_hash"`             //区块哈希
	Confirmations   uint64  `gorm:"column:f_confirmations;not null;comment:确认区块数" json:"confirmations"`      //确认区块数
	TransactionTime int64   `gorm:"column:f_transaction_time;not null;comment:交易时间" json:"transaction_time"` //交易时间
	BlockTime       int64   `gorm:"column:f_block_time;not null;comment:区块时间" json:"block_time"`             //区块时间
	Fee             float64 `gorm:"column:f_fee;not null;comment:交易费用" json:"fee"`                           //交易费用
	CreateAt        int64   `gorm:"column:f_create_at;not null;comment:创建时间" json:"create_at"`               // 创建时间
}

// TableName BaseTransaction's table name
func (*BaseTransaction) TableName() string {
	return TableNameBaseTransaction
}
