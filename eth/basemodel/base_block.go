package basemodel

const TableNameBaseBlock = "t_base_block"

// BaseBlock mapped from table <t_base_block>
type BaseBlock struct {
	ID               int32   `gorm:"column:f_id;primaryKey;autoIncrement:true" json:"id"`
	ChainMagicNumber string  `gorm:"column:f_chain_magic_number;not null;comment:链编号" json:"chain_magic_number"`       // 链编号
	BlockHeight      int64   `gorm:"column:f_block_height;not null;comment:区块高度" json:"block_height"`                  // 区块高度
	BlockHash        string  `gorm:"column:f_block_hash;not null;comment:区块哈希" json:"block_hash"`                      // 区块哈希
	Confirmations    int64   `gorm:"column:f_confirmations;not null;comment:确认区块数" json:"confirmations"`               //确认区块数
	StrippedSize     int32   `gorm:"column:f_stripped_size;not null;comment:去除了见证数据后的区块大小" json:"stripped_size"`       //去除了见证数据后的区块大小
	Size             int32   `gorm:"column:f_size;not null;comment:区块的总大小" json:"size"`                                //区块的总大小
	Weight           int32   `gorm:"column:f_weight;not null;comment:区块的权重" json:"weight"`                             //区块的权重
	MerkleRoot       string  `gorm:"column:f_merkle_root;not null;comment:默克尔树根" json:"merkle_root"`                   //默克尔树根
	TransactionCnt   uint32  `gorm:"column:f_transaction_cnt;not null;comment:交易数量" json:"transaction_cnt"`            // 交易数量
	BlockTime        int64   `gorm:"column:f_block_time;not null;comment:区块被开采的时间" json:"block_time"`                  // 区块被开采的时间
	Nonce            uint32  `gorm:"column:f_nonce;not null;comment:随机数" json:"nonce"`                                 //随机数
	Bits             string  `gorm:"column:f_bits;not null;comment:目标难度" json:"bits"`                                  //目标难度
	Difficulty       float64 `gorm:"column:f_difficulty;not null;comment:目标难度" json:"difficulty"`                      //目标难度
	PreviousHash     string  `gorm:"column:f_previous_block_hash;not null;comment:前一个区块哈希" json:"previous_block_hash"` // 前一个区块哈希
	NextHash         string  `gorm:"column:f_next_block_hash;not null;comment:后一个区块哈希" json:"next_block_hash"`         //后一个区块哈希
	CreateAt         int64   `gorm:"column:f_create_at;not null;comment:创建时间" json:"create_at"`                        // 创建时间
}

// TableName BaseBlock's table name
func (*BaseBlock) TableName() string {
	return TableNameBaseBlock
}
