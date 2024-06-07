package basemodel

const TableNameBaseFile = "t_base_file"

// BaseFile mapped from table <t_base_file>
type BaseFile struct {
	ID              int32  `gorm:"column:f_id;primaryKey;autoIncrement:true" json:"id"`
	Net             string `gorm:"column:f_net;not null;comment:链网络" json:"net"`                                  // 链网络
	MagicNumber     string `gorm:"column:f_magic_number;not null;comment:链魔数" json:"magic_number"`                // 链魔数
	BlockHeight     int64  `gorm:"column:f_block_height;not null;comment:区块高度" json:"block_height"`               // 区块高度
	BlockHash       string `gorm:"column:f_block_hash;not null;comment:区块哈希" json:"block_hash"`                   // 区块哈希
	TransactionHash string `gorm:"column:f_transaction_hash;not null;comment:交易哈希" json:"transaction_hash"`       // 交易哈希
	ContentType     string `gorm:"column:f_content_type;not null;comment:内容类型" json:"content_type"`               // 内容类型
	ContentLength   uint64 `gorm:"column:f_content_length;not null;default:0;comment:内容长度" json:"content_length"` //内容长度
	ContentBody     string `gorm:"column:f_content_body;not null;comment:内容体" json:"content_body"`                //内容体
	Index           uint32 `gorm:"column:f_index;not null;default:0;comment:序号" json:"index"`                     //序号
	Offset          uint64 `gorm:"column:f_offset;not null;default:0;comment:偏移量" json:"offset"`                  //偏移量
	Data            string `gorm:"column:f_data;not null" json:"data"`
	CreateAt        int64  `gorm:"column:f_create_at;not null;comment:创建时间" json:"create_at"` // 创建时间
}

// TableName BaseFile's table name
func (*BaseFile) TableName() string {
	return TableNameBaseFile
}
