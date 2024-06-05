package model

//const TableNameBaseFile = "t_base_file"
//
//// BaseFile mapped from table <t_base_file>
//type BaseFile struct {
//	ID               int32  `gorm:"column:f_id;primaryKey;autoIncrement:true" json:"id"`
//	ChainMagicNumber string `gorm:"column:f_chain_magic_number;not null;comment:链魔数" json:"chain_magic_number"` // 链魔数
//	SourceHash       string `gorm:"column:f_source_hash;not null;comment:数据源哈希" json:"source_hash"`             // 数据源哈希
//	Sender           string `gorm:"column:f_sender;not null;comment:" json:"sender"`                            //
//	Submitter        string `gorm:"column:f_submitter;not null;comment:" json:"submitter"`                      //
//	Length           uint64 `gorm:"column:f_length;not null;default:0;comment:" json:"length"`                  //
//	Index            uint64 `gorm:"column:f_index;not null;default:0;comment:" json:"index"`                    //
//	Commitment       string `gorm:"column:f_commitment;not null" json:"commitment"`
//	Data             string `gorm:"column:f_data;not null" json:"data"`
//	Sign             string `gorm:"column:f_sign;not null" json:"sign"`
//	TransactionHash  string `gorm:"column:f_transaction_hash;not null;comment:交易hash" json:"transaction_hash"` // 交易hash
//	CreateAt         int64  `gorm:"column:f_create_at;not null;comment:创建时间" json:"create_at"`                 // 创建时间
//}
//
//// TableName BaseFile's table name
//func (*BaseFile) TableName() string {
//	return TableNameBaseFile
//}
