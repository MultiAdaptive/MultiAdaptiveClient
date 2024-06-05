package model

const TableNameBaseChain = "t_base_chain"

// BaseChain mapped from table <t_base_chain>
type BaseChain struct {
	ID               int32  `gorm:"column:f_id;primaryKey;autoIncrement:true;comment:ID" json:"id"`             // ID
	ChainName        string `gorm:"column:f_chain_name;not null;comment:链名称" json:"chain_name"`                 // 链名称
	ChainMagicNumber string `gorm:"column:f_chain_magic_number;not null;comment:链魔数" json:"chain_magic_number"` // 链魔数
	CurrentHeight    uint64 `gorm:"column:f_current_height;not null;comment:当前高度" json:"current_height"`        // 当前高度
	CreateAt         int64  `gorm:"column:f_create_at;not null;comment:创建时间" json:"create_at"`                  // 创建时间
}

// TableName BaseChain's table name
func (*BaseChain) TableName() string {
	return TableNameBaseChain
}
