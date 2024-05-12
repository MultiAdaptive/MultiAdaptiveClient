package db

/*
tx_hash             VARCHAR NOT NULL PRIMARY KEY REFERENCES transaction (hash) ON DELETE CASCADE,
                  type                integer,
			post_state          BYTEA,
                  status              BIGINT,
                  cumulative_gas_used BIGINT,
                  gas_used            BIGINT,
                  block_num           BIGINT  NOT NULL REFERENCES block (block_num) ON DELETE CASCADE,
                  tx_index            integer,
                  contract_address    VARCHAR
*/

//type Receipt struct {
//	TxHash            common.Hash
//	Type              uint8  `json:"type,omitempty"`
//	PostState         []byte `json:"root"`
//	Status            uint64 `json:"status"`
//	CumulativeGasUsed uint64     `json:"cumulativeGasUsed" gencodec:"required"`
//	GasUsed           uint64     `json:"gasUsed" gencodec:"required"`
//	BlockNumber      *big.Int     `json:"blockNumber,omitempty"`
//	TransactionIndex uint        `json:"transactionIndex"`
//	ContractAddress   common.Address `json:"contractAddress"`
//}

