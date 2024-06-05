create table t_base_chain
(
    f_id                 INTEGER                 not null PRIMARY KEY AUTOINCREMENT,
    f_chain_name         varchar(127) default '' not null,
    f_chain_magic_number varchar(127) default '' not null,
    f_current_height     bigint       default 0  not null,
    f_create_at          bigint unsigned    default 0 not null,
    constraint udx_chain_chain_magic_number
        unique (f_chain_magic_number)
);

create table t_base_block
(
    f_id                  INTEGER                 not null PRIMARY KEY AUTOINCREMENT,
    f_chain_magic_number  varchar(127) default '' not null,
    f_block_height        bigint       default 0  not null,
    f_block_hash          varchar(127) default '' not null,
    f_confirmations       bigint       default 0  not null,
    f_stripped_size       int          default 0  not null,
    f_size                int          default 0  not null,
    f_weight              int          default 0  not null,
    f_merkle_root         varchar(127) default '' not null,
    f_transaction_cnt     int unsigned    default 0 not null,
    f_block_time          bigint       default 0  not null,
    f_nonce               int unsigned    default 0,
    f_bits                varchar(127) default '' not null,
    f_difficulty          float        default 0.0,
    f_previous_block_hash varchar(127) default '' not null,
    f_next_block_hash     varchar(127) default '' not null,
    f_create_at           bigint unsigned    default 0 not null,
    constraint udx_block_chain_magic_number_block_hash
        unique (f_chain_magic_number, f_block_hash),
    constraint udx_block_chain_magic_number_block_height
        unique (f_chain_magic_number, f_block_height)
);

CREATE INDEX idx_block_block_time ON t_base_block (f_block_time);


create table t_base_transaction
(
    f_id                 INTEGER                 not null PRIMARY KEY AUTOINCREMENT,
    f_chain_magic_number varchar(127) default '' not null,
    f_hex                varchar(127) default '' not null,
    f_txid               varchar(127) default '' not null,
    f_transaction_hash   varchar(127) default '' not null,
    f_size               int          default 0  not null,
    f_vsize              int          default 0  not null,
    f_weight             int          default 0  not null,
    f_locktime           int unsigned      default 0 not null,
    f_vin                blob,
    f_vout               blob,
    f_block_hash         varchar(127) default '' not null,
    f_confirmations      bigint       default 0  not null,
    f_transaction_time   bigint unsigned      default 0 not null,
    f_block_time         bigint unsigned      default 0 not null,
    f_create_at          bigint unsigned    default 0 not null,
    constraint udx_transaction_chain_magic_number_transaction_hash
        unique (f_chain_magic_number, f_transaction_hash)
);
CREATE INDEX idx_transaction_hex ON t_base_transaction (f_hex);
CREATE INDEX idx_transaction_txid ON t_base_transaction (f_txid);
CREATE INDEX idx_transaction_block_hash ON t_base_transaction (f_block_hash);
CREATE INDEX idx_transaction_transaction_time ON t_base_transaction (f_transaction_time);
CREATE INDEX idx_transaction_block_time ON t_base_transaction (f_block_time);


CREATE TABLE t_base_file
(
    f_id                 INTEGER      not null PRIMARY KEY AUTOINCREMENT,
    f_chain_magic_number varchar(127)          default '' not null,
    f_block_height        bigint       default 0  not null,
    f_block_hash          varchar(127) default '' not null,
    f_transaction_hash   varchar(127)          default '' not null,
    f_content_type        varchar(127) default '' not null,
    f_content_length             bigint   unsigned    not null default 0,
    f_content_body         text,
    f_index integer unsigned    not null default 0,
    f_offset bigint   unsigned    not null default 0,
    f_data               longtext,
    f_create_at          bigint unsigned    default 0 not null,
    constraint udx_file_chain_magic_number_block_hash_transaction_hash_index
        unique (f_chain_magic_number, f_block_hash,f_transaction_hash,f_index)
);
CREATE INDEX idx_file_transaction_hash ON t_base_file (f_transaction_hash);
