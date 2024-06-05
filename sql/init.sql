create table t_base_chain
(
    f_id                 INTEGER                 not null PRIMARY KEY AUTOINCREMENT,
    f_chain_name         varchar(127) default '' not null,
    f_chain_magic_number varchar(127) default '' not null,
    f_current_height     bigint       default 0  not null,
    f_create_at          bigint unsigned    default 0 not null,
    constraint udx_chain_magic_number
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
    constraint udx_chain_magic_number_block_hash
        unique (f_chain_magic_number, f_block_hash),
    constraint udx_chain_magic_number_block_height
        unique (f_chain_magic_number, f_block_height)
);

CREATE INDEX idx_block_time ON t_base_block (f_block_time);


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
    constraint udx_chain_magic_number_transaction_hash
        unique (f_chain_magic_number, f_transaction_hash),
    index                idx_hex (f_hex),
    index                idx_txid (f_txid),
    index                idx_block_hash (f_block_hash),
    index                idx_transaction_time (f_transaction_time),
    index                idx_block_time (f_block_time)
);


CREATE TABLE t_base_file
(
    f_id                 INTEGER      not null PRIMARY KEY AUTOINCREMENT,
    f_chain_magic_number varchar(127)          default '' not null,
    f_source_hash        varchar(127) not null,
    f_sender             varchar(63)  not null,
    f_submitter          varchar(63)  not null,
    f_length             bigint       not null default 0,
    f_index              bigint       not null default 0,
    f_commitment         text,
    f_data               longtext,
    f_sign               text,
    f_transaction_hash   varchar(127)          default '' not null,
    f_create_at          bigint unsigned    default 0 not null,
    constraint udx_chain_magic_number_source_hash
        unique (f_chain_magic_number, f_source_hash),
    index                idx_transaction_hash (f_transaction_hash)
);
