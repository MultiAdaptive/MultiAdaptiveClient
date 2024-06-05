
create table t_base_chain
(
    f_id             INTEGER not null PRIMARY KEY AUTOINCREMENT,
    f_chain_name     varchar(512)                default '' not null,
    f_chain_magic_number       varchar(512) default '' not null,
    f_current_height bigint  default 0 not null,
    f_create_at      bigint unsigned    default 0 not null,
    constraint udx_chain_magic_number
        unique (f_chain_magic_number)
);

-- create table t_base_block
-- (
--     f_id               bigint unsigned auto_increment comment '主键',
--     f_chain_magic_number         varchar(127)    default '' not null comment '链编号',
--     f_block_height     bigint  default 0 not null comment '区块高度',
--     f_block_hash       varchar(127)    default ''  not null comment '区块哈希',
--     f_confirmations  bigint  default 0 not null comment '确认区块数',
--     f_stripped_size  int  default 0 not null comment '去除了见证数据后的区块大小',
--     f_size  int  default 0 not null comment '区块的总大小',
--     f_weight int  default 0 not null comment '区块的权重',
--     f_merkle_root  varchar(127)    default ''  not null comment '默克尔树根',
--     f_transaction_cnt  int unsigned    default 0 not null comment '交易数量',
--     f_block_time  bigint  default 0 not null comment '区块被开采的时间',
--     f_nonce int unsigned    default 0 comment '随机数',
--     f_bits  varchar(127)    default ''  not null comment '目标难度',
--     f_difficulty float default 0 comment '目标难度',
--     f_previous_block_hash      varchar(127)    default ''  not null comment '前一个区块哈希',
--     f_next_block_hash      varchar(127)    default ''  not null comment '后一个区块哈希',
--     f_create_at        bigint unsigned    default 0 comment '创建时间',
--     PRIMARY KEY (f_id),
--     constraint udx_chain_magic_number_block_hash
--         unique (f_chain_magic_number, f_block_hash),
--     constraint udx_chain_magic_number_block_height
--         unique (f_chain_magic_number, f_block_height),
--     index idx_block_time (f_block_time)
-- )
--     ENGINE = InnoDB
--     DEFAULT CHARSET = UTF8MB4 comment '区块信息';
--
--
-- create table t_base_transaction
-- (
--     f_id                 bigint unsigned auto_increment comment '主键',
--     f_chain_magic_number         varchar(127)    default '' not null comment '链编号',
--     f_hex varchar(127)         default ''  not null comment '交易',
--     f_txid varchar(127)         default ''  not null comment '交易编号',
--     f_transaction_hash   varchar(127)         default ''  not null comment '交易哈希',
--     f_size  int  default 0 not null comment '交易大小',
--     f_vsize int  default 0 not null comment '交易虚拟大小',
--     f_weight int  default 0 not null comment '交易权重',
--     f_locktime int unsigned      default 0 not null comment '交易锁定时间',
--     f_vin blob comment '交易输入',
--     f_vout blob comment '交易输出',
--     f_block_hash         varchar(127)         default ''  not null comment '区块哈希',
--     f_confirmations  bigint  default 0 not null comment '确认区块数',
--     f_transaction_time    bigint unsigned      default 0 not null comment '交易时间',
--     f_block_time    bigint unsigned      default 0 not null comment '区块时间',
--     f_create_at          bigint unsigned    default 0 comment '创建时间',
--     PRIMARY KEY (f_id),
--     constraint udx_chain_magic_number_transaction_hash
--         unique (f_chain_magic_number, f_transaction_hash),
--     index idx_hex (f_hex),
--     index idx_txid (f_txid),
--     index idx_block_hash (f_block_hash),
--     index idx_transaction_time (f_transaction_time),
--     index idx_block_time (f_block_time)
-- )
--     ENGINE = InnoDB
--     DEFAULT CHARSET = UTF8MB4 comment '交易信息';
--
--
-- CREATE TABLE t_base_file
-- (
--     f_id               bigint unsigned auto_increment comment '主键',
--     f_chain_magic_number         bigint unsigned       default '0' not null comment '链ID',
--     f_source_hash      varchar(127) not null comment '数据源哈希',
--     f_sender           varchar(63)  not null COMMENT '',
--     f_submitter        varchar(63)  not null COMMENT '',
--     f_length           bigint       not null default 0 COMMENT '',
--     f_index            bigint       not null default 0 COMMENT '',
--     f_commitment       text COMMENT '',
--     f_data             longtext COMMENT '',
--     f_sign             text COMMENT '',
--     f_transaction_hash varchar(127)          default '' not null comment '交易哈希',
--     f_create_at        bigint unsigned    default 0 comment '创建时间',
--     PRIMARY KEY (f_id),
--     constraint udx_chain_magic_number_source_hash
--         unique (f_chain_magic_number, f_source_hash),
--     index idx_transaction_hash (f_transaction_hash)
-- )
--     ENGINE = InnoDB
--     DEFAULT CHARSET = UTF8MB4 COMMENT '文件信息';
