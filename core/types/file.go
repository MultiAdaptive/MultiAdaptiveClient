package types

import (
	"errors"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"math/big"
	"time"
)

type NameSpace struct {
	ID          uint64
	Creater     common.Address
	StorageList []common.Address
}

// DA struct
// sender       address
// index        uint64
// commitment   证据
// data         file
// sign         签名
// receiveAt    收到的时间
// order

type DA struct {
	Sender       common.Address `json:"Sender"` //文件发送者
	Nonce        uint64         `json:"Nonce"`  //
	Index        uint64         `json:"Index"`  //文件发送者类nonce 相同的index认为是重复交易
	Length       uint64         `json:"Length"` //长度
	Data         []byte         `json:"Data"`   //上传的的文件
	Commitment   kzg.Digest     `json:"Commitment"`
	SignData     [][]byte       `json:"SignData"`
	SignerAddr   []string       `json:"SignerAddr"`
	DasKey       [32]byte       `json:"DasKey"`
	TxHash       common.Hash    `json:"TxHash"`
	BlockNum     uint64         `json:"BlockNum"`
	ReceiveAt    time.Time      `json:"ReceiveAt"`
	Proof        []byte         `json:"Proof"`
	ClaimedValue []byte         `json:"ClaimedValue"`
	NameSpaceID  *big.Int       `json:"NameSpaceID"`
	Root         common.Hash    `json:"Root"`
}

func NewDA(sender common.Address, index, length uint64, commitment kzg.Digest, data []byte, dasKey [32]byte, proof []byte, claimedValue []byte) *DA {
	return &DA{
		Sender:       sender,
		Index:        index,
		Length:       length,
		Commitment:   commitment,
		Data:         data,
		DasKey:       dasKey,
		Proof:        proof,
		ClaimedValue: claimedValue,
	}
}

func (f *DA) Encode() ([]byte, error) {
	data, err := rlp.EncodeToBytes(f)
	return data, err
}

func (f *DA) Decode(data []byte) error {
	return rlp.DecodeBytes(data, f)
}

func (f *DA) Size() uint64 {
	data, _ := rlp.EncodeToBytes(f)
	return uint64(len(data))
}

func (f *DA) WithSignature(signer FdSigner, sign []byte) (*DA, error) {
	if len(sign) == 0 {
		return nil, errors.New("sign is empty")
	}
	r, s, v, err := signer.SignatureValues(f, sign)
	if err != nil {
		return nil, err
	}
	newSign := make([]byte, 0)
	newSign = append(newSign, r.Bytes()...)
	newSign = append(newSign, s.Bytes()...)
	newSign = append(newSign, v.Bytes()...)
	f.SignData = [][]byte{newSign}
	return f, nil
}

func (f *DA) RawSignatureValues(index uint64) (r, s, v *big.Int) {
	sign := f.SignData[index]
	return decodeSignature(sign)
}

type DAs []*DA

func (f DAs) Len() int { return len(f) }
