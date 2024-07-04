/**
 * Copyright 2024.1.11
 * @Author: EchoWu
 * @Description: This file is part of the DOMICON library.
 */
package types

import (
	"crypto/ecdsa"
	"encoding/binary"
	"github.com/ethereum/go-ethereum/log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

//var ErrInvalidChainId = errors.New("invalid chain id for signer")

// sigFdCache is used to cache the derived sender and contains
// the signer used to derive it.
// type sigFdCache struct {
// 	signer DASigner
// 	from   common.Address
// }

// MakeDASigner returns a Signer based on the given chain config and block number.
func MakeDASigner(config *params.ChainConfig, blockNumber *big.Int, blockTime uint64) DASigner {
	var signer DASigner
	switch {
	case config.IsEIP155(blockNumber):
		signer = NewEIP155DASigner(config.ChainID)
	case config.IsHomestead(blockNumber):
		signer = HomesteadDASigner{}
	default:
		signer = FrontierDASigner{}
	}
	return signer
}

// LatestDASigner returns the 'most permissive' Signer available for the given chain
// configuration. Specifically, this enables support of all types of DA
// when their respective forks are scheduled to occur at any block number (or time)
// in the chain config.
//
// Use this in fileData-handling code where the current block number is unknown. If you
// have the current block number available, use MakeSigner instead.
func LatestDASigner(config *params.ChainConfig) DASigner {
	if config.ChainID != nil {
		// if config.CancunTime != nil {
		// 	return NewCancunDASigner(config.ChainID)
		// }
		// if config.LondonBlock != nil {
		// 	return NewLondonDASigner(config.ChainID)
		// }
		// if config.BerlinBlock != nil {
		// 	return NewEIP2930DASigner(config.ChainID)
		// }
		if config.EIP155Block != nil {
			return NewEIP155DASigner(config.ChainID)
		}
	}
	return HomesteadDASigner{}
}


// LatestDASignerForChainID returns the 'most permissive' Signer available. Specifically,
// this enables support for EIP-155 replay protection and all implemented EIP-2718
// fileData types if chainID is non-nil.
//
// Use this in fileData-handling code where the current block number and fork
// configuration are unknown. If you have a ChainConfig, use LatestSigner instead.
// If you have a ChainConfig and know the current block number, use MakeSigner instead.
func LatestDASignerForChainID(chainID *big.Int) DASigner {
	if chainID == nil {
		return HomesteadDASigner{}
	}
	return NewEIP155DASigner(chainID)
}

// SignFd signs the fileData using the given signer and private key.
func SignFd(fd *DA, s DASigner, prv *ecdsa.PrivateKey) (*DA, error) {
	h := s.Hash(fd)
	sig, err := crypto.Sign(h[:], prv)
	if err != nil {
		return nil, err
	}
	return fd.WithSignature(s,sig)
}

// FdSender returns the address derived from the signature (V, R, S) using secp256k1
// elliptic curve and an error if it failed deriving or upon an incorrect
// signature.
//
func FdSender(signer DASigner, fd *DA) ([]common.Address, []error) {
	addr,err := signer.Sender(fd)
	return addr, err
}

// DASigner encapsulates fileData signature handling. The name of this type is slightly
// misleading because Signers don't actually sign, they're just for validating and
// processing of signatures.
//
// Note that this interface is not a stable API and may change at any time to accommodate
// new protocol rules.
type DASigner interface {
	// Sender returns the sender address of the fileData.
	Sender(fd *DA) ([]common.Address, []error)

	// SignatureValues returns the raw R, S, V values corresponding to the
	// given signature.
	SignatureValues(fd *DA, sig []byte) (r, s, v *big.Int, err error)
	
	ChainID() *big.Int

	// Hash returns 'signature hash', i.e. the fileData hash that is signed by the
	// private key. This hash does not uniquely identify the fileData.
	Hash(fd *DA) common.Hash
	
	// Equal returns true if the given signer is the same as the receiver.
	Equal(DASigner) bool
}

// EIP155Signer implements Signer using the EIP-155 rules. This accepts transactions which
// are replay-protected as well as unprotected homestead transactions.
type EIP155DASigner struct {
	chainId, chainIdMul *big.Int
}

func NewEIP155DASigner(chainId *big.Int) EIP155DASigner {
	if chainId == nil {
		chainId = new(big.Int)
	}
	return EIP155DASigner{
		chainId:    chainId,
		chainIdMul: new(big.Int).Mul(chainId, big.NewInt(2)),
	}
}

func (s EIP155DASigner) ChainID() *big.Int {
	return s.chainId
}

func (s EIP155DASigner) Equal(s2 DASigner) bool {
	eip155, ok := s2.(EIP155DASigner)
	return ok && eip155.chainId.Cmp(s.chainId) == 0
}

func (s EIP155DASigner) Sender(fd *DA) ([]common.Address, []error) {
	recoverAddr := make([]common.Address,len(fd.SignData))
	errors := make([]error,len(fd.SignData))
	for i,signData := range fd.SignData{
		R, S, V := sliteSignature(signData)
		addr,err := recoverPlain(s.Hash(fd), R, S, V, true)
		errors[i] = err
		if err != nil {
			log.Info("Sender-----","err",err.Error())
		}
		recoverAddr[i] = addr
	}
	return recoverAddr,errors
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (s EIP155DASigner) SignatureValues(fd *DA, sig []byte) (R, S, V *big.Int, err error) {
	R, S, V = decodeSignature(sig)
	// if s.chainId.Sign() != 0 {
	// 	V = big.NewInt(int64(sig[64] + 35))
	// 	V.Add(V, s.chainIdMul)
	// }
	return R, S, V, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (s EIP155DASigner) Hash(fd *DA) common.Hash {
	data := make([]byte,0)
	chainId := transTo32Byte(uint64ToBigEndianHexBytes(s.chainId.Uint64()))
	indexByte := transTo32Byte(uint64ToBigEndianHexBytes(fd.Index))
	lengthByte := transTo32Byte(uint64ToBigEndianHexBytes(fd.Length))
	receiveByte := transTo32Byte(uint64ToBigEndianHexBytes(uint64(fd.OutOfTime.Unix())))
	addrByte := transTo32Byte(fd.Sender.Bytes())
	commitXByte := fd.Commitment.X.Bytes()
	commitYByte := fd.Commitment.Y.Bytes()
	data = append(data,chainId[:]...)
	data = append(data,addrByte[:]...)
	data = append(data,indexByte[:]...)
	data = append(data,lengthByte[:]...)
	data = append(data,receiveByte[:]...)
	data = append(data,commitXByte[:]...)
	data = append(data,commitYByte[:]...)
	return crypto.Keccak256Hash(data)
}

func transTo32Byte(data []byte) [32]byte {
	var byteData [32]byte
	byteDataLength := len(byteData)
	dataLength := len(data)
	for i,b := range data {
		byteData[byteDataLength-dataLength+i] = b
	}
	return byteData
}

// HomesteadDASigner implements Signer interface using the
// homestead rules.
type HomesteadDASigner struct{ FrontierDASigner }

func (s HomesteadDASigner) ChainID() *big.Int {
	return nil
}

func (s HomesteadDASigner) Equal(s2 DASigner) bool {
	_, ok := s2.(HomesteadDASigner)
	return ok
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (hs HomesteadDASigner) SignatureValues(fd *DA, sig []byte) (r, s, v *big.Int, err error) {
	return hs.FrontierDASigner.SignatureValues(fd, sig)
}

func (hs HomesteadDASigner) Sender(fd *DA) ([]common.Address, []error) {
	recoverAddr := make([]common.Address,len(fd.SignData))
	errors := make([]error,len(fd.SignData))
	for i,_ := range fd.SignData{
		r, s ,v := fd.RawSignatureValues(uint64(i))
		v.Sub(v,new(big.Int).SetUint64(27))
		addr,err := recoverPlain(hs.Hash(fd), r, s, v, true)
		errors[i] = err
		recoverAddr[i] = addr
	}
	return recoverAddr,errors
}


// FrontierDASigner implements Signer interface using the
// frontier rules.
type FrontierDASigner struct{}

func (s FrontierDASigner) ChainID() *big.Int {
	return nil
}

func (s FrontierDASigner) Equal(s2 DASigner) bool {
	_, ok := s2.(FrontierDASigner)
	return ok
}

func (fs FrontierDASigner) Sender(fd *DA) ([]common.Address, []error) {
	recoverAddr := make([]common.Address,len(fd.SignData))
	errors := make([]error,len(fd.SignData))
	for i,signData := range fd.SignData{
		r, s, v := sliteSignature(signData)
		v = v.Mul(v,new(big.Int).SetUint64(27))
		addr,err := recoverPlain(fs.Hash(fd), r, s, v, false)
		errors[i] = err
		recoverAddr[i] = addr
	}
	return recoverAddr,errors
}

// SignatureValues returns signature values. This signature
// needs to be in the [R || S || V] format where V is 0 or 1.
func (fs FrontierDASigner) SignatureValues(fd *DA, sig []byte) (r, s, v *big.Int, err error) {
	r, s, v = decodeSignature(sig)
	return r, s, v, nil
}

// Hash returns the hash to be signed by the sender.
// It does not uniquely identify the transaction.
func (fs FrontierDASigner) Hash(fd *DA) common.Hash {
	data := make([]byte,0)
	indexByte := transTo32Byte(uint64ToBigEndianHexBytes(fd.Index))
	lengthByte := transTo32Byte(uint64ToBigEndianHexBytes(fd.Length))
	addrByte := transTo32Byte(fd.Sender.Bytes())
	commitXByte := fd.Commitment.X.Bytes()
	commitYByte := fd.Commitment.Y.Bytes()
	data = append(data,addrByte[:]...)
	data = append(data,indexByte[:]...)
	data = append(data,lengthByte[:]...)
	data = append(data,commitXByte[:]...)
	data = append(data,commitYByte[:]...)
	return crypto.Keccak256Hash(data)
}

func sliteSignature(sig []byte) (r,s,v *big.Int) {
	r = new(big.Int).SetBytes(sig[:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes(sig[64:])
	return r,s,v
 }

 func uint64ToBigEndianHexBytes(value uint64) []byte {
	// 创建一个长度为 8 的字节切片
	byteData := make([]byte, 8)
	// 使用 binary.BigEndian.PutUint64 将 uint64 转换为大端字节序
	binary.BigEndian.PutUint64(byteData, value)
	return byteData
}