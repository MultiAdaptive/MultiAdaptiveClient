package types

import (
	"crypto/ecdsa"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	kzgSdk "github.com/multiAdaptive/kzg-sdk"
	"os"
	"strings"
)

const dSrsSize = 1 << 16

type SingerTool struct {
	config *params.ChainConfig
	prv    *ecdsa.PrivateKey
}

func NewSingerTool(conf *params.ChainConfig, prv *ecdsa.PrivateKey) *SingerTool {
	return &SingerTool{
		config: conf,
		prv:    prv,
	}
}

func (s *SingerTool) Sign(da *DA) ([]byte, error) {
	singer := NewEIP155FdSigner(s.config.ChainID)
	h := singer.Hash(da)
	sign, err := crypto.Sign(h.Bytes(), s.prv)
	v := []byte{sign[64] + 27}
	newSig := sign[:64]
	newSig = append(newSig, v...)
	return newSig, err
}

func (s *SingerTool) Sender(da *DA) ([]common.Address, []error) {
	singer := NewEIP155FdSigner(s.config.ChainID)
	addr, err := singer.Sender(da)
	return addr, err
}

func (s *SingerTool) VerifyEth(da *DA) (bool, error) {
	if da.Length != uint64(len(da.Data)) {
		return false, errors.New("da data length is not match")
	}
	currentPath, _ := os.Getwd()
	path := strings.Split(currentPath, "/build")[0] + "/srs"
	domiconSDK, err := kzgSdk.InitMultiAdaptiveSdk(path)
	if err != nil {
		return false, err
	}
	commit := da.Commitment.Marshal()
	flag, err := domiconSDK.VerifyCommitWithProof(commit, da.Proof, da.ClaimedValue)
	if err != nil {
		return false, err
	}
	return flag, nil
}

func (s *SingerTool) VerifyBtc(da *DA) (bool, error) {
	currentPath, _ := os.Getwd()

	path := strings.Split(currentPath, "/build")[0] + "/srs"
	domiconSDK, err := kzgSdk.InitMultiAdaptiveSdk(path)
	if err != nil {
		return false, err
	}
	commit := da.Commitment.Marshal()
	flag, err := domiconSDK.VerifyCommitWithProof(commit, da.Proof, da.ClaimedValue)
	if err != nil {
		return false, err
	}
	return flag, nil
}
