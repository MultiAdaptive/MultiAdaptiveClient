package eth

import (
	"bytes"
	"context"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"strconv"
	"testing"
)

const (
	port       = "8545"
	privateKey = "2ffb28910709e79b8bf06d22c8289fd24f86853a9f9832cd0707acc0fe554610"
)

func TestEthAPIBackend_SendDAByParams(t *testing.T) {
	client,err := ethclient.DialContext(context.TODO(),"http://127.0.0.1:"+port)
	if err != nil {
		println("err---dial---",err.Error())
	}

	index := 2
	length := 1024
	commit := []byte("commit------1")
	s := strconv.Itoa(index)
	data := bytes.Repeat([]byte(s), 1024)
	daskey := common.Hex2Bytes("0xa54af72a7b9f92d8d3a7c2ad0a6b4f84275d1fef612ab3b1297fbf8a31815ba3")
	priv, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		println("HexToECDSA---err",err.Error())
	}
	sender := crypto.PubkeyToAddress(priv.PublicKey)
	var byteArray [32]byte
	copy(byteArray[:], daskey)
	res,err := client.SendDAByParams(context.Background(),sender,uint64(index),uint64(length),commit,data,byteArray)
	if err != nil {
		println("err",err.Error())
	}
	sigHex := common.Bytes2Hex(res)
	println("sigHex------",sigHex)
}