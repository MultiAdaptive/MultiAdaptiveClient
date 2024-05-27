package eth

import (

	"bytes"
	"context"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	kzgSdk "github.com/domicon-labs/kzg-sdk"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

const (
	port       = "8545"
	privateKey = "2ffb28910709e79b8bf06d22c8289fd24f86853a9f9832cd0707acc0fe554610"
)
const dSrsSize = 1 << 16

func TestEthAPIBackend_SendDAByParams(t *testing.T) {
	currentPath, _ := os.Getwd()
	parentPath := filepath.Dir(currentPath)
	println("parentPath----",parentPath)
	path := parentPath + "/srs"
	domiconSDK,err := kzgSdk.InitDomiconSdk(dSrsSize,path)
	if err != nil {
		println("kzg init domicon sdk err",err.Error())
	}


	client,err := ethclient.DialContext(context.TODO(),"http://43.203.215.230:"+port)
	if err != nil {
		println("err---dial---",err.Error())
	}
	index := 0
	length := 1024
	s := strconv.Itoa(index)
	data := bytes.Repeat([]byte(s), 1024)

	digst,err := domiconSDK.GenerateDataCommit(data)
	if err != nil {
		println("GenerateDataCommit ---ERR",err.Error())
	}
	digstData := digst.Marshal()

	daskey := common.Hex2Bytes("0xbd5064c5be5c91b2c22c616f33d66f6c0f83b93e8c4748d8dfaf37cb9f00d622")
	priv, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		println("HexToECDSA---err",err.Error())
	}
	sender := crypto.PubkeyToAddress(priv.PublicKey)
	var byteArray [32]byte
	copy(byteArray[:], daskey)
	res,err := client.SendDAByParams(context.Background(),sender,uint64(index),uint64(length),digstData,data,byteArray)
	if err != nil {
		println("err",err.Error())
	}
	sigHex := common.Bytes2Hex(res)
	println("sigHex------",sigHex)
}