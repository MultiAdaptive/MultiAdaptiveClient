package eth

import (
	"bytes"
	"context"
	kzgSdk "github.com/domicon-labs/kzg-sdk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

const (
	port       = "8545"
	privateKey = "8ff8d133dfe084a96029b4054f1f258db8fff9559a6c031e0d3f0d5f3688cc8e"
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
	index := 8
	length := 1024
	s := strconv.Itoa(index)
	data := bytes.Repeat([]byte(s), 1024)

	digst,err := domiconSDK.GenerateDataCommit(data)
	if err != nil {
		println("GenerateDataCommit ---ERR",err.Error())
	}
	digstData := digst.Marshal()
	commitStr := common.Bytes2Hex(digstData)
	println("commitStr-----",commitStr)
	println("digst------",digst.String())
	daskey := common.Hex2Bytes("0xbd5064c5be5c91b2c22c616f33d66f6c0f83b93e8c4748d8dfaf37cb9f00d622")
	sender := common.HexToAddress("0x4F7A66eDEe01290F824545E483C7D69b8F1E88fb")
	var byteArray [32]byte
	copy(byteArray[:], daskey)
	res,err := client.SendDAByParams(context.Background(),sender,uint64(index),uint64(length),digstData,data,byteArray)
	if err != nil {
		println("err",err.Error())
	}
	sigHex := common.Bytes2Hex(res)
	println("sigHex------",sigHex)
}

func TestEthereum_ChainDb(t *testing.T) {
	client,err := ethclient.DialContext(context.TODO(),"http://43.203.215.230:"+port)
	if err != nil {
		println("err---dial---",err.Error())
	}
	//0xb0074eda3c8677e92978daf87107949668c4e6b9118f630642cb221eb0351a09
	commitStr := "094bd88dbc30525b003e3732bd9650e316d70b6526a1a3a9b98d76d56ec3b38a02cad0ff924bea9ed54f56de8d13badc107e6f6fc183108d01cb1551ab2d59a9"
	da,err := client.GetDAByCommitment(context.Background(),commitStr)
	if err == nil {
		println("da----",da.TxHash.String())
	}
}