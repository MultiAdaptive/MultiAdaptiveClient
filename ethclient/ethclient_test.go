package ethclient

import (
	"context"
	"testing"
)

func TestDial(t *testing.T) {

	client,err := Dial("https://eth-sepolia.g.alchemy.com/v2/-t67_L9EE802yd-RZYxsZ38XRcJOCHfq")
	if err != nil {
		println("err",err.Error())
	}

	bnum,err := client.BlockNumber(context.Background())
	if err != nil {
		println("err",err.Error())
	}
	println("block num",bnum)
}