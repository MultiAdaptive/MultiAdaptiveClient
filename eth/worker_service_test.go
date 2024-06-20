package eth

import (
	"github.com/btcsuite/btcd/rpcclient"
	"testing"
)

func TestGetTransactionFee(t *testing.T) {
	connCfg := &rpcclient.ConnConfig{
		Host:         "52.221.9.230:18332/wallet/newwallet.dat",
		User:         "testuser",
		Pass:         "123456",
		HTTPPostMode: true,
		DisableTLS:   true,
	}

	client, err := rpcclient.New(connCfg, nil)
	if err != nil {
		t.Fatalf("Failed to create RPC client: %v", err)
	}

	ws := NewWorkerService(nil, client, "", "", 0)
	txID := "5ea0624c1df5f6efdcb53b6285822d03d9219e08c444218de3183f3b8d59a845"

	// 获取交易费用
	fee, err := ws.GetTransactionFee(txID)
	if err != nil {
		t.Fatalf("Error getting transaction fee: %v", err)
	}

	t.Logf("Transaction fee for %s: %f BTC\n", txID, fee)
}
