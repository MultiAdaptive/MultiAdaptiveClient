package scriptparser

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/ethereum/go-ethereum/log"
)

const (
	ProtocolID     string = "6f7264"
	BodyTag        string = "00"
	ContentTypeTag string = "01"
)

type TransactionInscription struct {
	Validator   *ValidatorContent
	Inscription *InscriptionContent
	TxInIndex   uint32
	TxInOffset  uint64
}

type InscriptionContent struct {
	ContentType             []byte
	ContentBody             []byte
	ContentLength           uint64
	IsUnrecognizedEvenField bool
}

type ValidatorContent struct {
	ValidatorAddresses []string
}

func ParseInscriptionsFromTransaction(msgTx *wire.MsgTx, net *chaincfg.Params) []*TransactionInscription {
	var inscriptionsFromTx []*TransactionInscription
	txHash := msgTx.TxHash().String()

	if !msgTx.HasWitness() {
		log.Debug("Tx: %s inputs does not contain witness data", txHash)
		return nil
	}

	for i, v := range msgTx.TxIn {
		index, input := i, v
		if len(input.Witness) <= 1 {
			log.Debug("Tx: %s, the length of tx input witness data is %d", txHash, len(input.Witness))
			continue
		}
		if len(input.Witness) == 2 && input.Witness[len(input.Witness)-1][0] == txscript.TaprootAnnexTag {
			log.Debug("Tx: %s, tx witness contains Taproot Annex data but the length of tx input witness data is 2",
				txHash)
			continue
		}

		// If Taproot Annex data exists, take the last element of the witness as the script data, otherwise,
		// take the penultimate element of the witness as the script data
		var witnessScript []byte
		if input.Witness[len(input.Witness)-1][0] == txscript.TaprootAnnexTag {
			witnessScript = input.Witness[len(input.Witness)-1]
		} else {
			witnessScript = input.Witness[len(input.Witness)-2]
		}

		if !needParse(witnessScript) {
			continue
		}

		validator := ParseValidator(witnessScript, net)
		if len(validator.ValidatorAddresses) == 0 {
			continue
		}

		// Parse script and get ordinals content
		inscriptions := ParseInscriptions(witnessScript)
		if len(inscriptions) == 0 {
			continue
		}
		for i, v := range inscriptions {
			txInOffset, inscription := i, v
			inscriptionsFromTx = append(inscriptionsFromTx, &TransactionInscription{
				Validator:   validator,
				Inscription: inscription,
				TxInIndex:   uint32(index),
				TxInOffset:  uint64(txInOffset),
			})
		}
	}
	return inscriptionsFromTx
}

func needParse(witnessScript []byte) bool {
	flag := false
	tokenizer := txscript.MakeScriptTokenizer(0, witnessScript)
	for tokenizer.Next() {
		if tokenizer.OpcodePosition() == 8 {
			if hex.EncodeToString(tokenizer.Data()) == ProtocolID {
				flag = true
				break
			}
		}
	}

	return flag
}

func ParseValidator(witnessScript []byte, net *chaincfg.Params) *ValidatorContent {
	var validators ValidatorContent

	tokenizer := txscript.MakeScriptTokenizer(0, witnessScript)
	for tokenizer.Next() {
		if tokenizer.OpcodePosition() == 0 || tokenizer.OpcodePosition() == 2 {
			pubkey, _ := schnorr.ParsePubKey(tokenizer.Data())
			address, _ := convertPubKey2Address(pubkey, net)
			log.Info("Data: ", address)
			validators.ValidatorAddresses = append(validators.ValidatorAddresses, address)
		}
	}

	return &validators
}

func ParseInscriptions(witnessScript []byte) []*InscriptionContent {
	var inscriptions []*InscriptionContent

	// Parse inscription content from witness script
	tokenizer := txscript.MakeScriptTokenizer(0, witnessScript)
	for tokenizer.Next() {
		// Check inscription envelop header: OP_FALSE(0x00), OP_IF(0x63), PROTOCOL_ID([0x6f, 0x72, 0x64])
		if tokenizer.Opcode() == txscript.OP_FALSE {
			if !tokenizer.Next() || tokenizer.Opcode() != txscript.OP_IF {
				return inscriptions
			}
			if !tokenizer.Next() || hex.EncodeToString(tokenizer.Data()) != ProtocolID {
				return inscriptions
			}
			inscription := parseOneInscription(&tokenizer)
			if inscription != nil {
				inscriptions = append(inscriptions, inscription)
			}
		}
	}

	return inscriptions
}

func parseOneInscription(tokenizer *txscript.ScriptTokenizer) *InscriptionContent {
	var (
		tags                    = make(map[string][]byte)
		contentType             []byte
		contentBody             []byte
		contentLength           uint64
		isUnrecognizedEvenField bool
	)

	// Find any pushed data in the script. This includes OP_0, but not OP_1 - OP_16.
	for tokenizer.Next() {
		if tokenizer.Opcode() == txscript.OP_ENDIF {
			break
		} else if hex.EncodeToString([]byte{tokenizer.Opcode()}) == BodyTag {
			var body []byte
			for tokenizer.Next() {
				if tokenizer.Opcode() == txscript.OP_ENDIF {
					break
				} else if tokenizer.Opcode() == txscript.OP_0 {
					// OP_0 push no data
					continue
				} else if tokenizer.Opcode() >= txscript.OP_DATA_1 && tokenizer.Opcode() <= txscript.OP_PUSHDATA4 {
					// Taproot's restriction, individual data pushes may not be larger than 520 bytes.
					if len(tokenizer.Data()) > 520 {
						log.Error("data is longer than 520")
						return nil
					}
					body = append(body, tokenizer.Data()...)
				} else {
					// Invalid opcode found in content body, e.g., 615a7c90df1d4fdd07c6ea98766bc6846dd5264a9fa81ca41611bbf9bde38cf8.
					return nil
				}
			}
			contentBody = body
			contentLength = uint64(len(body))
			break
		} else {
			if tokenizer.Data() == nil {
				return nil
			}
			tag := hex.EncodeToString(tokenizer.Data())
			if _, ok := tags[tag]; ok {
				return nil
			}
			if tokenizer.Next() {
				if tokenizer.Opcode() != txscript.OP_0 && tokenizer.Data() == nil {
					// Invalid data length, e.g., 0b71bd09c848be66334c0cdaa32686e98dffa8a212af694f59165cdbb588e587
					return nil
				}
				tags[tag] = tokenizer.Data()
			}
		}
	}

	// No OP_ENDIF
	if tokenizer.Opcode() != txscript.OP_ENDIF {
		return nil
	}

	// Error occurred
	if err := tokenizer.Err(); err != nil {
		return nil
	}

	// Get inscription content
	for k := range tags {
		key := k
		if key == ContentTypeTag {
			contentType = tags[ContentTypeTag]
			continue
		}
		// Unrecognized even tag
		tag, _ := hex.DecodeString(key)
		if len(tag) > 0 && int(tag[0])%2 == 0 {
			isUnrecognizedEvenField = true
		}
	}

	inscription := &InscriptionContent{
		ContentType:             contentType,
		ContentBody:             contentBody,
		ContentLength:           contentLength,
		IsUnrecognizedEvenField: isUnrecognizedEvenField,
	}
	return inscription
}

func convertPubKey2Address(pubKey *btcec.PublicKey, net *chaincfg.Params) (string, error) {
	// 将公钥转换为压缩格式的字节数组
	pubKeyBytes := pubKey.SerializeCompressed()

	// 将公钥字节数组转换为比特币地址
	address, err := btcutil.NewAddressPubKey(pubKeyBytes, net)
	if err != nil {
		log.Error("%v", err.Error())
		return "", err
	}

	// 输出比特币地址
	log.Info("Bitcoin Address:", address.EncodeAddress())

	return address.EncodeAddress(), nil
}
