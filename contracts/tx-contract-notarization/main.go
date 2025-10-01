package main

import (
	"log"

	"github.com/0xharryriddle/shiden-chaincode/contracts/tx-contract-notarization/chaincode"
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

func main() {
	txContractNotarization, err := contractapi.NewChaincode(&chaincode.TxContractNotarizationContract{})

	if err != nil {
		log.Panicf("Error creating tx-contract-notarization chaincode: %v", err)
	}

	if err := txContractNotarization.Start(); err != nil {
		log.Panicf("Error starting tx-contract-notarization chaincode: %v", err)
	}
}
