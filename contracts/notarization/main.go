package main

import (
	chaincode "github.com/0xharryriddle/shiden-chaincode/contracts/notarization/chaincode"
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

func main() {
	notarizationContract, err := contractapi.NewChaincode(
		&chaincode.NotarizationContract{},
	)
	if err != nil {
		panic("Error creating notarization chaincode: " + err.Error())
	}

	if err := notarizationContract.Start(); err != nil {
		panic("Error starting notarization chaincode: " + err.Error())
	}
}
