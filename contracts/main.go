package contracts

import (
	"github.com/0xharryriddle/shiden-chaincode/contracts/chaincode"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func main() {
	notarizationContract, err := contractapi.NewChaincode(&chaincode.NotarizationContract{})
	if err != nil {
		panic("Error creating notarization chaincode: " + err.Error())
	}

	if err := notarizationContract.Start(); err != nil {
		panic("Error starting notarization chaincode: " + err.Error())
	}
}
