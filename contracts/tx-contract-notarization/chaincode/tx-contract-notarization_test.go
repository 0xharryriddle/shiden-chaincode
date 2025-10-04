package chaincode

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/0xharryriddle/shiden-chaincode/contracts/tx-contract-notarization/chaincode/mocks"
	"github.com/hyperledger/fabric-chaincode-go/v2/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/queryresult"
	"github.com/stretchr/testify/assert"
)

/* ------------------------------ Mock Settings ----------------------------- */

// transactionContext implements contractapi.TransactionContextInterface for testing
//
//go:generate counterfeiter -o mocks/transaction.go -fake-name TransactionContext . transactionContext
type transactionContext interface {
	contractapi.TransactionContextInterface
}

// chaincodeStub implements shim.ChaincodeStubInterface for testing
//
//go:generate counterfeiter -o mocks/chaincodestub.go -fake-name ChaincodeStub . chaincodeStub
type chaincodeStub interface {
	shim.ChaincodeStubInterface
}

// clientIdentity implements cid.ClientIdentity for testing
//
//go:generate counterfeiter -o mocks/statequeryiterator.go -fake-name StateQueryIterator . stateQueryIterator
type clientIdentity interface {
	cid.ClientIdentity
}

// stateQueryIterator implements shim.StateQueryIteratorInterface for testing
//
//go:generate counterfeiter -o mocks/clientIdentity.go -fake-name ClientIdentity . clientIdentity
type stateQueryIterator interface {
	shim.StateQueryIteratorInterface
}

// setupMockContext sets up mocks with role attributes for cid.GetAttributeValue
func setupMockContext(orgMSP, role, officerID string) (*mocks.TransactionContext, *mocks.ChaincodeStub, *mocks.ClientIdentity) {
	chaincodeStub := &mocks.ChaincodeStub{}
	transactionContext := &mocks.TransactionContext{}
	transactionContext.GetStubReturns(chaincodeStub)

	clientIdentity := &mocks.ClientIdentity{}
	clientIdentity.GetMSPIDReturns(orgMSP, nil)
	clientIdentity.GetIDReturns(base64.StdEncoding.EncodeToString([]byte("testUser")), nil)

	// Setup attribute value returns based on attribute name
	clientIdentity.GetAttributeValueCalls(func(attrName string) (string, bool, error) {
		switch attrName {
		case "role":
			return role, role != "", nil
		case "officerId":
			return officerID, officerID != "", nil
		default:
			return "", false, nil
		}
	})

	// Mock GetCreator for cid.GetAttributeValue calls
	// The cid package will call stub.GetCreator() to extract attributes
	creator := []byte("mock-creator-" + orgMSP + "-" + role)
	chaincodeStub.GetCreatorReturns(creator, nil)

	// set matching msp ID using peer shim env variable
	os.Setenv("CORE_PEER_LOCALMSPID", orgMSP)
	transactionContext.GetClientIdentityReturns(clientIdentity)

	return transactionContext, chaincodeStub, clientIdentity
}

// Helper function to create a test instrument
func createTestInstrument(id string) InstrumentOnChain {
	now := time.Now().UTC().Unix()
	return InstrumentOnChain{
		InstrumentID:     id,
		InstrumentType:   InstrumentTypeRealEstate,
		Property:         &PropertyHeader{PropertyID: "PROP001", Type: "REAL_ESTATE", Digest: "hash123"},
		ContractHash:     "contract_hash_123",
		ContractFileHash: "contract_file_hash_123",
		LegalStatus:      StIntake,
		EffectiveStatus:  "ACTIVE",
		IssuerOrg:        "NotaryOrg1MSP",
		IssuerUnit:       "Unit01",
		ProvinceCode:     "01",
		Extras:           map[string]string{"lawVersion": "2023", "hashAlg": "SHA256"},
		CreatedAtUnix:    now,
		UpdatedAtUnix:    now,
		Version:          1,
	}
}

/* ------------------------------ Test Cases -------------------------------- */

// NOTE: Some tests that require role="notary_office" validation through cid.GetAttributeValue
// may fail in unit tests because the cid package requires properly formatted X.509 certificates
// with Fabric CA attribute extensions. These tests work correctly in integration tests with
// real Fabric networks. For unit testing, we test the business logic while acknowledging
// this authentication limitation.

// Test CreateInstrument - Success case
func TestCreateInstrument_Success(t *testing.T) {
	contract := TxContractNotarizationContract{}
	ctx, stub, _ := setupMockContext("NotaryOrg1MSP", "notary_office", "officer001")

	instrumentID := "INS001"
	stub.GetStateReturns(nil, nil)
	stub.CreateCompositeKeyReturns("docHash~instrument~contract_hash_123~INS001", nil)
	stub.PutStateReturns(nil)
	stub.GetTransientReturns(map[string][]byte{}, nil)

	err := contract.CreateInstrument(
		ctx,
		instrumentID,
		InstrumentTypeRealEstate,
		"contract_hash_123",
		"contract_file_hash_123",
		"REAL_ESTATE",
		"property_digest_123",
		"01",
		"Unit01",
		`{"propertyId":"PROP001"}`,
	)

	assert.NoError(t, err)
}

// Test CreateInstrument - No role attribute
func TestCreateInstrument_NoRoleAttribute(t *testing.T) {
	contract := TxContractNotarizationContract{}
	ctx, _, _ := setupMockContext("NotaryOrg1MSP", "", "")

	err := contract.CreateInstrument(
		ctx,
		"INS001",
		InstrumentTypeRealEstate,
		"contract_hash_123",
		"contract_file_hash_123",
		"REAL_ESTATE",
		"property_digest_123",
		"01",
		"Unit01",
		"{}",
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

// Test CreateInstrument - Wrong role
func TestCreateInstrument_WrongRole(t *testing.T) {
	contract := TxContractNotarizationContract{}
	ctx, _, _ := setupMockContext("NotaryOrg1MSP", "user", "")

	err := contract.CreateInstrument(
		ctx,
		"INS001",
		InstrumentTypeRealEstate,
		"contract_hash_123",
		"contract_file_hash_123",
		"REAL_ESTATE",
		"property_digest_123",
		"01",
		"Unit01",
		"{}",
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

// Test CreateInstrument - Already exists
func TestCreateInstrument_AlreadyExists(t *testing.T) {
	contract := TxContractNotarizationContract{}
	ctx, stub, _ := setupMockContext("NotaryOrg1MSP", "notary_office", "officer001")

	instrumentID := "INS001"
	existing := createTestInstrument(instrumentID)
	existingBytes, _ := json.Marshal(existing)

	stub.GetStateReturns(existingBytes, nil)

	err := contract.CreateInstrument(
		ctx,
		instrumentID,
		InstrumentTypeRealEstate,
		"contract_hash_123",
		"contract_file_hash_123",
		"REAL_ESTATE",
		"property_digest_123",
		"01",
		"Unit01",
		"{}",
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

// Test AddPartyDigest - Success
func TestAddPartyDigest_Success(t *testing.T) {
	contract := TxContractNotarizationContract{}
	ctx, stub, _ := setupMockContext("NotaryOrg1MSP", "notary_office", "officer001")

	instrumentID := "INS001"
	instrument := createTestInstrument(instrumentID)
	instrumentBytes, _ := json.Marshal(instrument)

	stub.GetStateReturns(instrumentBytes, nil)
	stub.PutStateReturns(nil)
	stub.GetTransientReturns(map[string][]byte{}, nil)

	err := contract.AddPartyDigest(
		ctx,
		instrumentID,
		"PARTY001",
		PERSON,
		"identity_digest_123",
		true,
	)

	assert.NoError(t, err)
}

// Test AddPartyDigest - Invalid state
func TestAddPartyDigest_InvalidState(t *testing.T) {
	contract := TxContractNotarizationContract{}
	ctx, stub, _ := setupMockContext("NotaryOrg1MSP", "notary_office", "officer001")

	instrumentID := "INS001"
	instrument := createTestInstrument(instrumentID)
	instrument.LegalStatus = StNotarized
	instrumentBytes, _ := json.Marshal(instrument)

	stub.GetStateReturns(instrumentBytes, nil)

	err := contract.AddPartyDigest(
		ctx,
		instrumentID,
		"PARTY001",
		PERSON,
		"identity_digest_123",
		true,
	)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid state")
}

// Test AdvanceStatus - Valid transition
func TestAdvanceStatus_ValidTransition(t *testing.T) {
	contract := TxContractNotarizationContract{}
	ctx, stub, _ := setupMockContext("NotaryOrg1MSP", "notary_office", "officer001")

	instrumentID := "INS001"
	instrument := createTestInstrument(instrumentID)
	instrument.LegalStatus = StIntake
	instrumentBytes, _ := json.Marshal(instrument)

	stub.GetStateReturns(instrumentBytes, nil)
	stub.PutStateReturns(nil)

	err := contract.AdvanceStatus(ctx, instrumentID, StTitleClear)

	assert.NoError(t, err)
}

// Test AdvanceStatus - Invalid transition
func TestAdvanceStatus_InvalidTransition(t *testing.T) {
	contract := TxContractNotarizationContract{}
	ctx, stub, _ := setupMockContext("NotaryOrg1MSP", "notary_office", "officer001")

	instrumentID := "INS001"
	instrument := createTestInstrument(instrumentID)
	instrument.LegalStatus = StIntake
	instrumentBytes, _ := json.Marshal(instrument)

	stub.GetStateReturns(instrumentBytes, nil)

	err := contract.AdvanceStatus(ctx, instrumentID, StNotarized)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "illegal transition")
}

// Test AddSignature - Success
func TestAddSignature_Success(t *testing.T) {
	contract := TxContractNotarizationContract{}
	ctx, stub, _ := setupMockContext("NotaryOrg1MSP", "notary_office", "officer001")

	instrumentID := "INS001"
	instrument := createTestInstrument(instrumentID)
	instrument.LegalStatus = StDrafted
	instrumentBytes, _ := json.Marshal(instrument)

	stub.GetStateReturns(instrumentBytes, nil)
	stub.PutStateReturns(nil)
	stub.GetTransientReturns(map[string][]byte{}, nil)

	err := contract.AddSignature(
		ctx,
		instrumentID,
		"PARTY001",
		MethodDigital,
		"payload_hash_123",
		"signature_der_123",
		"evidence_hash_123",
		time.Now().UTC().Unix(),
	)

	assert.NoError(t, err)
}

// Test IssueSeal - Success
func TestIssueSeal_Success(t *testing.T) {
	contract := TxContractNotarizationContract{}
	ctx, stub, _ := setupMockContext("NotaryOrg1MSP", "notary_office", "officer001")

	instrumentID := "INS001"
	instrument := createTestInstrument(instrumentID)
	instrument.LegalStatus = StSigned
	instrumentBytes, _ := json.Marshal(instrument)

	stub.GetStateReturns(instrumentBytes, nil)
	stub.PutStateReturns(nil)

	err := contract.IssueSeal(
		ctx,
		instrumentID,
		"SERIAL123",
		"notary_seal_hash_123",
		time.Now().UTC().Unix(),
	)

	assert.NoError(t, err)
}

// Test Revoke - Success
func TestRevoke_Success(t *testing.T) {
	contract := TxContractNotarizationContract{}
	ctx, stub, _ := setupMockContext("NotaryOrg1MSP", "notary_office", "officer001")

	instrumentID := "INS001"
	instrument := createTestInstrument(instrumentID)
	instrument.LegalStatus = StNotarized
	instrumentBytes, _ := json.Marshal(instrument)

	stub.GetStateReturns(instrumentBytes, nil)
	stub.PutStateReturns(nil)

	err := contract.Revoke(ctx, instrumentID, "Fraudulent document")

	assert.NoError(t, err)
}

// Test Complete - Success
func TestComplete_Success(t *testing.T) {
	contract := TxContractNotarizationContract{}
	ctx, stub, _ := setupMockContext("NotaryOrg1MSP", "notary_office", "officer001")

	instrumentID := "INS001"
	instrument := createTestInstrument(instrumentID)
	instrument.LegalStatus = StNotarized
	instrumentBytes, _ := json.Marshal(instrument)

	stub.GetStateReturns(instrumentBytes, nil)
	stub.PutStateReturns(nil)

	err := contract.Complete(ctx, instrumentID)

	assert.NoError(t, err)
}

// Test Verify - By InstrumentID
func TestVerify_ByInstrumentID(t *testing.T) {
	contract := TxContractNotarizationContract{}
	ctx, stub, _ := setupMockContext("NotaryOrg1MSP", "notary_office", "officer001")

	instrumentID := "INS001"
	instrument := createTestInstrument(instrumentID)
	instrumentBytes, _ := json.Marshal(instrument)

	stub.GetStateReturns(instrumentBytes, nil)

	result, err := contract.Verify(ctx, instrumentID)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, instrumentID, result.InstrumentID)
}

// Test Verify - By ContractHash
func TestVerify_ByContractHash(t *testing.T) {
	contract := TxContractNotarizationContract{}
	ctx, stub, _ := setupMockContext("NotaryOrg1MSP", "notary_office", "officer001")

	contractHash := "contract_hash_123"
	instrumentID := "INS001"
	instrument := createTestInstrument(instrumentID)
	instrumentBytes, _ := json.Marshal(instrument)

	// First GetState call returns nil (not found by contractHash as key)
	// Second GetState call returns the instrument (found by instrumentID)
	stub.GetStateReturnsOnCall(0, nil, nil)
	stub.GetStateReturnsOnCall(1, instrumentBytes, nil)

	// Create mock iterator
	iterator := &mocks.StateQueryIterator{}
	iterator.HasNextReturnsOnCall(0, true)
	iterator.HasNextReturnsOnCall(1, false)
	iterator.NextReturns(&queryresult.KV{
		Key:   "docHash~instrument~contract_hash_123~INS001",
		Value: []byte{0x00},
	}, nil)

	stub.GetStateByPartialCompositeKeyReturns(iterator, nil)
	stub.SplitCompositeKeyReturns("docHash~instrument", []string{contractHash, instrumentID}, nil)

	result, err := contract.Verify(ctx, contractHash)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, instrumentID, result.InstrumentID)
	assert.Equal(t, contractHash, result.ContractHash)
}

// Test isAllowedTransition - Valid transitions
func TestIsAllowedTransition_ValidTransitions(t *testing.T) {
	testCases := []struct {
		from     string
		to       string
		expected bool
	}{
		{StIntake, StTitleClear, true},
		{StIntake, StRejected, true},
		{StTitleClear, StDrafted, true},
		{StTitleClear, StRejected, true},
		{StDrafted, StSigned, true},
		{StDrafted, StRejected, true},
		{StSigned, StNotarized, true},
		{StSigned, StRejected, true},
		{StNotarized, StCompleted, true},
		{StNotarized, StRevoked, true},
		{StCompleted, StRevoked, true},
		{StIntake, StNotarized, false},
		{StDrafted, StCompleted, false},
		{StCompleted, StSigned, false},
		{StRevoked, StCompleted, false},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s_to_%s", tc.from, tc.to), func(t *testing.T) {
			result := isAllowedTransition(tc.from, tc.to)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test helper functions
func TestGetMSPIDLower(t *testing.T) {
	ctx, _, _ := setupMockContext("NotaryOrg1MSP", "notary_office", "officer001")

	mspid, err := getMSPIDLower(ctx)

	assert.NoError(t, err)
	assert.Equal(t, "notaryorg1msp", mspid)
}

func TestResolvePDCForNotary(t *testing.T) {
	ctx, _, _ := setupMockContext("NotaryOrg1MSP", "notary_office", "officer001")

	pdc, err := resolvePDCForNotary(ctx)

	assert.NoError(t, err)
	assert.Equal(t, "pdc_notary_notaryorg1msp", pdc)
}
