package chaincode

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
	"github.com/hyperledger/fabric-contract-api-go/v2/metadata"
)

/* -------------------------------- Constants ------------------------------- */

const (
	InstrumentTypeRealEstate = "REALESTATE_SALE"
	InstrumentTypeVehicle    = "VEHICLE_SALE"

	// Lifecycle on dossier/instrument (finite state machine)
	StIntake     = "INTAKE"
	StTitleClear = "TITLE_CLEAR"
	StDrafted    = "DRAFTED"
	StSigned     = "SIGNED"
	StNotarized  = "NOTARIZED"
	StCompleted  = "COMPLETED"
	StRevoked    = "REVOKED"  // Revoked after issuance
	StRejected   = "REJECTED" // Rejected during processing
)

// Party Type
const (
	PERSON       = "PERSON"
	ORGANIZATION = "ORGANIZATION"
)

// Relation Type
const (
	PARENT               = "PARENT"
	CHILD                = "CHILD"
	SPOUSE               = "SPOUSE"
	EMPLOYER             = "EMPLOYER"
	EMPLOYEE             = "EMPLOYEE"
	LEGAL_REPRESENTATIVE = "LEGAL_REPRESENTATIVE"
	OTHER                = "OTHER"
)

// Collections (must exist in collections_config.json)
const (
	PDCNotaryPrefix = "pdc_notary_" // actual name: pdc_notary_<mspid_lower>
)

// Signature Methods
const (
	MethodWet         = "WET"
	MethodDigital     = "DIGITAL"
	MethodFingerprint = "FINGERPRINT"
)

/* ------------------------------- Data Models ------------------------------ */

type BaseRecord struct {
	OrgId string `json:"orgId,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
	OffchainRef string `json:"offchainRef,omitempty"` // e.g., URL or IPFS hash
	SchemaVersion string `json:"schemaVersion,omitempty"`
}

type AttestationRecord struct {
	BaseRecord
	DocHash string `json:"docHash,omitempty"` // hash of the signed payload
	HashOriginalFile string `json:"hashFile,omitempty"`
}

type CertificateOnChain struct {
	InstrumentHash     string                 `json:"instrumentHash,omitempty"` // hash of the entire record (for integrity check)
	InstrumentFileHash string                 `json:"instrumentFileHash,omitempty"`
	InstrumentType     string                 `json:"instrumentType"` // REALESTATE_SALE | VEHICLE_SALE | ...
	Session            *RequestSession        `json:"session,omitempty"`
	Parties            []Party                `json:"parties"`
	Relationships      []RelationshipLink     `json:"relationships,omitempty"`
	Property           *PropertyHeader        `json:"property"`
	NotarySeal         *NotarySeal            `json:"notarySeal,omitempty"`
	Signatures         []SignatureAttestation `json:"signatures,omitempty"`
	LegalStatus        string                 `json:"legalStatus"`     // INTAKE..NOTARIZED..REVOKED/REJECTED
	EffectiveStatus    string                 `json:"effectiveStatus"` // ACTIVE|REVOKED
	IssuerOrg          string                 `json:"issuerOrg,omitempty"`
	IssuerUnit         string                 `json:"issuerUnit,omitempty"`
	ProvinceCode       string                 `json:"provinceCode,omitempty"`
	Extras             map[string]string      `json:"extras,omitempty"` // serial, lawVersion, hashAlg, etc.
	CreatedAtUnix      int64                  `json:"createdAt"`
	UpdatedAtUnix      int64                  `json:"updatedAt"`
	Version            int                    `json:"version"`
}

type InstrumentBatch

/* --------------------------- Contract Definition -------------------------- */

type TxContractNotarizationContract struct {
	contractapi.Contract
	info metadata.InfoMetadata
}

func (t *TxContractNotarizationContract) GetName() string {
	return "TxContractNotarizationContract"
}

func (t *TxContractNotarizationContract) GetInfo() metadata.InfoMetadata {
	return t.info
}

/* ----------------------------- Helper Methods ----------------------------- */

func (t *TxContractNotarizationContract) mustLoad(ctx contractapi.TransactionContextInterface, id string) (InstrumentOnChain, error) {
	state, err := ctx.GetStub().GetState(id)
	if err != nil || state == nil {
		return InstrumentOnChain{}, fmt.Errorf("instrument %s not found", id)
	}
	var instrument InstrumentOnChain
	_ = json.Unmarshal(state, &instrument)
	return instrument, nil
}

func (t *TxContractNotarizationContract) save(ctx contractapi.TransactionContextInterface, instrument *InstrumentOnChain) error {
	instrument.UpdatedAtUnix = time.Now().UTC().Unix()
	if instrument.Version == 0 {
		instrument.Version = 1
	}
	state, _ := json.Marshal(instrument)
	return ctx.GetStub().PutState(instrument.InstrumentID, state)
}

func isAllowedTransition(from, to string) bool {
	allowed := map[string][]string{
		StIntake:     {StTitleClear, StRejected},
		StTitleClear: {StDrafted, StRejected},
		StDrafted:    {StSigned, StRejected},
		StSigned:     {StNotarized, StRejected},
		StNotarized:  {StCompleted, StRevoked},
		StCompleted:  {StRevoked},
	}
	for _, v := range allowed[from] {
		if v == to {
			return true
		}
	}
	return false
}

func getMSPIDLower(ctx contractapi.TransactionContextInterface) (string, error) {
	mspid, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", err
	}
	return strings.ToLower(mspid), nil
}

func resolvePDCForNotary(ctx contractapi.TransactionContextInterface) (string, error) {
	msp, err := getMSPIDLower(ctx)
	if err != nil {
		return "", err
	}
	return PDCNotaryPrefix + msp, nil // e.g., pdc_notary_notaryorg1msp
}

/* ------------------------------ Transactions ------------------------------ */

// CreateInstrument: create a new instrument record on-chain; initial state is INTAKE
func (t *TxContractNotarizationContract) CreateInstrument(ctx contractapi.TransactionContextInterface, instrumentID, instrumentType, contractHash, contractFileHash, propertyType, propertyDigest, provinceCode, issuerUnit, extrasJSON string) error {
	// role, roleFound, _ := ctx.GetClientIdentity().GetAttributeValue("role") // e.g., notary_office
	// if !roleFound {
	// 	return fmt.Errorf("forbidden: no role attribute")
	// }
	// if role != "notary_office" {
	// 	return fmt.Errorf("forbidden: role=%s", role)
	// }

	if state, _ := ctx.GetStub().GetState(instrumentID); state != nil {
		return fmt.Errorf("instrument %s already exists", instrumentID)
	}

	extras := map[string]string{}
	if extrasJSON != "" {
		_ = json.Unmarshal([]byte(extrasJSON), &extras)
	}

	now := time.Now().UTC().Unix()

	mspid, _ := ctx.GetClientIdentity().GetMSPID()
	issuerOrg := mspid

	asset := InstrumentOnChain{
		InstrumentID:     instrumentID,
		InstrumentType:   instrumentType,
		Property:         &PropertyHeader{PropertyID: extras["propertyId"], Type: propertyType, Digest: propertyDigest},
		ContractHash:     contractHash,
		ContractFileHash: contractFileHash,
		LegalStatus:      StIntake,
		EffectiveStatus:  "ACTIVE",
		IssuerOrg:        issuerOrg,
		IssuerUnit:       issuerUnit,
		ProvinceCode:     provinceCode,
		Extras:           extras,
		CreatedAtUnix:    now,
		UpdatedAtUnix:    now,
		Version:          1,
	}

	if _, ok := asset.Extras["lawVersion"]; !ok {
		asset.Extras["lawVersion"] = "2024"
	}
	if _, ok := asset.Extras["hashAlg"]; !ok {
		asset.Extras["hashAlg"] = "sha256"
	}

	// Optional: write PII to PDC from transient map
	if temp, err := ctx.GetStub().GetTransient(); err == nil && len(temp) > 0 {
		if piib, ok := temp["pii_json"]; ok {
			pdc, err := resolvePDCForNotary(ctx)
			if err == nil {
				_ = ctx.GetStub().PutPrivateData(pdc, instrumentID+"::pii", piib)
			}
		}
		if filesb, ok := temp["files_meta_json"]; ok {
			pdc, err := resolvePDCForNotary(ctx)
			if err == nil {
				_ = ctx.GetStub().PutPrivateData(pdc, instrumentID+"::files", filesb)
			}
		}
	}

	b, _ := json.Marshal(asset)
	if err := ctx.GetStub().PutState(instrumentID, b); err != nil {
		return err
	}
	// maintain a composite key index for docHash → instrumentID
	if asset.ContractHash != "" {
		indexKey, _ := ctx.GetStub().CreateCompositeKey("docHash~instrument", []string{asset.ContractHash, instrumentID})
		if err := ctx.GetStub().PutState(indexKey, []byte{0x00}); err != nil {
			return err
		}
	}
	return nil
}

// AddPartyDigest: assign party digest (PII in PDC - pass through transient)
func (t *TxContractNotarizationContract) AddPartyDigest(ctx contractapi.TransactionContextInterface,
	instrumentID, partyID, partyType, identityDigest string, presentAtSigning bool) error {

	asset, err := t.mustLoad(ctx, instrumentID)
	if err != nil {
		return err
	}
	if asset.LegalStatus != StIntake && asset.LegalStatus != StTitleClear && asset.LegalStatus != StDrafted {
		return fmt.Errorf("invalid state: %s", asset.LegalStatus)
	}
	p := Party{PartyID: partyID, Type: partyType, IdentityDigest: identityDigest, PresentAtSigning: presentAtSigning}
	asset.Parties = append(asset.Parties, p)
	if err := t.save(ctx, &asset); err != nil {
		return err
	}

	// if PII in transient, write to PDC
	if tm, err := ctx.GetStub().GetTransient(); err == nil {
		if piib, ok := tm["pii_json"]; ok {
			pdc, e := resolvePDCForNotary(ctx)
			if e == nil {
				_ = ctx.GetStub().PutPrivateData(pdc, instrumentID+"::party::"+partyID, piib)
			}
		}
	}
	return nil
}

// AdvanceStatus: transfer state machine to next step
func (t *TxContractNotarizationContract) AdvanceStatus(ctx contractapi.TransactionContextInterface,
	instrumentID, nextStatus string) error {

	asset, err := t.mustLoad(ctx, instrumentID)
	if err != nil {
		return err
	}
	if !isAllowedTransition(asset.LegalStatus, nextStatus) {
		return fmt.Errorf("illegal transition %s→%s", asset.LegalStatus, nextStatus)
	}
	if nextStatus == StSigned && len(asset.Signatures) == 0 {
		return fmt.Errorf("no signatures yet")
	}
	asset.LegalStatus = nextStatus
	return t.save(ctx, &asset)
}

// AddSignature: add signature attestation from a party (WET/DIGITAL/FINGERPRINT)
func (t *TxContractNotarizationContract) AddSignature(ctx contractapi.TransactionContextInterface,
	instrumentID, partyID, method, payloadHash, signatureDer, evidenceRefHash string, signedAt int64) error {

	asset, err := t.mustLoad(ctx, instrumentID)
	if err != nil {
		return err
	}
	if asset.LegalStatus != StDrafted && asset.LegalStatus != StSigned {
		return fmt.Errorf("invalid state: %s", asset.LegalStatus)
	}
	signature := SignatureAttestation{
		PartyID: partyID, Method: method, PayloadHash: payloadHash,
		SignatureDER: signatureDer, SignedAtUnix: signedAt, EvidenceRefHash: evidenceRefHash,
	}
	asset.Signatures = append(asset.Signatures, signature)
	if asset.LegalStatus == StDrafted {
		asset.LegalStatus = StSigned
	}
	if err := t.save(ctx, &asset); err != nil {
		return err
	}

	// if evidence in transient, write to PDC
	if tm, err := ctx.GetStub().GetTransient(); err == nil {
		if evb, ok := tm["evidence_json"]; ok {
			pdc, e := resolvePDCForNotary(ctx)
			if e == nil {
				_ = ctx.GetStub().PutPrivateData(pdc, instrumentID+"::sig::"+partyID, evb)
			}
		}
	}
	return nil
}

// IssueSeal (Notarize): add notary seal and change state to NOTARIZED
func (t *TxContractNotarizationContract) IssueSeal(ctx contractapi.TransactionContextInterface,
	instrumentID, serial, notarySealHash string, sealTime int64) error {
	// role, roleFound, _ := ctx.GetClientIdentity().GetAttributeValue("role")
	// if !roleFound {
	// 	return fmt.Errorf("forbidden: no role attribute")
	// }
	// if role != "notary_office" {
	// 	return fmt.Errorf("forbidden: role=%s", role)
	// }

	asset, err := t.mustLoad(ctx, instrumentID)
	if err != nil {
		return err
	}
	if asset.LegalStatus != StSigned {
		return fmt.Errorf("must be SIGNED")
	}

	mspID, _ := ctx.GetClientIdentity().GetMSPID()
	uid, uidFound, _ := ctx.GetClientIdentity().GetAttributeValue("officerId")

	if !uidFound {
		return fmt.Errorf("forbidden: no officerId attribute")
	}

	asset.NotarySeal = &NotarySeal{NotaryMSP: mspID, NotaryUserID: uid, NotarySealHash: notarySealHash, SealTimeUnix: sealTime}
	if asset.Extras == nil {
		asset.Extras = map[string]string{}
	}
	asset.Extras["serial"] = serial
	asset.LegalStatus = StNotarized
	return t.save(ctx, &asset)
}

// Revoke
func (t *TxContractNotarizationContract) Revoke(ctx contractapi.TransactionContextInterface,
	instrumentID, reason string) error {

	// role, roleFound, _ := ctx.GetClientIdentity().GetAttributeValue("role")
	// if !roleFound {
	// 	return fmt.Errorf("forbidden: no role attribute")
	// }
	// if role != "notary_office" {
	// 	return fmt.Errorf("forbidden: role=%s", role)
	// }

	asset, err := t.mustLoad(ctx, instrumentID)
	if err != nil {
		return err
	}
	if asset.LegalStatus != StNotarized && asset.LegalStatus != StCompleted {
		return fmt.Errorf("only NOTARIZED/COMPLETED can be REVOKED")
	}
	asset.LegalStatus = StRevoked
	if asset.Extras == nil {
		asset.Extras = map[string]string{}
	}
	asset.Extras["revokeReason"] = reason
	return t.save(ctx, &asset)
}

// Complete
func (t *TxContractNotarizationContract) Complete(ctx contractapi.TransactionContextInterface, instrumentID string) error {
	asset, err := t.mustLoad(ctx, instrumentID)
	if err != nil {
		return err
	}
	if asset.LegalStatus != StNotarized {
		return fmt.Errorf("must be NOTARIZED")
	}
	asset.LegalStatus = StCompleted
	return t.save(ctx, &asset)
}

// Verify by assetID or by ContractHash (using composite key)
func (t *TxContractNotarizationContract) Verify(ctx contractapi.TransactionContextInterface, idOrHash string) (*InstrumentOnChain, error) {
	// By primary key
	if b, _ := ctx.GetStub().GetState(idOrHash); b != nil {
		var a InstrumentOnChain
		_ = json.Unmarshal(b, &a)
		return &a, nil
	}
	// By docHash via partial composite key scan (LevelDB supports range)
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey("docHash~instrument", []string{idOrHash})
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	if iter.HasNext() {
		kv, _ := iter.Next()
		_, parts, _ := ctx.GetStub().SplitCompositeKey(kv.Key)
		if len(parts) == 2 {
			assetID := parts[1]
			b, _ := ctx.GetStub().GetState(assetID)
			if b != nil {
				var a InstrumentOnChain
				_ = json.Unmarshal(b, &a)
				return &a, nil
			}
		}
	}
	return nil, fmt.Errorf("NOT_FOUND")
}

/* ------------------------------- NOTES ---------------------------------
Deployment quick-notes (no CouchDB required)


Endorsement policy (when deploying):
notarization-cc: AND('NotaryOrg.member','DoJ.member')


Private Data Collections (collections_config.json):
[
{
"name": "pdc_notary_notaryorg1msp",
"policy": {"identities":[{"role":{"name":"member","mspId":"NotaryOrg1MSP"}},{"role":{"name":"member","mspId":"DoJMSP"}}],"policy":{"2-of":[{"signed-by":0},{"signed-by":1}]}},
"requiredPeerCount": 1,
"maxPeerCount": 2,
"blockToLive": 0,
"memberOnlyRead": true
}
]


State DB & Indexing (LevelDB-first):
- Keep default LevelDB (goleveldb). In peer core.yaml:


ledger:
state:
stateDatabase: goleveldb


- Secondary index uses composite keys (works with LevelDB):
* Primary state: PutState(instrumentID, asset)
* Secondary key: CreateCompositeKey("docHash~instrument", [docHash, instrumentID]) → PutState(idxKey, 0x00)
* Lookup by docHash: GetStateByPartialCompositeKey("docHash~instrument", [docHash]) → resolve instrumentID → GetState


Off-chain search (recommended for advanced queries):
- Run a lightweight block listener (Node/Go) to stream blocks → PostgreSQL/Elasticsearch.
- Store fields for ad‑hoc analytics (issuer, provinceCode, instrumentType, status, timestamps...).
- Public Verify API should first try on-chain (assetId/docHash via composite key), then optionally fall back to off-chain if you allow fuzzy/advanced filters.
----------------------------------------------------------------------- */
