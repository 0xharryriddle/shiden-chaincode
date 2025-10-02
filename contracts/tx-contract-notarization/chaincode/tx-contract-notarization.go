package chaincode

import (
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
	"github.com/hyperledger/fabric-contract-api-go/v2/metadata"
)

/* -------------------------------- Constants ------------------------------- */

const (
	InstrumentTypeRealEstate = "REALESTATE_SALE"
	InstrumentTypeVehicle    = "VEHICLE_SALE"

	// Lifecycle on dossier/instrument
	StIntake     = "INTAKE"
	StTitleClear = "TITLE_CLEAR"
	StDrafted    = "DRAFTED"
	StSigned     = "SIGNED"
	StNotarized  = "NOTARIZED"
	StCompleted  = "COMPLETED"
	StRevoked    = "REVOKED"  // Revoked after expiration
	StRejected   = "REJECTED" // Rejected during processing
)

// Parity Type
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

type RequestSession struct {
	SessionID                 string   `json:"sessionId"`
	RelatedDocumentsHash      []string `json:"relatedDocumentsHash"`
	RelatedDocumentsHashFiles []string `json:"relatedDocumentsHashFiles"`
}

// Party with minimal on-chain footprint; Personally Identifiable Information (PII) in Private Data Collection (PDC)
type Party struct {
	ParityID         string `json:"parityId"`
	Type             string `json:"type"`             // PERSON|ORGANIZATION
	IdentityDigest   string `json:"identityDigest"`   // hash(PII canonical json)
	PresentAtSigning bool   `json:"presentAtSigning"` // is presented at signing
}

type RelationshipLink struct {
	FromParityID string `json:"fromParityId"`
	ToParityID   string `json:"toParityId"`
	Relation     string `json:"relation"` // PARENT/CHILD/SPOUSE/EMPLOYER/EMPLOYEE/LEGAL_REPRESENTATIVE/OTHER
	Note         string `json:"note,omitempty"`
}

// Property “header” to profile loại tài sản (chi tiết trong PDC)
type PropertyHeader struct {
	PropertyID string `json:"propertyId"`
	Type       string `json:"type"` // REAL_ESTATE|VEHICLE
	Digest     string `json:"digest"`
}

type SignatureAttestation struct {
	PartyID         string `json:"partyId"`
	Method          string `json:"method"`       // WET|DIGITAL|FINGERPRINT
	PayloadHash     string `json:"payloadHash"`  // hash của PDF hợp đồng chuẩn hóa
	SignatureDER    string `json:"signatureDer"` // nếu DIGITAL; nếu WET giữ trong PDC
	SignedAtUnix    int64  `json:"signedAt"`
	EvidenceRefHash string `json:"evidenceRefHash,omitempty"` // ảnh/video: hash
}

type NotarySeal struct {
	NotaryMSP      string `json:"notaryMsp"`
	NotaryUserID   string `json:"notaryUserId"`
	NotarySealHash string `json:"notarySealHash"` // hash dấu/tem thời gian
	SealTimeUnix   int64  `json:"sealTimeUnix"`
}

type InstrumentOnChain struct {
	InstrumentID     string                 `json:"instrumentId"`
	InstrumentType   string                 `json:"instrumentType"` // REAL... | VEHICLE...
	Session          *RequestSession        `json:"session,omitempty"`
	Parties          []Party                `json:"parties"`
	Relationships    []RelationshipLink     `json:"relationships,omitempty"`
	Property         *PropertyHeader        `json:"property"`
	ContractHash     string                 `json:"contractHash"`     // hash(pdf normalized)
	ContractFileHash string                 `json:"contractFileHash"` // hash(binary pdf)
	NotarySeal       *NotarySeal            `json:"notarySeal,omitempty"`
	Signatures       []SignatureAttestation `json:"signatures,omitempty"`
	LegalStatus      string                 `json:"legalStatus"`     // INTAKE..NOTARIZED..REVOKED/REJECTED
	EffectiveStatus  string                 `json:"effectiveStatus"` // ACTIVE|REVOKED
	CreatedAtUnix    int64                  `json:"createdAt"`
	UpdatedAtUnix    int64                  `json:"updatedAt"`
	Version          int                    `json:"version"`
}

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
