package chaincode

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/v2/pkg/cid"
	statebased "github.com/hyperledger/fabric-chaincode-go/v2/pkg/statebased"
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

type PartyRef struct {
	ID   string `json:"id"`
	Role string `json:"role"`
	Name string `json:"name"`
}

type SignatureRef struct {
	Subject string `json:"subject"`
	CertSN  string `json:"certSn"`
	Algo    string `json:"algo"`
	Time    string `json:"time"`
}

type Instrument struct {
	ID                 string         `json:"id"`
	CaseID             string         `json:"caseId"`
	InstrumentNo       string         `json:"instrumentNo"`
	NotarizationOffice string         `json:"notarizationOffice"`
	Province           string         `json:"province"`
	Parties            []PartyRef     `json:"parties,omitempty"`
	DocHash            string         `json:"docHash"`
	OffchainURI        string         `json:"offchainUri"`
	IssuedAt           string         `json:"issuedAt"`
	Status             string         `json:"status"` // ISSUED|REVOKED
	RevokedAt          string         `json:"revokedAt,omitempty"`
	RevokedReason      string         `json:"revokedReason,omitempty"`
	JournalSeq         int            `json:"journalSeq"`
	QR                 string         `json:"qr"`
	Signatures         []SignatureRef `json:"signatures,omitempty"`
}

type issuePayload struct {
	ID           string         `json:"id"`
	CaseID       string         `json:"caseId"`
	InstrumentNo string         `json:"instrumentNo"`
	Province     string         `json:"province"`
	Parties      []PartyRef     `json:"parties,omitempty"`
	DocHash      string         `json:"docHash"`
	OffchainURI  string         `json:"offchainUri"`
	JournalSeq   int            `json:"journalSeq"`
	QR           string         `json:"qr"`
	Signatures   []SignatureRef `json:"signatures,omitempty"`
}

const (
	ISSUED  = "ISSUED"
	REVOKED = "REVOKED"
)

type NotarizationTransactionContext struct {
	contractapi.TransactionContext
}

// NotarizationContract provides functions for managing notarization instruments
type NotarizationContract struct {
	contractapi.Contract
}

// GetName returns the contract name
func (n *NotarizationContract) GetName() string {
	return "NotarizationContract"
}

func (s *NotarizationContract) mustRole(ctx contractapi.TransactionContextInterface, allowed ...string) error {
	role, ok, err := getAttr(ctx, "role")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("missing attribute: role")
	}
	for _, a := range allowed {
		if role == a {
			return nil
		}
	}
	return fmt.Errorf("forbidden: role %s not in %v", role, allowed)
}

// PutPII: ghi PII vào implicit PDC của org gọi giao dịch.
// Truyền payload qua transient map với key "pii"
func (s *NotarizationContract) PutPII(ctx contractapi.TransactionContextInterface, caseID string) error {
	msp, err := getMSP(ctx)
	if err != nil {
		return err
	}
	tm, err := ctx.GetStub().GetTransient()
	if err != nil {
		return err
	}
	raw, ok := tm["pii"]
	if !ok {
		return errors.New("transient pii missing")
	}
	key := fmt.Sprintf("PII|%s", caseID)
	return ctx.GetStub().PutPrivateData(implicitCollName(msp), key, raw)
}

// InstrumentIssue: tạo văn bản công chứng, thiết lập SBE per-key
func (s *NotarizationContract) InstrumentIssue(ctx contractapi.TransactionContextInterface, payloadJSON string, requireMOJ bool) (*Instrument, error) {
	if err := s.mustRole(ctx, "NOTARY"); err != nil {
		return nil, err
	}

	var p issuePayload
	if err := json.Unmarshal([]byte(payloadJSON), &p); err != nil {
		return nil, fmt.Errorf("invalid payload: %w", err)
	}
	if p.ID == "" || p.CaseID == "" || p.InstrumentNo == "" || p.DocHash == "" {
		return nil, errors.New("missing required fields")
	}

	msp, err := getMSP(ctx)
	if err != nil {
		return nil, err
	}
	issuedAt, err := nowRFC3339(ctx)
	if err != nil {
		return nil, err
	}

	inst := &Instrument{
		ID:                 p.ID,
		CaseID:             p.CaseID,
		InstrumentNo:       p.InstrumentNo,
		NotarizationOffice: msp,
		Province:           p.Province,
		Parties:            p.Parties,
		DocHash:            p.DocHash,
		OffchainURI:        p.OffchainURI,
		IssuedAt:           issuedAt,
		Status:             ISSUED,
		JournalSeq:         p.JournalSeq,
		QR:                 p.QR,
		Signatures:         p.Signatures,
	}

	key := "INS|" + inst.ID
	b, _ := json.Marshal(inst)
	if err := ctx.GetStub().PutState(key, b); err != nil {
		return nil, err
	}

	// Secondary index by InstrumentNo (composite key)
	idxKey, _ := ctx.GetStub().CreateCompositeKey("instrument~no", []string{strings.ToLower(inst.InstrumentNo), inst.ID})
	if err := ctx.GetStub().PutState(idxKey, []byte{0}); err != nil {
		return nil, err
	}

	// Set SBE per-key: require current VPCC MSP (+ optionally MOJMSP)
	ep, _ := statebased.NewStateEP(nil)
	if err := ep.AddOrgs(statebased.RoleTypePeer, msp); err != nil {
		return nil, err
	}
	if requireMOJ {
		if err := ep.AddOrgs(statebased.RoleTypePeer, "MOJMSP"); err != nil {
			return nil, err
		} // TODO: đổi tên MSP thực tế
	}
	pol, _ := ep.Policy()
	if err := ctx.GetStub().SetStateValidationParameter(key, pol); err != nil {
		return nil, err
	}

	// Event
	evt, _ := json.Marshal(map[string]any{"id": inst.ID, "instrumentNo": inst.InstrumentNo, "vpcc": inst.NotarizationOffice, "issuedAt": inst.IssuedAt})
	_ = ctx.GetStub().SetEvent("instrument.issued", evt)
	return inst, nil
}

func (s *NotarizationContract) InstrumentGet(ctx contractapi.TransactionContextInterface, id string) (*Instrument, error) {
	b, err := ctx.GetStub().GetState("INS|" + id)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("instrument %s not found", id)
	}
	var inst Instrument
	if err := json.Unmarshal(b, &inst); err != nil {
		return nil, err
	}
	return &inst, nil
}

func (s *NotarizationContract) InstrumentVerify(ctx contractapi.TransactionContextInterface, id string, docHash string) (map[string]any, error) {
	inst, err := s.InstrumentGet(ctx, id)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"id":                 inst.ID,
		"instrumentNo":       inst.InstrumentNo,
		"status":             inst.Status,
		"notarizationOffice": inst.NotarizationOffice,
		"issuedAt":           inst.IssuedAt,
		"hashMatch":          strings.EqualFold(inst.DocHash, docHash),
	}, nil
}

func (s *NotarizationContract) InstrumentRevoke(ctx contractapi.TransactionContextInterface, id string, reason string) (Instrument, error) {
	// Cho phép SUPERVISOR của VPCC hoặc bất kỳ user của MOJMSP
	msp, err := getMSP(ctx)
	if err != nil {
		return Instrument{}, err
	}
	if msp == "MOJMSP" { /* ok */
	} else {
		if err := s.mustRole(ctx, "SUPERVISOR"); err != nil {
			return Instrument{}, err
		}
	}

	inst, err := s.InstrumentGet(ctx, id)
	if err != nil {
		return Instrument{}, err
	}
	if inst.Status == REVOKED {
		return *inst, nil
	}

	t, _ := nowRFC3339(ctx)
	inst.Status = REVOKED
	inst.RevokedAt = t
	if reason != "" {
		inst.RevokedReason = reason
	}

	key := "INS|" + inst.ID
	b, _ := json.Marshal(inst)
	if err := ctx.GetStub().PutState(key, b); err != nil {
		return Instrument{}, err
	}

	// (tùy chọn) cập nhật SBE để yêu cầu MOJ phê duyệt mọi cập nhật tiếp theo
	ep, _ := statebased.NewStateEP(nil)
	if err := ep.AddOrgs(statebased.RoleTypePeer, "MOJMSP"); err != nil {
		return Instrument{}, err
	}
	pol, _ := ep.Policy()
	_ = ctx.GetStub().SetStateValidationParameter(key, pol)

	evt, _ := json.Marshal(map[string]any{"id": inst.ID, "reason": reason})
	_ = ctx.GetStub().SetEvent("instrument.revoked", evt)
	return *inst, nil
}

/* --------------------------------- Helpers -------------------------------- */

func nowRFC3339(ctx contractapi.TransactionContextInterface) (string, error) {
	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return "", err
	}
	t := time.Unix(ts.Seconds, int64(ts.Nanos)).UTC()
	return t.Format(time.RFC3339), nil
}

func getMSP(ctx contractapi.TransactionContextInterface) (string, error) {
	return cid.GetMSPID(ctx.GetStub())
}

func getAttr(ctx contractapi.TransactionContextInterface, key string) (string, bool, error) {
	return cid.GetAttributeValue(ctx.GetStub(), key)
}

func implicitCollName(msp string) string { return "_implicit_org_" + msp }
