package main

import (
	"context"
	"crypto/x509"
	"errors"
	"log"
	"os"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func must(err error) {
	if err != nil {
		log.Fatalf("%v", err)
	}
}

func fileBytes(path string) []byte {
	b, err := os.ReadFile(path)
	must(err)
	return b
}

func tlsCredentials(tlsCertPath string) (credentials.TransportCredentials, error) {
	pemBytes := fileBytes(tlsCertPath)
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("failed to add peer TLS cert")
	}
	return credentials.NewClientTLSFromCert(cp, ""), nil
}

func newGateway() (*client.Gateway, *grpc.ClientConn, error) {
	peer := os.Getenv("FABRIC_PEER_ENDPOINT")
	tlsPath := os.Getenv("FABRIC_TLS_CERT_PATH")
	mspID := os.Getenv("FABRIC_MSP_ID")

	cert, err := identity.CertificateFromPEM(fileBytes(os.Getenv("FABRIC_CERT_PATH")))
	if err != nil {
		return nil, nil, err
	}
	id, err := identity.NewX509Identity(mspID, cert)
	if err != nil {
		return nil, nil, err
	}
	pk, err := identity.PrivateKeyFromPEM(fileBytes(os.Getenv("FABRIC_KEY_PATH")))
	if err != nil {
		return nil, nil, err
	}
	sign, err := identity.NewPrivateKeySign(pk)
	if err != nil {
		return nil, nil, err
	}

	creds, err := tlsCredentials(tlsPath)
	if err != nil {
		return nil, nil, err
	}
	conn, err := grpc.Dial(peer, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, err
	}

	gw, err := client.Connect(id,
		client.WithClientConnection(conn),
		client.WithSign(sign),
		client.WithEvaluateTimeout(10*time.Second),
		client.WithEndorseTimeout(30*time.Second),
		client.WithSubmitTimeout(30*time.Second),
		client.WithCommitStatusTimeout(60*time.Second),
	)
	return gw, conn, err
}

func contract(gw *client.Gateway) *client.Contract {
	channel := os.Getenv("FABRIC_CHANNEL")
	cc := os.Getenv("FABRIC_CHAINCODE")
	cn := os.Getenv("FABRIC_CONTRACT")
	net := gw.GetNetwork(channel)
	if cn == "" {
		return net.GetContract(cc)
	}
	return net.GetContractWithName(cc, cn)
}

func PutPII(c *client.Contract, caseID string, piiJSON []byte) error {
	transient := map[string][]byte{"pii": piiJSON}
	proposal, err := c.NewProposal(
		"PutPII",
		client.WithArguments(caseID),
		client.WithTransient(transient),
	)
	if err != nil {
		return err
	}
	txn, err := proposal.Endorse()
	if err != nil {
		return err
	}
	_, err = txn.Submit()
	return err
}

func InstrumentIssue(c *client.Contract, payloadJSON []byte, requireMOJ bool) ([]byte, error) {
	argRequire := "false"
	if requireMOJ {
		argRequire = "true"
	}
	return c.SubmitTransaction("InstrumentIssue", string(payloadJSON), argRequire)
}

func InstrumentGet(c *client.Contract, id string) ([]byte, error) {
	return c.EvaluateTransaction("InstrumentGet", id)
}

func InstrumentVerify(c *client.Contract, id, docHash string) ([]byte, error) {
	return c.EvaluateTransaction("InstrumentVerify", id, docHash)
}

func InstrumentRevoke(c *client.Contract, id, reason string) ([]byte, error) {
	return c.SubmitTransaction("InstrumentRevoke", id, reason)
}

func listenEvents(net *client.Network) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := net.ChaincodeEvents(ctx, os.Getenv("FABRIC_CHAINCODE"))
	if err != nil {
		log.Printf("event subscribe err: %v", err)
		return cancel
	}
	go func() {
		for evt := range ch {
			log.Printf("event %s tx=%s payload=%s", evt.EventName, evt.TransactionID, string(evt.Payload))
		}
	}()
	return cancel
}

func main() {
	gw, conn, err := newGateway()
	must(err)
	defer conn.Close()
	defer gw.Close()

	c := contract(gw)
	stop := listenEvents(gw.GetNetwork(os.Getenv("FABRIC_CHANNEL")))
	defer stop()

	// Example: Issue
	payload := []byte(`{
        "id":"INS-2025-0000001",
        "caseId":"CASE-2025-0001",
        "instrumentNo":"2025/VPCC1/0000001",
        "province":"79",
        "parties":[{"id":"P1","role":"SELLER","name":"Nguyen A"}],
        "docHash":"sha256:...",
        "offchainUri":"s3://bucket/final.pdf",
        "journalSeq":1234,
        "qr":"INS-2025-0000001",
        "signatures":[{"subject":"CCV Nguyen A","certSn":"12AB","algo":"RSA-PSS","time":"2025-09-11T09:12:21Z"}]
    }`)
	res, err := InstrumentIssue(c, payload, true)
	must(err)
	log.Printf("issued: %s", string(res))

	// Example: PutPII (HMAC(CCCD, orgKey) & more)
	pii := []byte(`{"hmacCccd":"a1b2...","maritalStatus":"married"}`)
	must(PutPII(c, "CASE-2025-0001", pii))

	// Example: Verify
	ok, err := InstrumentVerify(c, "INS-2025-0000001", "sha256:...")
	must(err)
	log.Printf("verify: %s", string(ok))
}
