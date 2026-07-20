package mtls

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/x509util"
)

// TestCA is an in-memory certificate authority used only by tests to issue
// leaf certificates with a controllable Subject.Organization, so that mTLS
// accept/reject logic (PKI-F-02 and the per-component "verify organization"
// requirements it backs, e.g. DV-F-01, SS-F-01, ST-F-01) can be exercised
// without touching disk or a real Certificate-Authority service.
type TestCA struct {
	cert   *x509.Certificate
	signer crypto.Signer
	pool   *x509.CertPool
}

// NewTestCA generates a self-signed in-memory root certificate for use as
// the trust anchor in mTLS component tests.
func NewTestCA() (*TestCA, error) {
	signer, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"RAM-USB Test CA"}, CommonName: "RAM-USB Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCert, err := x509util.CreateCertificate(template, template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("sign CA certificate: %w", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return &TestCA{cert: caCert, signer: signer, pool: pool}, nil
}

// Pool returns an x509.CertPool trusting only this test CA, suitable for
// tls.Config.ClientCAs or tls.Config.RootCAs in tests.
func (ca *TestCA) Pool() *x509.CertPool {
	return ca.pool
}

// IssueLeaf signs a leaf certificate for the given organization, usable as
// either a client or a server certificate in tests. commonName distinguishes
// certificates within a test; it carries no authorization meaning.
//
// dnsNames overrides the certificate's SAN list; when omitted, it defaults
// to []string{"localhost"} (this package's established convention for
// every existing caller, all of which dial "https://localhost:<port>").
// A test exercising a certificate whose SAN deliberately does NOT cover
// the dialed network address (e.g. pkg/pki's ForceServerName tests,
// proving PKI-F-02's organization check - not hostname/SAN matching -
// is RAM-USB's actual peer-identity guarantee) passes its own dnsNames
// instead, typically []string{organization}.
func (ca *TestCA) IssueLeaf(organization, commonName string, dnsNames ...string) (tls.Certificate, error) {
	signer, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}

	if len(dnsNames) == 0 {
		dnsNames = []string{"localhost"}
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{organization},
			CommonName:   commonName,
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:    dnsNames,
	}

	leafCert, err := x509util.CreateCertificate(template, ca.cert, signer.Public(), ca.signer)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sign leaf certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{leafCert.Raw},
		PrivateKey:  signer,
		Leaf:        leafCert,
	}, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial number: %w", err)
	}
	return serial, nil
}
