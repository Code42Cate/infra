package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

func GenerateRootCert(ttlDays int, commonName string) (certPEM string, keyPEM string, err error) {

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	notBefore := time.Now().Add(-time.Hour)
	notAfter := time.Now().AddDate(ttlDays/365, 0, 0)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", err
	}

	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, priv.Public(), priv)
	if err != nil {
		return "", "", err
	}

	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	certPEM = string(pem.EncodeToMemory(certBlock))

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}

	keyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	}
	keyPEM = string(pem.EncodeToMemory(keyBlock))

	return certPEM, keyPEM, nil
}
