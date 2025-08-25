package api

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
)

// installCertificate installs the provided certificate into the trusted certificate store
// this is basically like running update-ca-certificates, but much faster
// TODO: If you rotate certs, old ones will still be trusted until they expire
func installCertificate(certificate string, logger zerolog.Logger) error {
	certData := []byte(certificate)
	sourceCert := "/usr/local/share/ca-certificates/e2b.crt"
	certsDir := "/etc/ssl/certs"
	pemLink := filepath.Join(certsDir, "e2b.pem")
	bundleFile := filepath.Join(certsDir, "ca-certificates.crt")

	// Wrap certificate with comment markers
	wrappedCert := []byte("#E2B_CERT_START\n" + certificate + "\n#E2B_CERT_END")

	// Write the certificate file
	if err := os.WriteFile(sourceCert, wrappedCert, 0o644); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	// 1. Create symlink to the certificate
	os.Remove(pemLink) // Remove if exists
	if err := os.Symlink(sourceCert, pemLink); err != nil {
		return fmt.Errorf("failed to create PEM symlink: %w", err)
	}

	// 2. Append to the certificate bundle if not already present
	// Check if the certificate already exists in the bundle
	existingBundle, err := os.ReadFile(bundleFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read bundle file: %w", err)
	}

	// Check if the wrapped certificate is already in the bundle
	if !bytes.Contains(existingBundle, wrappedCert) {
		// Use wrapped certificate for bundle
		bundleData := wrappedCert
		// Ensure trailing newline
		if len(bundleData) > 0 && bundleData[len(bundleData)-1] != '\n' {
			bundleData = append(bundleData, '\n')
		}

		f, err := os.OpenFile(bundleFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			return fmt.Errorf("failed to open bundle file: %w", err)
		}
		defer f.Close()

		if _, err := f.Write(bundleData); err != nil {
			return fmt.Errorf("failed to write to bundle: %w", err)
		}
		logger.Debug().Msg("Certificate appended to bundle")
	} else {
		logger.Debug().Msg("Certificate already exists in bundle, skipping append")
	}

	// 3. Create hash symlink for OpenSSL to make faster lookups
	block, _ := pem.Decode(certData)
	// Not super critical if this should fail for some reason, MITM will still work
	if block == nil {
		logger.Debug().Msg("Failed to decode PEM block from certificate")
		return nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		// This creates hash like 607eca47.0 -> e2b.pem
		hash := sha1.Sum(cert.RawSubject)
		hashValue := binary.LittleEndian.Uint32(hash[:4])
		hashLink := filepath.Join(certsDir, fmt.Sprintf("%08x.0", hashValue))

		os.Remove(hashLink) // Remove if exists
		if err := os.Symlink("e2b.pem", hashLink); err != nil {
			logger.Debug().Msgf("Failed to create hash symlink: %v", err)
		}
	} else {
		logger.Debug().Msgf("Failed to parse certificate: %v", err)
	}

	return nil
}
