package api

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/e2b-dev/infra/packages/envd/internal/host"
	"github.com/e2b-dev/infra/packages/envd/internal/logs"
	"github.com/rs/zerolog"
)

func (a *API) PostInit(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	operationID := logs.AssignOperationID()
	logger := a.logger.With().Str(string(logs.OperationIDKey), operationID).Logger()

	if r.Body != nil {
		var initRequest PostInitJSONBody

		err := json.NewDecoder(r.Body).Decode(&initRequest)
		if err != nil && err != io.EOF {
			logger.Error().Msgf("Failed to decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if initRequest.EnvVars != nil {
			logger.Debug().Msg(fmt.Sprintf("Setting %d env vars", len(*initRequest.EnvVars)))

			for key, value := range *initRequest.EnvVars {
				logger.Debug().Msgf("Setting env var for %s", key)
				a.envVars.Store(key, value)
			}
		}

		if initRequest.AccessToken != nil {
			if a.accessToken != nil && *initRequest.AccessToken != *a.accessToken {
				logger.Error().Msg("Access token is already set and cannot be changed")
				w.WriteHeader(http.StatusConflict)
				return
			}

			logger.Debug().Msg("Setting access token")
			a.accessToken = initRequest.AccessToken
		}

		if initRequest.RootCertificate != nil {
			logger.Info().Msg(*initRequest.RootCertificate)
			if err := installCertificate(*initRequest.RootCertificate, logger); err != nil {
				logger.Error().Msgf("Failed to install certificate: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			logger.Debug().Msg("Root certificate installed successfully")
		}

	}

	logger.Debug().Msg("Syncing host")

	go func() {
		err := host.SyncClock()
		if err != nil {
			logger.Error().Msgf("Failed to sync clock: %v", err)
		} else {
			logger.Trace().Msg("Clock synced")
		}
	}()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		host.PollForMMDSOpts(ctx, a.mmdsChan, a.envVars)
	}()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "")

	w.WriteHeader(http.StatusNoContent)
}

// installCertificate installs the provided certificate into the trusted certificate store
// this is basically like running update-ca-certificates, but much faster
func installCertificate(certificate string, logger zerolog.Logger) error {

	certData := []byte(certificate)
	sourceCert := "/usr/local/share/ca-certificates/e2b.crt"
	certsDir := "/etc/ssl/certs"
	pemLink := filepath.Join(certsDir, "e2b.pem")
	bundleFile := filepath.Join(certsDir, "ca-certificates.crt")

	// Write the certificate file
	if err := os.WriteFile(sourceCert, certData, 0o644); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	// 1. Create symlink to the certificate
	os.Remove(pemLink) // Remove if exists
	if err := os.Symlink(sourceCert, pemLink); err != nil {
		return fmt.Errorf("failed to create PEM symlink: %w", err)
	}

	// 2. Append to the certificate bundle
	// Ensure trailing newline
	bundleData := certData
	if len(bundleData) > 0 && bundleData[len(bundleData)-1] != '\n' {
		bundleData = append(bundleData, '\n')
	}

	f, err := os.OpenFile(bundleFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open bundle file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(bundleData); err != nil {
		return fmt.Errorf("failed to write to bundle: %w", err)
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
