package mitm

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/jellydator/ttlcache/v3"

	"github.com/e2b-dev/infra/packages/shared/pkg/vault"
)

const (
	certCacheExpiration = time.Hour * 24       // certCacheExpiration is the expiration time of the certificate cache in hours
	certLifetimeDays    = 3650                 // 10y (max allowed according to SOC2), certLifetimeDays is the lifetime of the certificate in days
	certRotateThreshold = time.Hour * 24 * 365 // certLifetime - certRotateThreshold is the time when the certificate should be rotated, the rotate threshold should be higher than the max *runtime* of a sandbox+cache expiration time (excl. pause/resume)
)

type Certificate struct {
	Cert string
	Key  string
}

type CertificateCache struct {
	cache *ttlcache.Cache[string, Certificate]
	vault vault.VaultBackend
}

func NewCertificateCache(ctx context.Context, vault vault.VaultBackend) (*CertificateCache, error) {
	cache := ttlcache.New(
		ttlcache.WithTTL[string, Certificate](certCacheExpiration),
	)

	cache.OnEviction(func(ctx context.Context, reason ttlcache.EvictionReason, item *ttlcache.Item[string, Certificate]) {
	})

	return &CertificateCache{
		cache: cache,
		vault: vault,
	}, nil
}

func (c *CertificateCache) Items() map[string]*ttlcache.Item[string, Certificate] {
	return c.cache.Items()
}

func (c *CertificateCache) GetCertificate(
	ctx context.Context,
	teamId string,
) (string, string, error) {
	// Check cache first
	cachedCert := c.cache.Get(
		teamId,
		ttlcache.WithTTL[string, Certificate](certCacheExpiration),
	)

	if cachedCert != nil {
		return cachedCert.Value().Cert, cachedCert.Value().Key, nil
	}

	// Try to get certificate from vault
	// TODO: This should be a single get call
	cert, _, certErr := c.vault.GetSecret(ctx, fmt.Sprintf("%s/cert", teamId))
	key, _, keyErr := c.vault.GetSecret(ctx, fmt.Sprintf("%s/key", teamId))

	// Handle errors that aren't "not found", maybe this should be handled as not found anyway
	if (certErr != nil && !errors.Is(certErr, vault.ErrSecretNotFound)) ||
		(keyErr != nil && !errors.Is(keyErr, vault.ErrSecretNotFound)) {
		return "", "", fmt.Errorf("failed to get certificate and private key from vault: %w %w", certErr, keyErr)
	}

	// Certificate doesn't exist - create a new one
	if errors.Is(certErr, vault.ErrSecretNotFound) || errors.Is(keyErr, vault.ErrSecretNotFound) {
		return c.generateAndStoreCertificate(ctx, teamId)
	}

	// Certificate exists but needs rotation
	if shouldRotate(cert, key) {
		return c.generateAndStoreCertificate(ctx, teamId)
	}

	// Certificate is valid - cache and return it
	c.cache.Set(teamId, Certificate{Cert: cert, Key: key}, time.Duration(certLifetimeDays)*time.Hour*24)
	return cert, key, nil
}

func (c *CertificateCache) generateAndStoreCertificate(
	ctx context.Context,
	teamId string,
) (string, string, error) {
	newCert, newPriv, err := GenerateRootCert(certLifetimeDays, "e2b.dev")
	if err != nil {
		return "", "", fmt.Errorf("failed to generate certificate: %w", err)
	}

	if err := c.vault.WriteSecret(ctx, fmt.Sprintf("%s/cert", teamId), newCert, nil); err != nil {
		return "", "", fmt.Errorf("failed to write certificate to vault: %w", err)
	}

	if err := c.vault.WriteSecret(ctx, fmt.Sprintf("%s/key", teamId), newPriv, nil); err != nil {
		return "", "", fmt.Errorf("failed to write private key to vault: %w", err)
	}

	c.cache.Set(teamId, Certificate{
		Cert: newCert,
		Key:  newPriv,
	}, time.Duration(certLifetimeDays)*time.Hour*24)

	return newCert, newPriv, nil
}

// shouldRotate returns true if the certificate cant be parsed or the expiry is within the next 30 days (or in the past)
// If certLifetimeDays is less than or equal to certRotateThreshold, each sandbox will get a new certificate (bad idea)
func shouldRotate(cert string, key string) bool {
	// Parse the PEM encoded certificate
	block, _ := pem.Decode([]byte(cert))
	if block == nil || block.Type != "CERTIFICATE" {
		// If we can't parse the certificate, rotate it to be safe
		return true
	}

	// Parse the certificate
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		// If we can't parse the certificate, rotate it to be safe
		return true
	}

	// Check if the certificate expires within the next 30 days
	thirtyDaysFromNow := time.Now().Add(certRotateThreshold)
	if parsedCert.NotAfter.Before(thirtyDaysFromNow) {
		return true
	}

	// Also check if the certificate is already expired
	if parsedCert.NotAfter.Before(time.Now()) {
		return true
	}

	return false
}
