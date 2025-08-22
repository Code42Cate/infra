package mitm

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jellydator/ttlcache/v3"

	"github.com/e2b-dev/infra/packages/shared/pkg/vault"
)

const (
	certCacheExpiration = time.Hour * 25
	certLifetimeDays    = 365
)

type CertificateCache struct {
	cache *ttlcache.Cache[string, string]
	vault vault.VaultBackend
}

func NewCertificateCache(ctx context.Context, vault vault.VaultBackend) (*CertificateCache, error) {
	cache := ttlcache.New(
		ttlcache.WithTTL[string, string](certCacheExpiration),
	)

	cache.OnEviction(func(ctx context.Context, reason ttlcache.EvictionReason, item *ttlcache.Item[string, string]) {

	})

	return &CertificateCache{
		cache: cache,
		vault: vault,
	}, nil
}

func (c *CertificateCache) Items() map[string]*ttlcache.Item[string, string] {
	return c.cache.Items()
}

func (c *CertificateCache) GetCertificate(
	ctx context.Context,
	teamId string,
) (string, error) {

	cachedCert := c.cache.Get(
		teamId,
		ttlcache.WithTTL[string, string](certCacheExpiration),
	)

	if cachedCert != nil {
		return cachedCert.Value(), nil

	}

	// check if its in the vault
	cert, _, certErr := c.vault.GetSecret(ctx, fmt.Sprintf("%s/cert", teamId))

	// we dont really care about the key, just about its existence. if just the cert exists, the mitm will fail
	_, _, keyErr := c.vault.GetSecret(ctx, fmt.Sprintf("%s/key", teamId))

	// TODO: Cert expiry things
	// no cert found, create new one and save it
	// TODO: probably use the same error type
	if errors.Is(certErr, vault.ErrSecretNotFound) || errors.Is(certErr, vault.ErrSecretValueNotFound) ||
		errors.Is(keyErr, vault.ErrSecretNotFound) || errors.Is(keyErr, vault.ErrSecretValueNotFound) {
		newCert, newPriv, err := GenerateRootCert(certLifetimeDays, "e2b.dev")
		if err != nil {
			return "", err
		}
		if err := c.vault.WriteSecret(ctx, fmt.Sprintf("%s/cert", teamId), newCert, nil); err != nil {
			return "", err
		}
		if err := c.vault.WriteSecret(ctx, fmt.Sprintf("%s/key", teamId), newPriv, nil); err != nil {
			return "", err
		}
		c.cache.Set(teamId, newCert, time.Duration(certLifetimeDays)*time.Hour*24)
		return newCert, nil
	} else if keyErr != nil || certErr != nil {
		return cert, fmt.Errorf("failed to get certificate and private key from vault: %w %w", certErr, keyErr)
	}

	c.cache.Set(teamId, cert, time.Duration(certLifetimeDays)*time.Hour*24)

	return cert, nil

}
