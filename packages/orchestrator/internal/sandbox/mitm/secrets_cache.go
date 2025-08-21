package mitm

import (
	"context"
	"fmt"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"go.uber.org/zap"

	"github.com/e2b-dev/infra/packages/shared/pkg/vault"
)

const (
	secretExpiration = time.Minute * 5
)

type SecretData struct {
	Value    string
	Metadata map[string]interface{}
}

type SecretsCache struct {
	cache       *ttlcache.Cache[string, *SecretData]
	vaultClient *vault.Client
}

func NewSecretsCache(ctx context.Context, vaultClient *vault.Client) (*SecretsCache, error) {
	cache := ttlcache.New(
		ttlcache.WithTTL[string, *SecretData](secretExpiration),
	)

	go cache.Start()

	return &SecretsCache{
		cache:       cache,
		vaultClient: vaultClient,
	}, nil
}

func (s *SecretsCache) GetSecret(ctx context.Context, teamID string, uuid string) (string, map[string]interface{}, error) {
	cacheKey := fmt.Sprintf("%s/%s", teamID, uuid)

	cachedSecret := s.cache.Get(cacheKey)

	if cachedSecret != nil {
		secretData := cachedSecret.Value()
		return secretData.Value, secretData.Metadata, nil
	}

	start := time.Now()
	secret, metadata, err := s.vaultClient.GetSecret(ctx, cacheKey)
	if err != nil {
		return "", nil, err
	}

	secretData := &SecretData{
		Value:    secret,
		Metadata: metadata,
	}

	s.cache.Set(cacheKey, secretData, secretExpiration)

	zap.L().Info("Retrieved secret from Vault",
		zap.String("uuid", uuid),
		zap.Duration("duration", time.Since(start)),
	)

	return secret, metadata, nil
}

func (s *SecretsCache) Stop() {
	s.cache.Stop()
}
