package team

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/e2b-dev/infra/packages/shared/pkg/db"
	"github.com/e2b-dev/infra/packages/shared/pkg/keys"
	"github.com/e2b-dev/infra/packages/shared/pkg/models"
	"github.com/e2b-dev/infra/packages/shared/pkg/models/secret"
	"github.com/e2b-dev/infra/packages/shared/pkg/telemetry"
	"github.com/e2b-dev/infra/packages/shared/pkg/vault"
)

func CreateSecret(ctx context.Context, db *db.DB, secretVault *vault.Client, teamID uuid.UUID, name string, value string, hosts []string) (*models.Secret, string, error) {
	// Create the secret record (only storing metadata, not the actual value)
	secret, err := db.Client.Secret.
		Create().
		SetTeamID(teamID).
		SetName(name).
		SetHosts(hosts).
		Save(ctx)
	if err != nil {
		telemetry.ReportCriticalError(ctx, "error when creating secret", err)
		return nil, "", fmt.Errorf("error when creating secret: %w", err)
	}

	// Insert it into the actual secret vault here
	// TODO: I kinda don't like that the path here is hardcoded like that. Going to be hard to replicate that consistently over the codebase
	if err := secretVault.WriteSecret(ctx, fmt.Sprintf("%s/%s", teamID.String(), secret.ID.String()), value, map[string]any{
		"hosts": hosts,
	}); err != nil {
		telemetry.ReportCriticalError(ctx, "error when writing secret to vault", err)
		return nil, "", fmt.Errorf("error when writing secret to vault: %w", err)
	}

	// Return the secret metadata and the actual value (only returned during creation)
	fullValue := keys.SecretPrefix + value
	return secret, fullValue, nil
}

var ErrSecretNotFound = errors.New("secret not found")

func DeleteSecret(ctx context.Context, db *db.DB, secretVault *vault.Client, teamID uuid.UUID, secretID uuid.UUID) error {
	err := db.Client.Secret.DeleteOneID(secretID).Where(secret.TeamID(teamID)).Exec(ctx)
	if err != nil {
		if models.IsNotFound(err) {
			return ErrSecretNotFound
		}
		return fmt.Errorf("error when deleting secret: %w", err)
	}

	if err := secretVault.DeleteSecret(ctx, fmt.Sprintf("%s/%s", teamID.String(), secretID.String())); err != nil {
		telemetry.ReportCriticalError(ctx, "error when deleting secret from vault", err)
		return fmt.Errorf("error when deleting secret from vault: %w", err)
	}

	return nil
}
