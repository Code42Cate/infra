package team

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/e2b-dev/infra/packages/shared/pkg/db"
	"github.com/e2b-dev/infra/packages/shared/pkg/keys"
	"github.com/e2b-dev/infra/packages/shared/pkg/models"
	"github.com/e2b-dev/infra/packages/shared/pkg/telemetry"
)

func CreateSecret(ctx context.Context, db *db.DB, teamID uuid.UUID, name string, value string, hosts []string) (*models.TeamSecret, string, error) {
	// Generate masked properties from the provided value
	maskedProperties, err := keys.MaskKey(keys.SecretPrefix, value)
	if err != nil {
		telemetry.ReportCriticalError(ctx, "error when masking secret", err)
		return nil, "", fmt.Errorf("error when masking secret: %w", err)
	}

	// Create the secret record (only storing metadata, not the actual value)
	secret, err := db.Client.TeamSecret.
		Create().
		SetTeamID(teamID).
		SetSecretPrefix(maskedProperties.Prefix).
		SetSecretLength(maskedProperties.ValueLength).
		SetSecretMaskPrefix(maskedProperties.MaskedValuePrefix).
		SetSecretMaskSuffix(maskedProperties.MaskedValueSuffix).
		SetName(name).
		SetHosts(hosts).
		Save(ctx)
	if err != nil {
		telemetry.ReportCriticalError(ctx, "error when creating secret", err)
		return nil, "", fmt.Errorf("error when creating secret: %w", err)
	}

	// TODO: Insert it into the actual secret vault here

	// Return the secret metadata and the actual value (only returned during creation)
	fullValue := keys.SecretPrefix + value
	return secret, fullValue, nil
}
