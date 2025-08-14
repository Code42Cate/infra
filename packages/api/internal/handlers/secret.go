package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/e2b-dev/infra/packages/api/internal/api"
	"github.com/e2b-dev/infra/packages/api/internal/team"
	"github.com/e2b-dev/infra/packages/api/internal/utils"
	"github.com/e2b-dev/infra/packages/shared/pkg/models"
	"github.com/e2b-dev/infra/packages/shared/pkg/models/teamsecret"
	"github.com/e2b-dev/infra/packages/shared/pkg/telemetry"
)

func (a *APIStore) GetSecrets(c *gin.Context) {
	ctx := c.Request.Context()

	teamID := a.GetTeamInfo(c).Team.ID

	secretsDB, err := a.db.Client.TeamSecret.
		Query().
		Where(teamsecret.TeamID(teamID)).
		All(ctx)
	if err != nil {
		zap.L().Warn("error when getting team secrets", zap.Error(err))
		c.String(http.StatusInternalServerError, "Error when getting team secrets")

		return
	}

	teamSecrets := make([]api.TeamSecret, len(secretsDB))
	for i, secret := range secretsDB {
		teamSecrets[i] = api.TeamSecret{
			Id:   secret.ID,
			Name: secret.Name,
			Mask: api.IdentifierMaskingDetails{
				Prefix:            secret.SecretPrefix,
				ValueLength:       secret.SecretLength,
				MaskedValuePrefix: secret.SecretMaskPrefix,
				MaskedValueSuffix: secret.SecretMaskSuffix,
			},
			Hosts:     secret.Hosts,
			CreatedAt: secret.CreatedAt,
		}
	}
	c.JSON(http.StatusOK, teamSecrets)
}

func (a *APIStore) PostSecrets(c *gin.Context) {
	ctx := c.Request.Context()

	teamID := a.GetTeamInfo(c).Team.ID

	body, err := utils.ParseBody[api.NewTeamSecret](ctx, c)
	if err != nil {
		a.sendAPIStoreError(c, http.StatusBadRequest, fmt.Sprintf("Error when parsing request: %s", err))

		telemetry.ReportCriticalError(ctx, "error when parsing request", err)

		return
	}

	secret, fullValue, err := team.CreateSecret(ctx, a.db, teamID, body.Name, body.Value, body.Hosts)
	if err != nil {
		a.sendAPIStoreError(c, http.StatusInternalServerError, fmt.Sprintf("Error when creating team secret: %s", err))

		telemetry.ReportCriticalError(ctx, "error when creating team secret", err)

		return
	}

	c.JSON(http.StatusCreated, api.CreatedTeamSecret{
		Id:    secret.ID,
		Name:  secret.Name,
		Value: fullValue, // Only returned on creation
		Mask: api.IdentifierMaskingDetails{
			Prefix:            secret.SecretPrefix,
			ValueLength:       secret.SecretLength,
			MaskedValuePrefix: secret.SecretMaskPrefix,
			MaskedValueSuffix: secret.SecretMaskSuffix,
		},
		Hosts:     secret.Hosts,
		CreatedAt: secret.CreatedAt,
	})
}

func (a *APIStore) DeleteSecretsSecretID(c *gin.Context, secretID string) {
	ctx := c.Request.Context()

	secretIDParsed, err := uuid.Parse(secretID)
	if err != nil {
		a.sendAPIStoreError(c, http.StatusBadRequest, fmt.Sprintf("Error when parsing secret ID: %s", err))

		telemetry.ReportCriticalError(ctx, "error when parsing secret ID", err)
		return
	}

	err = a.db.Client.TeamSecret.DeleteOneID(secretIDParsed).Exec(ctx)
	if models.IsNotFound(err) {
		c.String(http.StatusNotFound, "id not found")
		return
	} else if err != nil {
		a.sendAPIStoreError(c, http.StatusInternalServerError, fmt.Sprintf("Error when deleting secret: %s", err))

		telemetry.ReportCriticalError(ctx, "error when deleting secret", err)
		return
	}

	c.Status(http.StatusNoContent)
}
