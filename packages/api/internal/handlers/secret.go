package handlers

import (
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/e2b-dev/infra/packages/api/internal/api"
	"github.com/e2b-dev/infra/packages/api/internal/team"
	"github.com/e2b-dev/infra/packages/api/internal/utils"
	"github.com/e2b-dev/infra/packages/shared/pkg/models"
	"github.com/e2b-dev/infra/packages/shared/pkg/models/secret"
	"github.com/e2b-dev/infra/packages/shared/pkg/telemetry"
)

func (a *APIStore) GetSecrets(c *gin.Context) {
	ctx := c.Request.Context()

	teamID := a.GetTeamInfo(c).Team.ID

	secretsDB, err := a.db.Client.Secret.
		Query().
		Where(secret.TeamID(teamID)).
		All(ctx)
	if err != nil {
		zap.L().Warn("error when getting team secrets", zap.Error(err))
		c.String(http.StatusInternalServerError, "Error when getting team secrets")

		return
	}

	secrets := make([]api.Secret, len(secretsDB))
	for i, secret := range secretsDB {
		secrets[i] = api.Secret{
			Id:          secret.ID,
			Label:       secret.Label,
			Description: &secret.Description,
			Allowlist:   secret.Allowlist,
			CreatedAt:   secret.CreatedAt,
		}
	}
	c.JSON(http.StatusOK, secrets)
}

func (a *APIStore) PostSecrets(c *gin.Context) {
	ctx := c.Request.Context()

	teamID := a.GetTeamInfo(c).Team.ID

	body, err := utils.ParseBody[api.NewSecret](ctx, c)
	if err != nil {
		a.sendAPIStoreError(c, http.StatusBadRequest, fmt.Sprintf("Error when parsing request: %s", err))

		telemetry.ReportCriticalError(ctx, "error when parsing request", err)

		return
	}

	// There should be a limit to how many hosts can be added to a secret. Realistically its going to be 0 or 1 in most cases, 10 is already a lot. Adjust as needed
	maxHostsCount := 10
	if len(body.Allowlist) > maxHostsCount {
		a.sendAPIStoreError(c, http.StatusBadRequest, fmt.Sprintf("Too many hosts in allowlist (%d), only %d allowed", len(body.Allowlist), maxHostsCount))
		return
	}

	// default value, should be done by the SDK/Dashboard/CLI but just in case
	if len(body.Allowlist) == 0 {
		body.Allowlist = []string{"*"}
	}

	for _, host := range body.Allowlist {
		// match continues scanning to the end of the pattern even after a mismatch, so by matching "" we can check if the host is a valid pattern
		// https://go-review.googlesource.com/c/go/+/264397
		if _, err := filepath.Match(host, ""); err != nil {
			a.sendAPIStoreError(c, http.StatusBadRequest, fmt.Sprintf("Invalid host pattern: %s", host))
			return
		}
	}

	secret, fullValue, err := team.CreateSecret(ctx, a.db, a.secretVault, teamID, body.Value, body.Label, body.Description, body.Allowlist)
	if err != nil {
		a.sendAPIStoreError(c, http.StatusInternalServerError, fmt.Sprintf("Error when creating team secret: %s", err))

		telemetry.ReportCriticalError(ctx, "error when creating team secret", err)

		return
	}

	c.JSON(http.StatusCreated, api.CreatedSecret{
		Id:          secret.ID,
		Label:       secret.Label,
		Description: secret.Description,
		Value:       fullValue, // Only returned on creation
		Allowlist:   secret.Allowlist,
		CreatedAt:   secret.CreatedAt,
	})
}

func (a *APIStore) DeleteSecretsSecretID(c *gin.Context, secretID string) {
	ctx := c.Request.Context()
	teamID := a.GetTeamInfo(c).Team.ID

	secretIDParsed, err := uuid.Parse(secretID)
	if err != nil {
		a.sendAPIStoreError(c, http.StatusBadRequest, fmt.Sprintf("Error when parsing secret ID: %s", err))

		telemetry.ReportCriticalError(ctx, "error when parsing secret ID", err)
		return
	}

	if err := team.DeleteSecret(ctx, a.db, a.secretVault, teamID, secretIDParsed); err != nil {
		if models.IsNotFound(err) {
			c.String(http.StatusNotFound, "id not found")
			return
		} else if err != nil {
			a.sendAPIStoreError(c, http.StatusInternalServerError, fmt.Sprintf("Error when deleting secret: %s", err))

			telemetry.ReportCriticalError(ctx, "error when deleting secret", err)
			return
		}
	}

	c.Status(http.StatusNoContent)
}
