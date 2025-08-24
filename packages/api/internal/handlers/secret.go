package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/e2b-dev/infra/packages/api/internal/api"
	"github.com/e2b-dev/infra/packages/api/internal/secrets"
	"github.com/e2b-dev/infra/packages/api/internal/utils"
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

	if body.Label == "" {
		a.sendAPIStoreError(c, http.StatusBadRequest, "Label cannot be empty")
		return
	}

	// arbitrary limit
	if len(body.Label) > 256 {
		a.sendAPIStoreError(c, http.StatusBadRequest, fmt.Sprintf("Label cannot exceed 256 characters (got %d)", len(body.Label)))
		return
	}

	// arbitrary limit
	if len(body.Description) > 1024 {
		a.sendAPIStoreError(c, http.StatusBadRequest, fmt.Sprintf("Description cannot exceed 1024 characters (got %d)", len(body.Description)))
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
		if err := validateHostname(host); err != nil {
			a.sendAPIStoreError(c, http.StatusBadRequest, err.Error())
			return
		}
	}

	secret, fullValue, err := secrets.CreateSecret(ctx, a.db, a.secretVault, teamID, body.Value, body.Label, body.Description, body.Allowlist)
	if err != nil {
		a.sendAPIStoreError(c, http.StatusInternalServerError, fmt.Sprintf("Error when creating team secret: %s", err))

		telemetry.ReportCriticalError(ctx, "error when creating team secret", err)

		return
	}

	telemetry.ReportEvent(ctx, "Created secret")

	_, analyticsSpan := a.Tracer.Start(ctx, "analytics")
	a.posthog.IdentifyAnalyticsTeam(teamID.String(), a.GetTeamInfo(c).Team.Name)
	properties := a.posthog.GetPackageToPosthogProperties(&c.Request.Header)
	a.posthog.CreateAnalyticsTeamEvent(teamID.String(), "created_secret",
		properties.
			Set("secret_id", secret.ID.String()).
			Set("allowlist", body.Allowlist), // probably interesting to track to see what type of secrets users are trying to protect
	)
	analyticsSpan.End()

	telemetry.ReportEvent(ctx, "Created analytics event")

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

	if err := secrets.DeleteSecret(ctx, a.db, a.secretVault, teamID, secretIDParsed); err != nil {
		if errors.Is(err, secrets.ErrSecretNotFound) {
			c.String(http.StatusNotFound, "id not found")
			return
		}
		a.sendAPIStoreError(c, http.StatusInternalServerError, fmt.Sprintf("Error when deleting secret: %s", err))

		telemetry.ReportCriticalError(ctx, "error when deleting secret", err)
		return
	}

	c.Status(http.StatusNoContent)
}

// ValidateHostname validates a hostname with wildcard support
// Allowed: example.com, *.example.com, something.*.example.com, *, *.*
// Not allowed: URLs with schemes, paths, or invalid characters
func validateHostname(hostname string) error {
	// First check if its a valid go glob pattern
	// match continues scanning to the end of the pattern even after a mismatch, so by matching "" we can check if the host is a valid pattern
	// https://go-review.googlesource.com/c/go/+/264397
	if _, err := filepath.Match(hostname, ""); err != nil {
		return fmt.Errorf("invalid hostname pattern: %w", err)
	}

	// Most will be a wildcard anyway so we can skip the rest of the checks
	if hostname == "*" {
		return nil
	}

	// Check for common URL indicators that make it invalid
	if strings.Contains(hostname, "://") ||
		strings.Contains(hostname, "/") ||
		strings.HasPrefix(hostname, "http") {
		return fmt.Errorf("invalid hostname pattern: %s, cannot contain schemes (https/http) or paths (/api/, /v2/)", hostname)
	}

	// Regex pattern for hostname validation with wildcards
	// - Each label can be alphanumeric with hyphens (not starting/ending with hyphen)
	// - OR it can be a wildcard (*)
	// - Labels are separated by dots
	pattern := `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?|\*)(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?|\.\*)*$`

	if matched, err := regexp.MatchString(pattern, hostname); err != nil || !matched {
		return fmt.Errorf("invalid hostname pattern: %s", hostname)
	}

	return nil
}
