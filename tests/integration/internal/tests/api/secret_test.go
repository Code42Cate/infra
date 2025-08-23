package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/e2b-dev/infra/packages/shared/pkg/keys"
	"github.com/e2b-dev/infra/tests/integration/internal/api"
	"github.com/e2b-dev/infra/tests/integration/internal/setup"
)

func TestCreateSecret(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	c := setup.GetAPIClient()

	t.Run("succeeds with valid allowlist", func(t *testing.T) {
		// Create the secret
		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret",
			Value:       "secret-value-123",
			Description: "Test secret description",
			Allowlist:   []string{"*.example.com", "api.test.com"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusCreated, resp.StatusCode())
		assert.Equal(t, "test-secret", resp.JSON201.Label)
		assert.Equal(t, "Test secret description", resp.JSON201.Description)
		assert.NotEmpty(t, resp.JSON201.Value)
		assert.Contains(t, resp.JSON201.Value, keys.SecretPrefix)
		assert.Equal(t, []string{"*.example.com", "api.test.com"}, resp.JSON201.Allowlist)
	})

	t.Run("succeeds with empty allowlist defaults to wildcard", func(t *testing.T) {
		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret-empty-allowlist",
			Value:       "secret-value-456",
			Description: "Test with empty allowlist",
			Allowlist:   []string{},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusCreated, resp.StatusCode())
		assert.Equal(t, []string{"*"}, resp.JSON201.Allowlist)
	})

	t.Run("succeeds with wildcard patterns", func(t *testing.T) {
		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret-wildcards",
			Value:       "secret-value-789",
			Description: "Test with various wildcard patterns",
			Allowlist:   []string{"*", "*.domain.com"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusCreated, resp.StatusCode())
		assert.Equal(t, []string{"*", "*.domain.com"}, resp.JSON201.Allowlist)
	})

	t.Run("fails with glob question mark pattern", func(t *testing.T) {
		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret-glob-question",
			Value:       "secret-value",
			Description: "Test with glob question mark",
			Allowlist:   []string{"api-?.test.com"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())
		assert.Contains(t, string(resp.Body), "invalid hostname pattern")
	})

	t.Run("fails with glob bracket pattern", func(t *testing.T) {
		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret-glob-bracket",
			Value:       "secret-value",
			Description: "Test with glob bracket pattern",
			Allowlist:   []string{"service[1-3].example.com"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())
		assert.Contains(t, string(resp.Body), "invalid hostname pattern")
	})

	t.Run("fails with too many hosts in allowlist", func(t *testing.T) {
		tooManyHosts := make([]string, 11)
		for i := range 11 {
			tooManyHosts[i] = fmt.Sprintf("host%d.example.com", i)
		}

		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret-too-many-hosts",
			Value:       "secret-value",
			Description: "Test with too many hosts",
			Allowlist:   tooManyHosts,
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())
		assert.Contains(t, string(resp.Body), "Too many hosts in allowlist")
	})

	t.Run("fails with invalid host pattern", func(t *testing.T) {
		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret-invalid-pattern",
			Value:       "secret-value",
			Description: "Test with invalid pattern",
			Allowlist:   []string{"[invalid-pattern"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())
		assert.Contains(t, string(resp.Body), "invalid hostname pattern")
	})

	t.Run("fails with invalid bracket pattern", func(t *testing.T) {
		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret-invalid-brackets",
			Value:       "secret-value",
			Description: "Test with unclosed brackets",
			Allowlist:   []string{"host[1-3.example.com"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())
		assert.Contains(t, string(resp.Body), "invalid hostname pattern")
	})

	t.Run("fails with backslash in pattern", func(t *testing.T) {
		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret-backslash",
			Value:       "secret-value",
			Description: "Test with backslash",
			Allowlist:   []string{"host\\example.com"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())
		assert.Contains(t, string(resp.Body), "invalid hostname pattern")
	})

	t.Run("fails with URL scheme https", func(t *testing.T) {
		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret-https-scheme",
			Value:       "secret-value",
			Description: "Test with https scheme",
			Allowlist:   []string{"https://example.com"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())
		assert.Contains(t, string(resp.Body), "cannot contain schemes")
	})

	t.Run("fails with URL scheme http", func(t *testing.T) {
		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret-http-scheme",
			Value:       "secret-value",
			Description: "Test with http scheme",
			Allowlist:   []string{"http://example.com"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())
		assert.Contains(t, string(resp.Body), "cannot contain schemes")
	})

	t.Run("fails with URL path", func(t *testing.T) {
		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret-url-path",
			Value:       "secret-value",
			Description: "Test with URL path",
			Allowlist:   []string{"example.com/api"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())
		assert.Contains(t, string(resp.Body), "cannot contain schemes")
	})

	t.Run("fails with port number", func(t *testing.T) {
		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret-port",
			Value:       "secret-value",
			Description: "Test with port number",
			Allowlist:   []string{"example.com:8080"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())
		assert.Contains(t, string(resp.Body), "invalid hostname pattern")
	})

	t.Run("fails with invalid characters", func(t *testing.T) {
		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret-invalid-chars",
			Value:       "secret-value",
			Description: "Test with invalid characters",
			Allowlist:   []string{"example!.com"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())
		assert.Contains(t, string(resp.Body), "invalid hostname pattern")
	})

	t.Run("fails with spaces", func(t *testing.T) {
		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret-spaces",
			Value:       "secret-value",
			Description: "Test with spaces",
			Allowlist:   []string{"example .com"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())
		assert.Contains(t, string(resp.Body), "invalid hostname pattern")
	})

	t.Run("succeeds with valid hostnames", func(t *testing.T) {
		validHostnames := []string{
			"example.com",
			"sub.example.com",
			"sub-domain.example.com",
			"example123.com",
			"123-example.com",
			"a.b.c.d.example.com",
		}

		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret-valid-hostnames",
			Value:       "secret-value",
			Description: "Test with valid hostnames",
			Allowlist:   validHostnames,
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusCreated, resp.StatusCode())
		assert.Equal(t, validHostnames, resp.JSON201.Allowlist)
	})

	t.Run("succeeds with valid wildcard patterns", func(t *testing.T) {
		validWildcards := []string{
			"*",
			"*.example.com",
			"*.*.example.com",
			"api.*.example.com",
			"*.*",
		}

		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret-valid-wildcards",
			Value:       "secret-value",
			Description: "Test with valid wildcard patterns",
			Allowlist:   validWildcards,
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusCreated, resp.StatusCode())
		assert.Equal(t, validWildcards, resp.JSON201.Allowlist)
	})

	t.Run("fails with hostname starting with hyphen", func(t *testing.T) {
		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret-hyphen-start",
			Value:       "secret-value",
			Description: "Test with hostname starting with hyphen",
			Allowlist:   []string{"-example.com"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())
		assert.Contains(t, string(resp.Body), "invalid hostname pattern")
	})

	t.Run("fails with hostname ending with hyphen", func(t *testing.T) {
		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-secret-hyphen-end",
			Value:       "secret-value",
			Description: "Test with hostname ending with hyphen",
			Allowlist:   []string{"example-.com"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())
		assert.Contains(t, string(resp.Body), "invalid hostname pattern")
	})

	t.Run("fails with empty label", func(t *testing.T) {
		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "",
			Value:       "secret-value",
			Description: "Test with empty label",
			Allowlist:   []string{"*"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())
	})

	t.Run("fails with label exceeding 256 characters", func(t *testing.T) {
		longLabel := ""
		for i := 0; i < 257; i++ {
			longLabel += "a"
		}

		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       longLabel,
			Value:       "secret-value",
			Description: "Test with long label",
			Allowlist:   []string{"*"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())
	})

	t.Run("succeeds with label exactly 256 characters", func(t *testing.T) {
		maxLabel := ""
		for i := 0; i < 256; i++ {
			maxLabel += "a"
		}

		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       maxLabel,
			Value:       "secret-value",
			Description: "Test with max label",
			Allowlist:   []string{"*"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusCreated, resp.StatusCode())
		assert.Equal(t, maxLabel, resp.JSON201.Label)
	})

	t.Run("fails with description exceeding 1024 characters", func(t *testing.T) {
		longDescription := ""
		for i := 0; i < 1025; i++ {
			longDescription += "a"
		}

		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-long-description",
			Value:       "secret-value",
			Description: longDescription,
			Allowlist:   []string{"*"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())
	})

	t.Run("succeeds with description exactly 1024 characters", func(t *testing.T) {
		maxDescription := ""
		for i := 0; i < 1024; i++ {
			maxDescription += "a"
		}

		resp, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-max-description",
			Value:       "secret-value",
			Description: maxDescription,
			Allowlist:   []string{"*"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, http.StatusCreated, resp.StatusCode())
		assert.Equal(t, maxDescription, resp.JSON201.Description)
	})

}

func TestDeleteSecret(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	c := setup.GetAPIClient()

	t.Run("succeeds", func(t *testing.T) {
		// Create the secret
		respC, err := c.PostSecretsWithResponse(ctx, api.PostSecretsJSONRequestBody{
			Label:       "test-delete",
			Value:       "secret-to-delete",
			Description: "Will be deleted",
			Allowlist:   []string{"*"},
		}, setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, http.StatusCreated, respC.StatusCode())

		// Delete the secret
		respD, err := c.DeleteSecretsSecretIDWithResponse(ctx, respC.JSON201.Id.String(), setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, http.StatusNoContent, respD.StatusCode())
	})

	t.Run("id does not exist", func(t *testing.T) {
		respD, err := c.DeleteSecretsSecretIDWithResponse(ctx, uuid.New().String(), setup.WithAPIKey())
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, http.StatusNotFound, respD.StatusCode())
	})
}

func TestListSecrets(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	c := setup.GetAPIClient()

	resp, err := c.GetSecretsWithResponse(ctx, setup.WithAPIKey())
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, http.StatusOK, resp.StatusCode())
	assert.NotNil(t, resp.JSON200)
}
