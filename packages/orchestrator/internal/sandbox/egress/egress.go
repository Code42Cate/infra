package egress

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/elazarl/goproxy"
	"go.uber.org/zap"

	"github.com/e2b-dev/infra/packages/orchestrator/internal/sandbox/network"
	"github.com/e2b-dev/infra/packages/shared/pkg/vault"
)

type SecretProxy struct {
	httpServer  *http.Server
	httpsLn     net.Listener
	stopChan    chan struct{}
	stoppedChan chan struct{}
}

func NewSecretEgressProxy(s *network.Slot, teamID string, sandboxID string, rootCertificate string, rootCertificateKey string, vaultClient *vault.Client) *SecretProxy {
	m := &SecretProxy{
		stopChan:    make(chan struct{}),
		stoppedChan: make(chan struct{}),
	}

	ctx := context.Background()

	proxy := goproxy.NewProxyHttpServer()

	// This will be true for the build system
	if vaultClient == nil {
		var err error
		vaultClient, err = vault.NewClientFromEnv(ctx)
		if err != nil {
			zap.L().Error("Failed to create Vault client", zap.Error(err))
			return nil
		}
	}

	secretsCache, err := NewSecretsCache(ctx, vaultClient)
	if err != nil {
		zap.L().Error("Failed to create secrets cache", zap.Error(err))
		return nil
	}

	zap.L().Info("Starting MITM proxy",
		zap.String("teamID", teamID),
		zap.String("sandboxID", sandboxID),
		zap.Uint("httpPort", s.MitmProxyHTTPPort()),
		zap.Uint("httpsPort", s.MitmProxyHTTPSPort()))

	caCert, err := loadCACertificate(rootCertificate, rootCertificateKey)
	if err != nil {
		zap.L().Error("Failed to load CA certificate", zap.Error(err))
		return nil
	}

	configureProxy(proxy, caCert, secretsCache, teamID, sandboxID)

	if err := m.startServers(s, proxy); err != nil {
		zap.L().Error("Failed to start servers", zap.Error(err))
		return m
	}

	return m
}

func (m *SecretProxy) startServers(s *network.Slot, proxy *goproxy.ProxyHttpServer) error {
	// Setup and start HTTP server
	m.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.MitmProxyHTTPPort()),
		Handler: proxy,
	}

	go func() {
		if err := m.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			zap.L().Error("HTTP server error", zap.Error(err))
		}
	}()

	// Setup HTTPS listener
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.MitmProxyHTTPSPort()))
	if err != nil {
		return fmt.Errorf("error listening for https connections: %w", err)
	}
	m.httpsLn = ln

	// Start HTTPS handler
	go m.runHTTPSHandler(ln, proxy)

	return nil
}

func (m *SecretProxy) runHTTPSHandler(ln net.Listener, proxy *goproxy.ProxyHttpServer) {
	defer close(m.stoppedChan)

	for {
		select {
		case <-m.stopChan:
			return
		default:
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-m.stopChan:
					return
				default:
					zap.L().Error("Error accepting new connection", zap.Error(err))
					continue
				}
			}
			go handleNewTLSConn(c, proxy)
		}
	}
}

// Close gracefully shuts down the MITM proxy
func (m *SecretProxy) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}

	// Signal the HTTPS handler to stop
	close(m.stopChan)

	// Shutdown HTTP server with context
	if m.httpServer != nil {
		if err := m.httpServer.Shutdown(ctx); err != nil {
			zap.L().Error("Error shutting down HTTP server", zap.Error(err))
		}
	}

	// Close HTTPS listener
	if m.httpsLn != nil {
		if err := m.httpsLn.Close(); err != nil {
			zap.L().Error("Error closing HTTPS listener", zap.Error(err))
		}
	}

	// Wait for HTTPS handler to stop
	select {
	case <-m.stoppedChan:
	case <-ctx.Done():
		zap.L().Warn("Timeout waiting for HTTPS handler to stop")
	}

	return nil
}
