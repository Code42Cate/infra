package mitm

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

type MITMProxy struct {
	httpServer  *http.Server
	httpsLn     net.Listener
	stopChan    chan struct{}
	stoppedChan chan struct{}
}

func NewMITMProxy(s *network.Slot, teamID string, sandboxID string) *MITMProxy {
	m := &MITMProxy{
		stopChan:    make(chan struct{}),
		stoppedChan: make(chan struct{}),
	}

	ctx := context.Background()

	proxy := goproxy.NewProxyHttpServer()

	// if the vault client cant be created, we fail and sandbox doesn't start. Maybe it would make sense to ignore it and continue without it
	// this would mean secret injection won't properly work but at least the sandbox will start
	vaultClient, err := vault.NewClientFromEnv(ctx)
	if err != nil {
		zap.L().Error("Failed to create Vault client", zap.Error(err))
		return nil
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

	// At this point we know that the certificate exists. It would be nicer if we wouldnt have to make network requests to vault here but would get the certificate passed in the constructor
	// No point in using the cache as we will only need the certificate and key once
	priv, _, err := vaultClient.GetSecret(ctx, fmt.Sprintf("%s/key", teamID))
	if err != nil {
		zap.L().Error("Failed to get team root certificate key", zap.Error(err))
		return nil
	}
	cert, _, err := vaultClient.GetSecret(ctx, fmt.Sprintf("%s/cert", teamID))
	if err != nil {
		zap.L().Error("Failed to get team root certificate", zap.Error(err))
		return nil
	}

	caCert, err := loadCACertificate(cert, priv)
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

func (m *MITMProxy) startServers(s *network.Slot, proxy *goproxy.ProxyHttpServer) error {
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

func (m *MITMProxy) runHTTPSHandler(ln net.Listener, proxy *goproxy.ProxyHttpServer) {
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
func (m *MITMProxy) Close(ctx context.Context) error {
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
