package egress

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/inconshreveable/go-vhost"
	"go.uber.org/zap"

	"github.com/e2b-dev/infra/packages/orchestrator/internal/sandbox/network"
)

type BypassProxy struct {
	httpLn      net.Listener
	httpsLn     net.Listener
	stopChan    chan struct{}
	stoppedChan chan struct{}
}

// NewBypassProxy creates a proxy that bypasses inspection and just forwards traffic
func NewBypassProxy(s *network.Slot, teamID string, sandboxID string) *BypassProxy {
	m := &BypassProxy{
		stopChan:    make(chan struct{}),
		stoppedChan: make(chan struct{}),
	}

	zap.L().Info("Starting bypass proxy",
		zap.String("teamID", teamID),
		zap.String("sandboxID", sandboxID),
		zap.Uint("httpPort", s.MitmProxyHTTPPort()),
		zap.Uint("httpsPort", s.MitmProxyHTTPSPort()))

	if err := m.startServers(s); err != nil {
		zap.L().Error("Failed to start bypass servers", zap.Error(err))
		return m
	}

	return m
}

func (m *BypassProxy) startServers(s *network.Slot) error {
	// Setup HTTP listener
	httpLn, err := net.Listen("tcp", fmt.Sprintf(":%d", s.MitmProxyHTTPPort()))
	if err != nil {
		return fmt.Errorf("error listening for http connections: %w", err)
	}
	m.httpLn = httpLn

	// Start HTTP bypass handler
	go m.runHTTPBypass(httpLn)

	// Setup HTTPS listener
	httpsLn, err := net.Listen("tcp", fmt.Sprintf(":%d", s.MitmProxyHTTPSPort()))
	if err != nil {
		return fmt.Errorf("error listening for https connections: %w", err)
	}
	m.httpsLn = httpsLn

	// Start HTTPS bypass handler
	go m.runHTTPSBypass(httpsLn)

	return nil
}

func (m *BypassProxy) runHTTPBypass(ln net.Listener) {
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
					zap.L().Error("Error accepting new HTTP connection", zap.Error(err))
					continue
				}
			}
			go handleHTTPBypass(c)
		}
	}
}

func (m *BypassProxy) runHTTPSBypass(ln net.Listener) {
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
					zap.L().Error("Error accepting new HTTPS connection", zap.Error(err))
					continue
				}
			}
			go handleHTTPSBypass(c)
		}
	}
}

func handleHTTPBypass(conn net.Conn) {
	defer conn.Close()

	// Use vhost to peek at HTTP Host header without consuming the connection
	httpConn, err := vhost.HTTP(conn)
	if err != nil || httpConn.Host() == "" {
		return
	}

	// Connect to the target server
	target := net.JoinHostPort(httpConn.Host(), "80")
	remote, err := net.Dial("tcp", target)
	if err != nil {
		return
	}

	// Bidirectional copy
	handleProxy(httpConn, remote)
}

func handleHTTPSBypass(conn net.Conn) {
	defer conn.Close()

	// Use vhost to peek at SNI without consuming the connection
	tlsConn, err := vhost.TLS(conn)
	if err != nil || tlsConn.Host() == "" {
		return
	}

	// Connect to the target server
	target := net.JoinHostPort(tlsConn.Host(), "443")
	remote, err := net.Dial("tcp", target)
	if err != nil {
		return
	}

	// Bidirectional copy
	handleProxy(tlsConn, remote)
}

func handleProxy(client, remote net.Conn) {
	defer client.Close()
	defer remote.Close()

	done := make(chan bool)
	go func() {
		io.Copy(remote, client)
		done <- true
	}()
	go func() {
		io.Copy(client, remote)
		done <- true
	}()
	<-done
}

// Close gracefully shuts down the bypass proxy
func (m *BypassProxy) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}

	// Signal handlers to stop
	close(m.stopChan)

	// Close HTTP listener
	if m.httpLn != nil {
		if err := m.httpLn.Close(); err != nil {
			zap.L().Error("Error closing HTTP listener", zap.Error(err))
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
		zap.L().Warn("Timeout waiting for bypass handlers to stop")
	}

	return nil
}
