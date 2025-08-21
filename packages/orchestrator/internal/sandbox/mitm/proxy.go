package mitm

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	"go.uber.org/zap"
)

func configureProxy(proxy *goproxy.ProxyHttpServer, caCert tls.Certificate, secretsCache *SecretsCache, teamID, sandboxID string) {
	proxy.Verbose = true

	// Configure TLS actions
	tlsConfig := goproxy.TLSConfigFromCA(&caCert)
	goproxy.GoproxyCa = caCert
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: tlsConfig}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsConfig}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: tlsConfig}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: tlsConfig}

	// Handle non-proxy requests
	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host == "" {
			fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		proxy.ServeHTTP(w, req)
	})

	// Process E2B headers with secrets
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		requestHost, _, _ := net.SplitHostPort(req.Host)
		if requestHost == "" {
			requestHost = req.Host
		}

		zap.L().Info("Handling request with sandbox ID from header",
			zap.String("host", requestHost),
			zap.String("sandboxID", sandboxID),
			zap.String("teamID", teamID),
		)

		processE2BHeaders(req.Header, func(uuid string) (string, error) {
			start := time.Now()

			secret, metadata, err := secretsCache.GetSecret(req.Context(), teamID, uuid)
			if err != nil {
				return "", err
			}

			zap.L().Info("Retrieved secret from Vault",
				zap.String("uuid", uuid),
				zap.Duration("duration", time.Since(start)),
			)

			hosts, err := extractHostsFromMetadata(metadata)
			if err != nil {
				return "", err
			}

			// Check if the request host matches any of the allowed glob patterns
			for _, pattern := range hosts {
				pattern = strings.TrimSpace(pattern)
				// not sure if filepath.Match is a good idea here but it works :D
				if matched, err := filepath.Match(pattern, requestHost); err == nil && matched {
					return secret, nil
				}
			}

			return "", fmt.Errorf("request host %s does not match any allowed pattern", requestHost)
		})

		return req, nil
	})

	// Configure MITM for all hosts
	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*$"))).
		HandleConnect(goproxy.AlwaysMitm)

	// Handle port 80 connections
	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*:80$"))).
		HijackConnect(handlePort80Connection(proxy))
}

// copied/converted from https.go
func dial(ctx context.Context, proxy *goproxy.ProxyHttpServer, network, addr string) (c net.Conn, err error) {
	if proxy.Tr.DialContext != nil {
		return proxy.Tr.DialContext(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// copied/converted from https.go
func connectDial(ctx context.Context, proxy *goproxy.ProxyHttpServer, network, addr string) (c net.Conn, err error) {
	if proxy.ConnectDial == nil {
		return dial(ctx, proxy, network, addr)
	}
	return proxy.ConnectDial(network, addr)
}

func extractHostsFromMetadata(metadata map[string]interface{}) ([]string, error) {
	// Extract custom_metadata first
	customMetadata, ok := metadata["custom_metadata"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid metadata, missing custom_metadata")
	}

	// Extract hosts JSON string from custom_metadata
	hostsJSON, ok := customMetadata["hosts"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid metadata, missing or invalid hosts in custom_metadata")
	}

	// Parse JSON string to get hosts slice
	var hosts []string
	if err := json.Unmarshal([]byte(hostsJSON), &hosts); err != nil {
		return nil, fmt.Errorf("invalid metadata, hosts is not a valid json array: %v", err)
	}

	return hosts, nil
}
