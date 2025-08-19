package mitm

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"regexp"

	"github.com/elazarl/goproxy"
	"go.uber.org/zap"

	"github.com/e2b-dev/infra/packages/shared/pkg/vault"
)

func configureProxy(proxy *goproxy.ProxyHttpServer, caCert tls.Certificate, vaultClient *vault.Client, teamID, sandboxID string) {
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
		zap.L().Info("Handling request with sandbox ID from header",
			zap.String("host", req.Host),
			zap.String("sandboxID", sandboxID),
			zap.String("teamID", teamID),
		)

		processE2BHeaders(req.Header, func(uuid string) (string, error) {
			secret, _, err := vaultClient.GetSecret(req.Context(), fmt.Sprintf("%s/%s", teamID, uuid))
			if err != nil {
				return "", err
			}
			return secret, nil
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
