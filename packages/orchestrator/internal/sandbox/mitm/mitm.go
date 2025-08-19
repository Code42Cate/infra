package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"

	"github.com/e2b-dev/infra/packages/orchestrator/internal/sandbox/network"
	"github.com/e2b-dev/infra/packages/shared/pkg/vault"
	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
	"go.uber.org/zap"
)

var crt = `-----BEGIN CERTIFICATE-----
MIIBjzCCATWgAwIBAgIUa6uLlbKPj+Xkkh3dcoTqatV+uNEwCgYIKoZIzj0EAwIw
FTETMBEGA1UEAwwKcHJveHktcm9vdDAeFw0yNTA4MDIwMDEwMTFaFw0yNjA4MDIw
MDEwMTFaMBUxEzARBgNVBAMMCnByb3h5LXJvb3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQy6moqnZxY7etTlq/Ifpv3CVQM3+8NABYGa1wSWK5zgic6F4K9sqk/
o8Mb1ldU3SkGv7g+pzbzAPyK7JO5agfco2MwYTAdBgNVHQ4EFgQU/JjLmKTVJxES
aKqdC9fA7o/GzxwwHwYDVR0jBBgwFoAU/JjLmKTVJxESaKqdC9fA7o/GzxwwDwYD
VR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIg
cWmX/ybckN1HXrUvICq5NkI3vPvn++Sud2RzXJtB9hMCIQDwaayXxROajoG937Pp
rje/jkqPQPTNMgng1AvsgeFmkQ==
-----END CERTIFICATE-----`

var key = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVDWTLVkSCdJc8W0r
TvwCR0lIQvHpkzv1UYvOJkiGahmhRANCAAQy6moqnZxY7etTlq/Ifpv3CVQM3+8N
ABYGa1wSWK5zgic6F4K9sqk/o8Mb1ldU3SkGv7g+pzbzAPyK7JO5agfc
-----END PRIVATE KEY-----`

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

	vaultClient, err := vault.NewClientFromEnv(ctx)
	if err != nil {
		zap.L().Error("Failed to create Vault client", zap.Error(err))
		return nil
	}

	zap.L().Info("Starting MITM proxy", zap.Uint("httpPort", s.MitmProxyHTTPPort()), zap.Uint("httpsPort", s.MitmProxyHTTPSPort()))

	proxy := goproxy.NewProxyHttpServer()

	caCert, err := tls.X509KeyPair([]byte(crt), []byte(key))
	if err != nil {
		zap.L().Error("Failed to load CA certificate", zap.Error(err))
		return nil
	}
	caCert.Leaf, err = x509.ParseCertificate(caCert.Certificate[0])
	if err != nil {
		zap.L().Error("Failed to parse CA certificate", zap.Error(err))
		return nil
	}

	goproxy.GoproxyCa = caCert
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: goproxy.TLSConfigFromCA(&caCert)}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&caCert)}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&caCert)}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&caCert)}

	proxy.Verbose = true

	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host == "" {
			fmt.Fprintln(w, "Cannot handle requests without Host header, e.g., HTTP 1.0")
			return
		}
		req.URL.Scheme = "http"
		req.URL.Host = req.Host
		proxy.ServeHTTP(w, req)
	})

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

		req.Header.Set("X-E2B-Sandbox", sandboxID)
		req.Header.Set("X-E2B-Team", teamID)

		return req, nil
	})

	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*$"))).
		HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*:80$"))).
		HijackConnect(func(req *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
			defer func() {
				if e := recover(); e != nil {
					ctx.Logf("error connecting to remote: %v", e)
					client.Write([]byte("HTTP/1.1 500 Cannot reach destination\r\n\r\n"))
				}
				client.Close()
			}()
			clientBuf := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))

			remote, err := connectDial(req.Context(), proxy, "tcp", req.URL.Host)
			orPanic(err)
			remoteBuf := bufio.NewReadWriter(bufio.NewReader(remote), bufio.NewWriter(remote))
			for {
				req, err := http.ReadRequest(clientBuf.Reader)
				orPanic(err)
				orPanic(req.Write(remoteBuf))
				orPanic(remoteBuf.Flush())
				resp, err := http.ReadResponse(remoteBuf.Reader, req)
				orPanic(err)
				orPanic(resp.Write(clientBuf.Writer))
				orPanic(clientBuf.Flush())
			}
		})

	// Setup HTTP server
	m.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.MitmProxyHTTPPort()),
		Handler: proxy,
	}

	// Start HTTP server
	go func() {
		if err := m.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			zap.L().Error("HTTP server error", zap.Error(err))
		}
	}()

	// listen to the TLS ClientHello but make it a CONNECT request instead
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.MitmProxyHTTPSPort()))
	if err != nil {
		zap.L().Error("Error listening for https connections", zap.Error(err))
		return m
	}
	m.httpsLn = ln

	// Start HTTPS handler
	go func() {
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
				go func(c net.Conn) {
					tlsConn, err := vhost.TLS(c)
					if err != nil {
						zap.L().Error("Error accepting new connection", zap.Error(err))
						c.Close()
						return
					}
					if tlsConn.Host() == "" {
						zap.L().Error("Cannot support non-SNI enabled clients")
						c.Close()
						return
					}

					zap.L().Info("Handling request", zap.String("host", tlsConn.Host()))
					connectReq := &http.Request{
						Method: http.MethodConnect,
						URL: &url.URL{
							Opaque: tlsConn.Host(),
							Host:   net.JoinHostPort(tlsConn.Host(), "443"),
						},
						Host:       tlsConn.Host(),
						Header:     make(http.Header),
						RemoteAddr: c.RemoteAddr().String(),
					}
					resp := dumbResponseWriter{tlsConn}
					proxy.ServeHTTP(resp, connectReq)
					// Connection will be closed by the proxy when done
				}(c)
			}
		}
	}()

	return m
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

type dumbResponseWriter struct {
	net.Conn
}

func (dumb dumbResponseWriter) Header() http.Header {
	panic("Header() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil // throw away the HTTP OK response from the faux CONNECT request
	}
	return dumb.Conn.Write(buf)
}

func (dumb dumbResponseWriter) WriteHeader(code int) {
	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}

func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}
