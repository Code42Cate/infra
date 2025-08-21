package mitm

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
	"go.uber.org/zap"
)

func loadCACertificate(rootcert, rootkey string) (tls.Certificate, error) {
	caCert, err := tls.X509KeyPair([]byte(rootcert), []byte(rootkey))
	if err != nil {
		return caCert, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	caCert.Leaf, err = x509.ParseCertificate(caCert.Certificate[0])
	if err != nil {
		return caCert, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	return caCert, nil
}

func handleNewTLSConn(c net.Conn, proxy *goproxy.ProxyHttpServer) {
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

	connectReq := createConnectRequest(tlsConn)
	resp := dumbResponseWriter{tlsConn}
	proxy.ServeHTTP(resp, connectReq)
}

func createConnectRequest(tlsConn net.Conn) *http.Request {
	host := tlsConn.(*vhost.TLSConn).Host()
	return &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Opaque: host,
			Host:   net.JoinHostPort(host, "443"),
		},
		Host:       host,
		Header:     make(http.Header),
		RemoteAddr: tlsConn.RemoteAddr().String(),
	}
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
