package mitm

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"

	"github.com/elazarl/goproxy"
	"github.com/inconshreveable/go-vhost"
	"go.uber.org/zap"
)

func NewMITMProxy(httpPort, httpsPort uint) {
	zap.L().Info("Starting MITM proxy", zap.Uint("httpPort", httpPort), zap.Uint("httpsPort", httpsPort))

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	zap.L().Info("Created proxy HTTP server with verbose mode enabled")

	// Simple pass-through for HTTPS
	zap.L().Info("Setting up HTTPS pass-through handler")
	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*$"))).
		HandleConnect(goproxy.AlwaysMitm)

	// Handle HTTP on port 80
	zap.L().Info("Setting up HTTP port 80 hijack handler")
	proxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*:80$"))).
		HijackConnect(func(req *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
			zap.L().Info("Hijacking HTTP connection", zap.String("host", req.URL.Host), zap.String("method", req.Method), zap.String("url", req.URL.String()))
			defer client.Close()
			zap.L().Info("Dialing remote host", zap.String("host", req.URL.Host))
			remote, err := net.Dial("tcp", req.URL.Host)
			if err != nil {
				zap.L().Error("Failed to dial remote host", zap.String("host", req.URL.Host), zap.Error(err))
				client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
				return
			}
			defer remote.Close()
			zap.L().Info("Connection established to remote host", zap.String("host", req.URL.Host))
			client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
			handleProxy(client, remote)
		})

	go func() {
		addr := fmt.Sprintf("0.0.0.0:%d", httpPort)
		zap.L().Info("Starting HTTP server", zap.String("address", addr))
		if err := http.ListenAndServe(addr, proxy); err != nil {
			zap.L().Error("HTTP server failed", zap.String("address", addr), zap.Error(err))
		}
	}()
	listenHTTPS(fmt.Sprintf("0.0.0.0:%d", httpsPort))
}

func listenHTTPS(addr string) {
	zap.L().Info("Starting HTTPS listener", zap.String("address", addr))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		zap.L().Fatal("Failed to start HTTPS listener", zap.String("address", addr), zap.Error(err))
		log.Fatal(err)
	}
	zap.L().Info("HTTPS listener started successfully", zap.String("address", addr))

	for {
		c, err := ln.Accept()
		if err != nil {
			zap.L().Error("Failed to accept connection", zap.Error(err))
			continue
		}
		zap.L().Info("Accepted new HTTPS connection", zap.String("remoteAddr", c.RemoteAddr().String()))
		go func(conn net.Conn) {
			zap.L().Info("Processing TLS connection")
			tlsConn, err := vhost.TLS(conn)
			if err != nil {
				zap.L().Error("Failed to parse TLS connection", zap.Error(err))
				conn.Close()
				return
			}
			if tlsConn.Host() == "" {
				zap.L().Info("Empty TLS host, closing connection")
				conn.Close()
				return
			}
			zap.L().Info("TLS connection parsed", zap.String("host", tlsConn.Host()))
			target := net.JoinHostPort(tlsConn.Host(), "443")
			zap.L().Info("Dialing TLS target", zap.String("target", target))
			remote, err := net.Dial("tcp", target)
			if err != nil {
				zap.L().Error("Failed to dial TLS target", zap.String("target", target), zap.Error(err))
				tlsConn.Close()
				return
			}
			zap.L().Info("Successfully connected to TLS target", zap.String("target", target))
			handleProxy(tlsConn, remote)
		}(c)
	}
}

func handleProxy(client, remote net.Conn) {
	zap.L().Info("Starting proxy handler",
		zap.String("clientAddr", client.RemoteAddr().String()),
		zap.String("remoteAddr", remote.RemoteAddr().String()))
	defer func() {
		client.Close()
		zap.L().Info("Closed client connection", zap.String("clientAddr", client.RemoteAddr().String()))
	}()
	defer func() {
		remote.Close()
		zap.L().Info("Closed remote connection", zap.String("remoteAddr", remote.RemoteAddr().String()))
	}()
	done := make(chan bool)
	go func() {
		zap.L().Info("Starting client->remote copy")
		n, err := io.Copy(remote, client)
		if err != nil {
			zap.L().Info("Client->remote copy error", zap.Error(err))
		} else {
			zap.L().Info("Client->remote copy completed", zap.Int64("bytes", n))
		}
		done <- true
	}()
	go func() {
		zap.L().Info("Starting remote->client copy")
		n, err := io.Copy(client, remote)
		if err != nil {
			zap.L().Info("Remote->client copy error", zap.Error(err))
		} else {
			zap.L().Info("Remote->client copy completed", zap.Int64("bytes", n))
		}
		done <- true
	}()
	<-done
	zap.L().Info("Proxy handler completed")
}
