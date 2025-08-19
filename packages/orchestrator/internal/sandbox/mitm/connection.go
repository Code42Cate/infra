package mitm

import (
	"bufio"
	"net"
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"
)

func handlePort80Connection(proxy *goproxy.ProxyHttpServer) func(*http.Request, net.Conn, *goproxy.ProxyCtx) {
	return func(req *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
		defer client.Close()

		remote, err := connectDial(req.Context(), proxy, "tcp", req.URL.Host)
		if err != nil {
			ctx.Logf("failed to connect to remote %s: %v", req.URL.Host, err)
			client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer remote.Close()

		proxyHTTPConnection(client, remote, ctx)
	}
}

func proxyHTTPConnection(client, remote net.Conn, ctx *goproxy.ProxyCtx) {
	clientBuf := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))
	remoteBuf := bufio.NewReadWriter(bufio.NewReader(remote), bufio.NewWriter(remote))

	for {
		req, err := http.ReadRequest(clientBuf.Reader)
		if err != nil {
			if err.Error() != "EOF" && !strings.Contains(err.Error(), "closed") {
				ctx.Logf("error reading request from client: %v", err)
			}
			return
		}

		if !forwardRequest(req, remoteBuf, client, ctx) {
			return
		}

		if !forwardResponse(req, clientBuf, remoteBuf, client, ctx) {
			return
		}
	}
}

func forwardRequest(req *http.Request, remoteBuf *bufio.ReadWriter, client net.Conn, ctx *goproxy.ProxyCtx) bool {
	if err := req.Write(remoteBuf); err != nil {
		ctx.Logf("error writing request to remote: %v", err)
		client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return false
	}

	if err := remoteBuf.Flush(); err != nil {
		ctx.Logf("error flushing request to remote: %v", err)
		client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return false
	}

	return true
}

func forwardResponse(req *http.Request, clientBuf, remoteBuf *bufio.ReadWriter, client net.Conn, ctx *goproxy.ProxyCtx) bool {
	resp, err := http.ReadResponse(remoteBuf.Reader, req)
	if err != nil {
		ctx.Logf("error reading response from remote: %v", err)
		client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return false
	}

	if err := resp.Write(clientBuf.Writer); err != nil {
		ctx.Logf("error writing response to client: %v", err)
		return false
	}

	if err := clientBuf.Flush(); err != nil {
		ctx.Logf("error flushing response to client: %v", err)
		return false
	}

	return true
}
