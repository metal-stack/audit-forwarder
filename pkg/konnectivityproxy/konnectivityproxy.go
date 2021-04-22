/*
Helper package for opening a http connect proxy connection through a uds socket, and
open a listener and forward connections through the proxy connection.

Connection handling and copying was borrowed from James Bardin's
Go TCP Proxy pattern:
https://gist.github.com/jbardin/821d08cb64c01c84b81a
*/

package konnectivityproxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"

	"go.uber.org/zap"
)

type Proxy struct {
	logger          *zap.SugaredLogger
	uds             string
	destinationIP   string
	destinationPort string
	listenerIP      string
	listenerPort    string
	listener        *net.TCPListener
}

// Creates a new proxy instance and opens a TCP listener for accepting connections.
func NewProxy(logger *zap.SugaredLogger, uds, destinationIP, destinationPort, listenerIP, listenerPort string) (*Proxy, error) {
	proxy := &Proxy{
		logger:          logger,
		uds:             uds,
		destinationIP:   destinationIP,
		destinationPort: destinationPort,
		listenerIP:      listenerIP,
		listenerPort:    listenerPort,
	}
	logger.Infow("NewProxy called", "unix domain socket", uds, "listener IP", listenerIP, "listener port", listenerPort)

	listenerTCPAddr, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort(listenerIP, listenerPort))
	var err error
	proxy.listener, err = net.ListenTCP("tcp", listenerTCPAddr)
	if err != nil {
		logger.Errorw("Could not open listener", "listener address", listenerTCPAddr)
		return nil, err
	}
	go proxy.forward()
	return proxy, nil
}

func (p *Proxy) forward() {
	for {
		srvConn, err := p.listener.AcceptTCP()
		if err != nil {
			p.logger.Errorw("Error accepting connection on listener", "listener:", p.listener)
			return
		}
		p.logger.Infow("New connection", "listener", p.listener, "to (listener address)", srvConn.LocalAddr(), "from (client address)", srvConn.RemoteAddr())

		go p.handleConnection(srvConn)
	}
}

// Closes the listener.
func (p *Proxy) DestroyProxy() {
	p.logger.Infow("Closing forwarder", "uds", p.uds, "destination ip", p.destinationIP)
	p.listener.Close()
}

func (p *Proxy) handleConnection(srvConn *net.TCPConn) {
	p.logger.Infow("handleConnection called", "local address", srvConn.LocalAddr(), "remote address", srvConn.RemoteAddr(), "unix domain socket", p.uds, "target address", p.destinationIP)
	proxyConn, err := net.Dial("unix", p.uds)
	if err != nil {
		p.logger.Errorw("dialing proxy failed", "unix domain socket", p.uds, "error", err)
		return
	}
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", net.JoinHostPort(p.destinationIP, p.destinationPort), p.listenerIP, "auditforwarder")
	br := bufio.NewReader(proxyConn)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		p.logger.Errorf("reading HTTP response from CONNECT to %s via uds proxy %s failed: %v", p.destinationIP, p.uds, err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		p.logger.Errorf("proxy error from %s while dialing %s: %v", p.uds, p.destinationIP, res.Status)
		return
	}
	// It's safe to discard the bufio.Reader here and return the
	// original TCP conn directly because we only use this for
	// TLS, and in TLS the client speaks first, so we know there's
	// no unbuffered data. But we can double-check.
	if br.Buffered() > 0 {
		p.logger.Errorf("unexpected %d bytes of buffered data from CONNECT uds proxy %q", br.Buffered(), p.uds)
		return
	}
	// Now we're supposed to have both connections open.
	// channels to wait on the close event for each connection
	serverClosed := make(chan struct{}, 1)
	proxyClosed := make(chan struct{}, 1)

	go p.broker(srvConn, proxyConn, proxyClosed)
	go p.broker(proxyConn, srvConn, serverClosed)

	// wait for one half of the proxy to exit, then trigger a shutdown of the
	// other half by calling CloseRead(). This will break the read loop in the
	// broker and allow us to fully close the connection cleanly without a
	// "use of closed network connection" error.
	var waitFor chan struct{}
	select {
	case <-proxyClosed:
		// the client closed first and any more packets from the server aren't
		// useful, so we can optionally SetLinger(0) here to recycle the port
		// faster.
		_ = srvConn.SetLinger(0)
		srvConn.Close()
		waitFor = serverClosed
	case <-serverClosed:
		proxyConn.Close()
		waitFor = proxyClosed
	}

	// Wait for the other connection to close.
	// This "waitFor" pattern isn't required, but gives us a way to track the
	// connection and ensure all copies terminate correctly; we can trigger
	// stats on entry and deferred exit of this function.
	<-waitFor
}

// This does the actual data transfer.
// The broker only closes the Read side.
func (p *Proxy) broker(dst, src net.Conn, srcClosed chan struct{}) {
	// We can handle errors in a finer-grained manner by inlining io.Copy (it's
	// simple, and we drop the ReaderFrom or WriterTo checks for
	// net.Conn->net.Conn transfers, which aren't needed). This would also let
	// us adjust buffersize.
	_, err := io.Copy(dst, src)

	if err != nil {
		p.logger.Errorf("Copy error: %s", err)
	}
	if err := src.Close(); err != nil {
		p.logger.Errorf("Close error: %s", err)
	}
	srcClosed <- struct{}{}
}
