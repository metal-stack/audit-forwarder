/*
Helper package for opening a http connect proxy connection through a uds socket, and
open a listener and forward connections through the proxy connection.
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
	logger        *zap.SugaredLogger
	uds           string
	destinationIP string
	listenerIP    string
	listenerPort  string
	listener      *net.TCPListener
}

// Creates a new proxy instance and opens a TCP listener for accepting connections.
func NewProxy(logger *zap.SugaredLogger, uds, destinationIP, listenerIP, listenerPort string) (*Proxy, error) {
	proxy := &Proxy{
		logger:        logger,
		uds:           uds,
		destinationIP: destinationIP,
		listenerIP:    listenerIP,
		listenerPort:  listenerPort,
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
		}
		p.logger.Infow("New connection", "listener", p.listener, "to (listener address)", srvConn.LocalAddr(), "from (client address)", srvConn.RemoteAddr())

		go p.handleConnection(srvConn)
	}
}

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
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", p.destinationIP, p.listenerIP, "auditforwarder")
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

// const (
// 	backoffTimer = time.Duration(10 * time.Second)
// )

// var (
// 	logger *zap.SugaredLogger
// )

// func MakeProxy(ctx context.Context, uds, ip, port string, l *zap.SugaredLogger) {
// 	logger = l
// 	addr := net.JoinHostPort(ip, port)
// 	logger.Infow("MakeProxy called", "unix domain socket", uds, "destination address", ip, "Port", port)

// 	// Setting up the listener.
// 	endpoint, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort("0.0.0.0", port))
// 	var listener *net.TCPListener
// 	var err error
// 	for i := 1; i <= 5; i++ {
// 		listener, err = net.ListenTCP("tcp", endpoint)
// 		if err == nil {
// 			break
// 		} else {
// 			logger.Errorw("Could not open port for listening", "Port:", port, "try", i, "out of", 5)
// 		}
// 		time.Sleep(backoffTimer)
// 	}
// 	if listener == nil {
// 		logger.Fatal("Could not open listener for konnectivity proxy, exiting")
// 	}
// 	defer listener.Close()
// 	go listenForConnections(*listener, uds, addr)
// 	<-ctx.Done()
// 	logger.Infow("Context canceled, exiting", "error", ctx.Err())
// }

// func listenForConnections(listener net.TCPListener, uds, addr string) {
// 	for {
// 		srvConn, err := listener.AcceptTCP()
// 		if err != nil {
// 			logger.Errorw("Error accepting connection on listener", "listener:", listener)
// 			return
// 		}
// 		logger.Infow("New connection", "listener", listener, "local address", srvConn.LocalAddr(), "remote address", srvConn.RemoteAddr())
// 		go handleConnection(srvConn, uds, addr)
// 	}
// }

// func handleConnection(srvConn *net.TCPConn, uds, addr string) {
// 	logger.Infow("handleConnection called", "local address", srvConn.LocalAddr(), "remote address", srvConn.RemoteAddr(), "unix domain socket", uds, "target address", addr)
// 	proxyConn, err := net.Dial("unix", uds)
// 	if err != nil {
// 		logger.Errorw("dialing proxy failed", "unix domain socket", uds, "error", err)
// 		return
// 	}
// 	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", addr, "127.0.0.1", "auditforwarder")
// 	br := bufio.NewReader(proxyConn)
// 	res, err := http.ReadResponse(br, nil)
// 	if err != nil {
// 		logger.Errorf("reading HTTP response from CONNECT to %s via uds proxy %s failed: %v", addr, uds, err)
// 		return
// 	}
// 	defer res.Body.Close()

// 	if res.StatusCode != 200 {
// 		logger.Errorf("proxy error from %s while dialing %s: %v", uds, addr, res.Status)
// 		return
// 	}
// 	// It's safe to discard the bufio.Reader here and return the
// 	// original TCP conn directly because we only use this for
// 	// TLS, and in TLS the client speaks first, so we know there's
// 	// no unbuffered data. But we can double-check.
// 	if br.Buffered() > 0 {
// 		logger.Errorf("unexpected %d bytes of buffered data from CONNECT uds proxy %q", br.Buffered(), uds)
// 		return
// 	}
// 	// Now we're supposed to have both connections open.
// 	// channels to wait on the close event for each connection
// 	serverClosed := make(chan struct{}, 1)
// 	proxyClosed := make(chan struct{}, 1)

// 	go broker(srvConn, proxyConn, proxyClosed)
// 	go broker(proxyConn, srvConn, serverClosed)

// 	// wait for one half of the proxy to exit, then trigger a shutdown of the
// 	// other half by calling CloseRead(). This will break the read loop in the
// 	// broker and allow us to fully close the connection cleanly without a
// 	// "use of closed network connection" error.
// 	var waitFor chan struct{}
// 	select {
// 	case <-proxyClosed:
// 		// the client closed first and any more packets from the server aren't
// 		// useful, so we can optionally SetLinger(0) here to recycle the port
// 		// faster.
// 		_ = srvConn.SetLinger(0)
// 		srvConn.Close()
// 		waitFor = serverClosed
// 	case <-serverClosed:
// 		proxyConn.Close()
// 		waitFor = proxyClosed
// 	}

// 	// Wait for the other connection to close.
// 	// This "waitFor" pattern isn't required, but gives us a way to track the
// 	// connection and ensure all copies terminate correctly; we can trigger
// 	// stats on entry and deferred exit of this function.
// 	<-waitFor
// }

// // This does the actual data transfer.
// // The broker only closes the Read side.
// func broker(dst, src net.Conn, srcClosed chan struct{}) {
// 	// We can handle errors in a finer-grained manner by inlining io.Copy (it's
// 	// simple, and we drop the ReaderFrom or WriterTo checks for
// 	// net.Conn->net.Conn transfers, which aren't needed). This would also let
// 	// us adjust buffersize.
// 	_, err := io.Copy(dst, src)

// 	if err != nil {
// 		logger.Errorf("Copy error: %s", err)
// 	}
// 	if err := src.Close(); err != nil {
// 		logger.Errorf("Close error: %s", err)
// 	}
// 	srcClosed <- struct{}{}
// }
