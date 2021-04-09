/*
Helper package for opening a http connect proxy connection through a uds socket, and
open a listener and forward connections through the proxy connection.
*/

package konnectivityproxy

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	"k8s.io/klog/v2"
)

func MakeProxy(uds, ip, port string) {
	addr := net.JoinHostPort(ip, port)

	// Setting up the listener.
	endpoint, _ := net.ResolveTCPAddr("tcp", net.JoinHostPort("0.0.0.0", port))
	listener, err := net.ListenTCP("tcp", endpoint)
	if err != nil {
		klog.Errorf("Could not open port for listening: %s", port)
		return
	}
	for {
		srvConn, err := listener.AcceptTCP()
		if err != nil {
			klog.Errorf("Error accepting connection on listener: %s", listener.Addr().String())
			return
		}
		go handleConnection(srvConn, uds, addr)
	}
}

func handleConnection(srvConn *net.TCPConn, uds, addr string) {
	proxyConn, err := net.Dial("unix", uds)
	if err != nil {
		klog.Errorf("dialing proxy %q failed: %v", uds, err)
		return
	}
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", addr, "127.0.0.1", "auditforwarder")
	br := bufio.NewReader(proxyConn)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		klog.Errorf("reading HTTP response from CONNECT to %s via uds proxy %s failed: %v", addr, uds, err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		klog.Errorf("proxy error from %s while dialing %s: %v", uds, addr, res.Status)
		return
	}
	// It's safe to discard the bufio.Reader here and return the
	// original TCP conn directly because we only use this for
	// TLS, and in TLS the client speaks first, so we know there's
	// no unbuffered data. But we can double-check.
	if br.Buffered() > 0 {
		klog.Errorf("unexpected %d bytes of buffered data from CONNECT uds proxy %q", br.Buffered(), uds)
		return
	}
	// Now we're supposed to have both connections open.
	// channels to wait on the close event for each connection
	serverClosed := make(chan struct{}, 1)
	proxyClosed := make(chan struct{}, 1)

	go broker(srvConn, proxyConn, proxyClosed)
	go broker(proxyConn, srvConn, serverClosed)

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
func broker(dst, src net.Conn, srcClosed chan struct{}) {
	// We can handle errors in a finer-grained manner by inlining io.Copy (it's
	// simple, and we drop the ReaderFrom or WriterTo checks for
	// net.Conn->net.Conn transfers, which aren't needed). This would also let
	// us adjust buffersize.
	_, err := io.Copy(dst, src)

	if err != nil {
		log.Printf("Copy error: %s", err)
	}
	if err := src.Close(); err != nil {
		log.Printf("Close error: %s", err)
	}
	srcClosed <- struct{}{}
}

// Not needed, keeping for reference now:

func tunnelHTTPConnect(proxyConn net.Conn, proxyAddress, addr string) (net.Conn, error) {
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, "127.0.0.1")
	br := bufio.NewReader(proxyConn)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("reading HTTP response from CONNECT to %s via proxy %s failed: %w",
			addr, proxyAddress, err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy error from %s while dialing %s, code %d: %s",
			proxyAddress, addr, res.StatusCode, res.Status)
	}

	// It's safe to discard the bufio.Reader here and return the
	// original TCP conn directly because we only use this for
	// TLS, and in TLS the client speaks first, so we know there's
	// no unbuffered data. But we can double-check.
	if br.Buffered() > 0 {
		proxyConn.Close()
		return nil, fmt.Errorf("unexpected %d bytes of buffered data from CONNECT proxy %q",
			br.Buffered(), proxyAddress)
	}
	return proxyConn, nil
}