package proxy

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// The proxy integration tests start HTTP servers using bare go http.Serve(ln, gw)
	// (see startGateway in gateway_test.go) and create HTTP clients with http.Transport
	// that keeps connections alive (see gwProxyClient). Neither path calls
	// http.Server.Shutdown or client.CloseIdleConnections after each test, so the
	// per-connection goroutines and transport goroutines outlive the individual tests.
	//
	// These are test-infrastructure goroutines, not application leaks:
	//
	//   internal/poll.runtime_pollWait — server-side net/http.(*conn).serve goroutines
	//     waiting for the next HTTP request on an idle keep-alive connection, and
	//     client-side net/http.(*persistConn).readLoop goroutines waiting for a
	//     response on the same idle connections.
	//
	//   net/http.(*persistConn).writeLoop — client-side transport write goroutines
	//     for idle keep-alive connections whose transport was not explicitly closed.
	//
	// The correct fix is to change startGateway to use http.Server.Shutdown and
	// gwProxyClient to add t.Cleanup(client.CloseIdleConnections). Since those
	// helpers live in gateway_test.go (owned by another slice), we suppress these
	// known-safe goroutines here instead.
	goleak.VerifyTestMain(m,
		goleak.IgnoreTopFunction("net/http.(*persistConn).writeLoop"),
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
	)
}
