package govern

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSMTP is a minimal SMTP server: it advertises STARTTLS when tlsCfg is set
// and records whether a message body arrived, and over which kind of
// connection.
type fakeSMTP struct {
	ln       net.Listener
	tlsCfg   *tls.Config
	implicit bool // TLS from the first byte (port 465 behaviour)

	mu         sync.Mutex
	gotData    bool
	dataOverTL bool
	gotMail    bool
}

func (s *fakeSMTP) serve(t *testing.T) {
	t.Helper()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeSMTP) handle(conn net.Conn) {
	defer conn.Close()
	isTLS := false
	if s.implicit {
		conn = tls.Server(conn, s.tlsCfg)
		isTLS = true
	}
	r, w := bufio.NewReader(conn), conn
	reply := func(line string) { _, _ = w.Write([]byte(line + "\r\n")) }
	reply("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			if s.tlsCfg != nil && !isTLS {
				reply("250-fake")
				reply("250 STARTTLS")
			} else {
				reply("250 fake")
			}
		case cmd == "STARTTLS":
			reply("220 go ahead")
			tc := tls.Server(conn, s.tlsCfg)
			if tc.Handshake() != nil {
				return
			}
			conn, isTLS = tc, true
			r, w = bufio.NewReader(tc), tc
		case strings.HasPrefix(cmd, "MAIL"):
			s.mu.Lock()
			s.gotMail = true
			s.mu.Unlock()
			reply("250 ok")
		case strings.HasPrefix(cmd, "RCPT"):
			reply("250 ok")
		case cmd == "DATA":
			reply("354 send")
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
			}
			s.mu.Lock()
			s.gotData, s.dataOverTL = true, isTLS
			s.mu.Unlock()
			reply("250 queued")
		case cmd == "QUIT":
			reply("221 bye")
			return
		default:
			reply("250 ok")
		}
	}
}

// selfSigned returns a server config for 127.0.0.1 and a client config that
// trusts it.
func selfSigned(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12},
		&tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
}

func startSMTP(t *testing.T, s *fakeSMTP) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go s.serve(t)
	return ln.Addr().(*net.TCPAddr).Port
}

func deliverer(t *testing.T, port int, allowPlaintext bool, clientTLS *tls.Config) *EmailApprovalNotifier {
	t.Helper()
	n, err := NewEmailApprovalNotifier(EmailApprovalNotifierConfig{
		Host: "127.0.0.1", Port: port, From: "graph@example.com", To: "sec@example.com",
		BaseURL: "https://graph.example.com", Secret: testSecret, AllowPlaintext: allowPlaintext,
	})
	require.NoError(t, err)
	n.tlsConfig = clientTLS
	return n
}

func TestDeliver_UpgradesWithSTARTTLS(t *testing.T) {
	serverTLS, clientTLS := selfSigned(t)
	srv := &fakeSMTP{tlsCfg: serverTLS}
	n := deliverer(t, startSMTP(t, srv), false, clientTLS)

	require.NoError(t, n.deliver(context.Background(), "graph@example.com", []string{"sec@example.com"}, []byte("Subject: x\r\n\r\nlink\r\n")))
	srv.mu.Lock()
	defer srv.mu.Unlock()
	assert.True(t, srv.gotData)
	assert.True(t, srv.dataOverTL, "the body must only travel inside TLS")
}

// The bug this guards: smtp.SendMail sends in the clear when the server (or a
// man in the middle stripping the advertisement) offers no STARTTLS.
func TestDeliver_RefusesAServerWithoutTLS(t *testing.T) {
	srv := &fakeSMTP{}
	n := deliverer(t, startSMTP(t, srv), false, nil)

	err := n.deliver(context.Background(), "graph@example.com", []string{"sec@example.com"}, []byte("link"))
	require.ErrorIs(t, err, ErrSMTPNoTLS)
	srv.mu.Lock()
	defer srv.mu.Unlock()
	assert.False(t, srv.gotMail, "nothing may be sent before TLS")
	assert.False(t, srv.gotData)
}

func TestDeliver_PlaintextOnlyWhenExplicitlyAllowed(t *testing.T) {
	srv := &fakeSMTP{}
	n := deliverer(t, startSMTP(t, srv), true, nil)

	require.NoError(t, n.deliver(context.Background(), "graph@example.com", []string{"sec@example.com"}, []byte("link\r\n")))
	srv.mu.Lock()
	defer srv.mu.Unlock()
	assert.True(t, srv.gotData)
	assert.False(t, srv.dataOverTL)
}

// A STARTTLS that fails (an untrusted certificate here) is an error, never a
// fallback to plaintext — even with plaintext allowed.
func TestDeliver_FailedHandshakeNeverFallsBack(t *testing.T) {
	serverTLS, _ := selfSigned(t)
	srv := &fakeSMTP{tlsCfg: serverTLS}
	n := deliverer(t, startSMTP(t, srv), true, &tls.Config{ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})

	err := n.deliver(context.Background(), "graph@example.com", []string{"sec@example.com"}, []byte("link"))
	require.ErrorContains(t, err, "STARTTLS")
	srv.mu.Lock()
	defer srv.mu.Unlock()
	assert.False(t, srv.gotData)
}

func TestDeliver_ImplicitTLS(t *testing.T) {
	serverTLS, clientTLS := selfSigned(t)
	srv := &fakeSMTP{tlsCfg: serverTLS, implicit: true}
	n := deliverer(t, startSMTP(t, srv), false, clientTLS)
	n.implicitTLS = true

	require.NoError(t, n.deliver(context.Background(), "graph@example.com", []string{"sec@example.com"}, []byte("link\r\n")))
	srv.mu.Lock()
	defer srv.mu.Unlock()
	assert.True(t, srv.gotData)
	assert.True(t, srv.dataOverTL)
}

func TestNewEmailApprovalNotifier_Port465IsImplicitTLS(t *testing.T) {
	for port, want := range map[int]bool{0: false, 587: false, 25: false, 465: true} {
		n, err := NewEmailApprovalNotifier(EmailApprovalNotifierConfig{Host: "h", Port: port, Secret: testSecret})
		require.NoError(t, err)
		assert.Equal(t, want, n.implicitTLS, "port %d", port)
	}
}
