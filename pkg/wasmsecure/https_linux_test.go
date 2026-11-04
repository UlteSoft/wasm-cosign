//go:build linux

// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Each child process initializes its own OS root pool from a private test CA.
// Production TLS verification is exercised without replacing http transports,
// modifying system trust, or enabling InsecureSkipVerify.
func TestFetchHTTPSAuthenticatedTLS(t *testing.T) {
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	serverKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "WSEA private HTTPS test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
	serverDER, e := x509.CreateCertificate(rand.Reader, serverTemplate, ca, &serverKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	td := t.TempDir()
	caPath := filepath.Join(td, "test-ca.pem")
	if e = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); e != nil {
		t.Fatal(e)
	}
	emptyRoots := filepath.Join(td, "empty-roots")
	if e = os.Mkdir(emptyRoots, 0700); e != nil {
		t.Fatal(e)
	}
	emptyCA := filepath.Join(td, "empty.pem")
	if e = os.WriteFile(emptyCA, nil, 0600); e != nil {
		t.Fatal(e)
	}
	var plaintextRequests atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		plaintextRequests.Add(1)
		_, _ = w.Write([]byte("must never be fetched"))
	}))
	defer plain.Close()
	var server *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte("authenticated evidence"))
		case "/redirect-https":
			http.Redirect(w, r, server.URL+"/ok", http.StatusFound)
		case "/redirect-http":
			http.Redirect(w, r, plain.URL+"/leak", http.StatusFound)
		case "/redirect-loop":
			http.Redirect(w, r, server.URL+"/redirect-loop", http.StatusFound)
		case "/oversize-length":
			w.Header().Set("Content-Length", "129")
			_, _ = w.Write(bytes.Repeat([]byte{'x'}, 129))
		case "/oversize-stream":
			w.(http.Flusher).Flush()
			_, _ = w.Write(bytes.Repeat([]byte{'x'}, 129))
		case "/encoded":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write([]byte("encoded material"))
		default:
			http.Error(w, "missing evidence", http.StatusNotFound)
		}
	})
	server = httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}}}
	server.StartTLS()
	defer server.Close()
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	// Go's -exec wrapper applies only to the first test process. Keep the TLS
	// trust-store child on the actual cross target as well (without binfmt changes).
	var executionPrefix []string
	if value := os.Getenv("WSEA_TEST_EXEC_PREFIX"); value != "" {
		if err := json.Unmarshal([]byte(value), &executionPrefix); err != nil {
			t.Fatal(err)
		}
		for _, arg := range executionPrefix {
			if arg == "" {
				t.Fatal("empty target execution argument")
			}
		}
	}
	for _, tc := range []struct{ name, roots, mode string }{{"private-CA-trusted", caPath, "trusted"}, {"private-CA-untrusted", emptyCA, "untrusted"}} {
		t.Run(tc.name, func(t *testing.T) {
			argv := append(append([]string{}, executionPrefix...), executable, "-test.run=^TestFetchHTTPSChild$", "-test.v")
			cmd := exec.Command(argv[0], argv[1:]...)
			env := []string{}
			for _, v := range os.Environ() {
				if strings.HasPrefix(v, "SSL_CERT_FILE=") || strings.HasPrefix(v, "SSL_CERT_DIR=") || strings.HasPrefix(v, "WSEA_HTTPS_TEST_") {
					continue
				}
				env = append(env, v)
			}
			env = append(env, "SSL_CERT_FILE="+tc.roots, "SSL_CERT_DIR="+emptyRoots, "WSEA_HTTPS_TEST_MODE="+tc.mode, "WSEA_HTTPS_TEST_URL="+server.URL)
			cmd.Env = env
			output, e := cmd.CombinedOutput()
			if e != nil {
				t.Fatalf("TLS child: %v\n%s", e, output)
			}
			t.Logf("%s", output)
		})
	}
	if n := plaintextRequests.Load(); n != 0 {
		t.Fatalf("HTTPS redirect contacted plaintext HTTP endpoint %d times", n)
	}
}

func TestFetchHTTPSChild(t *testing.T) {
	mode := os.Getenv("WSEA_HTTPS_TEST_MODE")
	base := os.Getenv("WSEA_HTTPS_TEST_URL")
	if mode == "" {
		t.Skip("only run in fresh isolated trust-store child")
	}
	if mode == "untrusted" {
		if _, e := FetchHTTPS(context.Background(), base+"/ok", 128); e == nil {
			t.Fatal("accepted server without trusting its private CA")
		}
		return
	}
	if mode != "trusted" || !strings.HasPrefix(base, "https://") {
		t.Fatal("invalid HTTPS child setup")
	}
	for _, path := range []string{"/ok", "/redirect-https"} {
		t.Run(path, func(t *testing.T) {
			b, e := FetchHTTPS(context.Background(), base+path, 128)
			if e != nil || string(b) != "authenticated evidence" {
				t.Fatalf("authenticated HTTPS: %q %v", b, e)
			}
		})
	}
	for _, tc := range []struct{ path, message string }{{"/oversize-length", "exceeds size limit"}, {"/oversize-stream", "exceeds size limit"}, {"/redirect-http", "HTTPS"}, {"/redirect-loop", "too many redirects"}, {"/encoded", "encoded evidence"}, {"/not-found", "HTTP 404"}} {
		t.Run(tc.path, func(t *testing.T) {
			_, e := FetchHTTPS(context.Background(), base+tc.path, 128)
			if e == nil || !strings.Contains(e.Error(), tc.message) {
				t.Fatalf("expected %s, got %v", tc.message, e)
			}
		})
	}
}
