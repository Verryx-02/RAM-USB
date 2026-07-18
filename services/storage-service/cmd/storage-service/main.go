// Command storage-service wires every already-implemented Storage-Service
// package into a running mTLS HTTP server: ST-F-01's connection-acceptance
// TLS config, the httpapi handler (ST-F-06, ST-F-10), and the real
// OS-level POSIX-user creation (ST-F-06, ST-F-08) via execrunner.Real and
// posixuser.RealDirMaker.
//
// Storage-Service has only one mTLS listener here, unlike Database-Vault's
// two: its other inbound surface is SFTP itself (ST-F-03/ST-F-04),
// handled entirely by sshd outside this Go process, not by an HTTP
// listener. ST-F-11's AuthorizedKeysCommand is a separate, already-scoped
// binary (services/storage-service/internal/pubkeylookup), not wired here.
// ST-F-12/ST-F-13 (metrics) have no implementation anywhere in
// Storage-Service yet and are deliberately not wired here either.
//
// Every configuration value is read from an environment variable, per
// CONTRIBUTING.md §7's "cmd/<service>/main.go: wiring, config loading,
// dependency construction, server start." Env var names follow the same
// RAM_USB_STORAGE_SERVICE_* convention already established by
// database-vault/cmd/database-vault/main.go's own
// RAM_USB_DATABASE_VAULT_* names.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Verryx-02/RAM-USB/services/storage-service/internal/execrunner"
	"github.com/Verryx-02/RAM-USB/services/storage-service/internal/httpapi"
	"github.com/Verryx-02/RAM-USB/services/storage-service/internal/posixuser"
	"github.com/Verryx-02/RAM-USB/services/storage-service/internal/server"
)

// Env var names this task introduces, mirroring database-vault/cmd's own
// RAM_USB_DATABASE_VAULT_* naming convention.
const (
	// envListenAddr is the address this server listens on for incoming
	// mTLS connections from Database-Vault (ST-F-01, ST-F-06).
	envListenAddr = "RAM_USB_STORAGE_SERVICE_LISTEN_ADDR"

	// envServerCert/envServerKey locate this server's own TLS certificate
	// and private key, presented to Database-Vault during the mTLS
	// handshake.
	envServerCert = "RAM_USB_STORAGE_SERVICE_TLS_CERT"
	envServerKey  = "RAM_USB_STORAGE_SERVICE_TLS_KEY"

	// envClientCA locates the CA certificate bundle (PEM) trusted to have
	// issued Database-Vault's client certificate (ST-F-01).
	envClientCA = "RAM_USB_STORAGE_SERVICE_CLIENT_CA"
)

func main() {
	if err := run(); err != nil {
		slog.Error("storage-service: fatal startup error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	listenAddr, err := requireEnv(envListenAddr)
	if err != nil {
		return err
	}

	tlsConfig, err := buildServerTLSConfig()
	if err != nil {
		return fmt.Errorf("build server tls config: %w", err)
	}

	creator := &posixuser.Creator{
		Runner:   execrunner.Real{},
		DirMaker: posixuser.RealDirMaker{},
	}

	handler := &httpapi.Handler{
		Creator: creator,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(httpapi.CreateUserPath, handler.CreateUser)

	httpServer := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		slog.Info("storage-service: listening", "addr", listenAddr)
		// TLSConfig already carries the certificate/key pair (via
		// server.NewTLSConfig), so ListenAndServeTLS is called with empty
		// file paths per net/http's documented convention for that case.
		serveErr <- httpServer.ListenAndServeTLS("", "")
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown listener: %w", err)
		}
		return nil
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve listener: %w", err)
	}
}

// requireEnv reads name from the environment, failing closed (RD-04) if
// it is unset or empty.
func requireEnv(name string) (string, error) {
	value, ok := os.LookupEnv(name)
	if !ok || value == "" {
		return "", fmt.Errorf("required environment variable %s is not set", name)
	}
	return value, nil
}

// loadCertPool reads a PEM certificate bundle from path and returns a
// pool containing it.
func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from this process's own operator-controlled env var config, not from any request input
	if err != nil {
		return nil, fmt.Errorf("read CA bundle %s: %w", path, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no certificates found in CA bundle %s", path)
	}
	return pool, nil
}

// buildServerTLSConfig assembles ST-F-01's mTLS server configuration from
// this server's own certificate/key and the CA pool trusted to have
// issued Database-Vault's certificate.
func buildServerTLSConfig() (*tls.Config, error) {
	certPath, err := requireEnv(envServerCert)
	if err != nil {
		return nil, err
	}
	keyPath, err := requireEnv(envServerKey)
	if err != nil {
		return nil, err
	}
	caPath, err := requireEnv(envClientCA)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load server certificate/key: %w", err)
	}

	clientCAs, err := loadCertPool(caPath)
	if err != nil {
		return nil, err
	}

	return server.NewTLSConfig(cert, clientCAs), nil
}
