package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/spf13/afero"
	"google.golang.org/grpc/credentials"
)

const (
	Client MTLSConfig = iota // Client-mode Mutual TLS
	Server                   // Server-mode Mutual TLS
)

// MTLSConfig is a type to support the Client/Server mode iota
type MTLSConfig int

// X509Files is a struct to hold the paths to the certificate, key, and certificate authority files
type X509Files struct {
	CertificateFile          string
	KeyFile                  string
	CertificateAuthorityFile string

	Fs afero.Fs
}

// X509FilesOption is a type to support the functional options pattern
type X509FilesOption func(*X509Files)

// NewX509Files creates a new X509Files struct, with file-paths for the certificate, key, and certificate authority
func NewX509Files(certificateFile string, keyFile string, certificateAuthorityFile string, options ...X509FilesOption) *X509Files {

	x509Files := &X509Files{
		CertificateFile:          certificateFile,
		KeyFile:                  keyFile,
		CertificateAuthorityFile: certificateAuthorityFile,
		Fs:                       afero.NewOsFs(),
	}

	// functional options pattern
	for _, option := range options {
		option(x509Files)
	}

	return x509Files
}

// WithFilesystem is an option to set the underlying filesystem for loading the x509 files
func WithFilesystem(fs afero.Fs) X509FilesOption {
	return func(x5f *X509Files) {
		x5f.Fs = fs
	}
}

// GenerateTransportCredentials generates the TransportCredentials for the given MTLSConfig
func (x509Files *X509Files) GenerateTransportCredentials(mtlsConfig MTLSConfig) (credentials.TransportCredentials, error) {
	certificateData, err := x509Files.readAllFile(x509Files.CertificateFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	keyData, err := x509Files.readAllFile(x509Files.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	certificate, err := tls.X509KeyPair(certificateData, keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to load x509 key pair: %w", err)
	}

	certificateAuthorityData, err := x509Files.readAllFile(x509Files.CertificateAuthorityFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate authority file: %w", err)
	}

	certificatePool := x509.NewCertPool()
	if !certificatePool.AppendCertsFromPEM(certificateAuthorityData) {
		return nil, fmt.Errorf("failed to append certificate authority to pool")
	}

	var tlsConfig *tls.Config
	switch mtlsConfig {
	case Client:
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{certificate},
			RootCAs:      certificatePool,
		}
	case Server:
		tlsConfig = &tls.Config{
			ClientAuth:   tls.RequireAndVerifyClientCert,
			Certificates: []tls.Certificate{certificate},
			ClientCAs:    certificatePool,
		}
	default:
		return nil, fmt.Errorf("invalid MTLSConfig: %d", mtlsConfig)
	}

	return credentials.NewTLS(tlsConfig), nil
}

func (x509Files *X509Files) readAllFile(path string) ([]byte, error) {
	file, err := x509Files.Fs.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return data, nil
}
