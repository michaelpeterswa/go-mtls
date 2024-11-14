package mtls_test

import (
	"testing"

	"github.com/michaelpeterswa/go-mtls"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/credentials"
)

func TestNewX509Files(t *testing.T) {
	tests := []struct {
		Name                     string
		CertificateFile          string
		KeyFile                  string
		CertificateAuthorityFile string
		ExpectedX509Files        *mtls.X509Files
	}{
		{
			Name:                     "new device id",
			CertificateFile:          "/path/to/certificate",
			KeyFile:                  "/path/to/key",
			CertificateAuthorityFile: "/path/to/certificate-authority",
			ExpectedX509Files: &mtls.X509Files{
				CertificateFile:          "/path/to/certificate",
				KeyFile:                  "/path/to/key",
				CertificateAuthorityFile: "/path/to/certificate-authority",
				Fs:                       afero.NewOsFs(),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			x509Files := mtls.NewX509Files(tc.CertificateFile, tc.KeyFile, tc.CertificateAuthorityFile)
			assert.NotNil(t, x509Files)

			assert.Equal(t, tc.ExpectedX509Files, x509Files)
		})
	}
}

func TestGenerateTransportCredentials(t *testing.T) {
	tests := []struct {
		Name                     string
		MTLSConfig               mtls.MTLSConfig
		CertificateFile          string
		KeyFile                  string
		CertificateAuthorityFile string
		CertificateData          string
		KeyData                  string
		CertificateAuthorityData string
		ProtocolInfo             credentials.ProtocolInfo
	}{
		{
			Name:                     "new transport credentials",
			MTLSConfig:               mtls.Client,
			CertificateFile:          "path/to/certificate",
			KeyFile:                  "path/to/key",
			CertificateAuthorityFile: "path/to/certificate-authority",
			CertificateData: `-----BEGIN CERTIFICATE-----
MIIBmjCCAUCgAwIBAgIUFI5hEZXQYKFMsTMkniI3TZ8mL/AwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAxMJbG9jYWxob3N0MB4XDTI0MDUxNzA0NTAwMFoXDTM0MDUxNTA0
NTAwMFowFDESMBAGA1UEAxMJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEJLoqhpV4RegO07HJ0+cNkGnNxnt/ER2XH782UwDGU9M5r4+Yl2NKHxSA
PFn/yV7i+gFhcP4VO2if5TuZOCbmlqNwMG4wDgYDVR0PAQH/BAQDAgWgMBMGA1Ud
JQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFGyN5i5wN3rf
tXf8dnYENR1NL/qjMBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATAKBggqhkjO
PQQDAgNIADBFAiAp22ok76Guflhlm6mUWs7Xz4ikJjpzeJR3+B9GlENMDgIhANbi
iZhyDgsKkO2d/aP/RyV4YlIY67IQ2u+0AKg24lL3
-----END CERTIFICATE-----`,
			KeyData: `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIH2JRKcZMl1WXRm/q3rbu4D+6dsCwb284eWu/jWKPc4+oAoGCCqGSM49
AwEHoUQDQgAEJLoqhpV4RegO07HJ0+cNkGnNxnt/ER2XH782UwDGU9M5r4+Yl2NK
HxSAPFn/yV7i+gFhcP4VO2if5TuZOCbmlg==
-----END EC PRIVATE KEY-----`,
			CertificateAuthorityData: `-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIIQaeDraGyzGcwCgYIKoZIzj0EAwIwFDESMBAGA1UEAxMJ
bG9jYWxob3N0MB4XDTI0MDUxNzA0NDk0MFoXDTM0MDUxNTA0NTQ0MFowFDESMBAG
A1UEAxMJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjzQI38b6
Fmi/mXjMX7MUQjlMojO7YiOxfw6+UZ4dwinR/SMCSrOzuUcVZxRaQyGCyfHuj9my
ar75EcC71TceYqN9MHswDgYDVR0PAQH/BAQDAgGmMB0GA1UdJQQWMBQGCCsGAQUF
BwMBBggrBgEFBQcDAjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRfN1sOn3MA
RFAwOZa0BQ+LWw1ZMzAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwCgYIKoZI
zj0EAwIDSAAwRQIhAPd7KXDbTMYeVxuMmTNPvCdp1sm76270JpJ7gmVT9UuIAiBf
Lo2ro+7vxekbXLADMmQKiiJokr/HHhvuchtcRv4QnQ==
-----END CERTIFICATE-----`,
			ProtocolInfo: credentials.ProtocolInfo{
				ServerName:       "",
				SecurityProtocol: "tls",
				SecurityVersion:  "1.2",
				ProtocolVersion:  "",
			},
		},
		{
			Name:                     "new transport credentials",
			MTLSConfig:               mtls.Server,
			CertificateFile:          "path/to/certificate",
			KeyFile:                  "path/to/key",
			CertificateAuthorityFile: "path/to/certificate-authority",
			CertificateData: `-----BEGIN CERTIFICATE-----
MIIBmTCCAUCgAwIBAgIUeQXgLKGeih5ce3HaNBfS6LEStHQwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAxMJbG9jYWxob3N0MB4XDTI0MDUxNzA0NTAwMFoXDTM0MDUxNTA0
NTAwMFowFDESMBAGA1UEAxMJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEBelR9Kk4LlLuMX//IkBl3Pfvi63EST3i/U77ItgW4chfF2W5XqNtCNqz
o1CLMnjikU5j5iVeIpIN+Slv3GJeGKNwMG4wDgYDVR0PAQH/BAQDAgWgMBMGA1Ud
JQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOdJ9vLAL3fQ
UJHAez7Pw5oNh5bSMBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATAKBggqhkjO
PQQDAgNHADBEAiEAuJQFDmctAhwy6fpp6jXKUr9LSQpbBeTFKX6Uj1JTmzACHx4i
YUsW36Pinswid2hshDS884/AhV+gSzVE2I9w2qI=
-----END CERTIFICATE-----`,
			KeyData: `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILQUUaf267+CzLaNZ6OCpsmpIzjXMJFqEQOwNhOvSB1foAoGCCqGSM49
AwEHoUQDQgAEBelR9Kk4LlLuMX//IkBl3Pfvi63EST3i/U77ItgW4chfF2W5XqNt
CNqzo1CLMnjikU5j5iVeIpIN+Slv3GJeGA==
-----END EC PRIVATE KEY-----`,
			CertificateAuthorityData: `-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIIQaeDraGyzGcwCgYIKoZIzj0EAwIwFDESMBAGA1UEAxMJ
bG9jYWxob3N0MB4XDTI0MDUxNzA0NDk0MFoXDTM0MDUxNTA0NTQ0MFowFDESMBAG
A1UEAxMJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjzQI38b6
Fmi/mXjMX7MUQjlMojO7YiOxfw6+UZ4dwinR/SMCSrOzuUcVZxRaQyGCyfHuj9my
ar75EcC71TceYqN9MHswDgYDVR0PAQH/BAQDAgGmMB0GA1UdJQQWMBQGCCsGAQUF
BwMBBggrBgEFBQcDAjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRfN1sOn3MA
RFAwOZa0BQ+LWw1ZMzAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwCgYIKoZI
zj0EAwIDSAAwRQIhAPd7KXDbTMYeVxuMmTNPvCdp1sm76270JpJ7gmVT9UuIAiBf
Lo2ro+7vxekbXLADMmQKiiJokr/HHhvuchtcRv4QnQ==
-----END CERTIFICATE-----`,
			ProtocolInfo: credentials.ProtocolInfo{
				ServerName:       "",
				SecurityProtocol: "tls",
				SecurityVersion:  "1.2",
				ProtocolVersion:  "",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			memFs := afero.NewMemMapFs()

			err := afero.WriteFile(memFs, tc.CertificateFile, []byte(tc.CertificateData), 0644)
			assert.NoError(t, err)

			err = afero.WriteFile(memFs, tc.KeyFile, []byte(tc.KeyData), 0644)
			assert.NoError(t, err)

			err = afero.WriteFile(memFs, tc.CertificateAuthorityFile, []byte(tc.CertificateAuthorityData), 0644)
			assert.NoError(t, err)

			x509Files := mtls.NewX509Files(tc.CertificateFile, tc.KeyFile, tc.CertificateAuthorityFile, mtls.WithFilesystem(memFs))

			transportCreds, err := x509Files.GenerateTransportCredentials(tc.MTLSConfig)
			assert.NoError(t, err)

			assert.Equal(t, tc.ProtocolInfo, transportCreds.Info())
		})
	}
}
