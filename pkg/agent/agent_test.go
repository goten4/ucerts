package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/goten4/ucerts/internal/config"
)

type grpcLogger struct {
	*logrus.Logger
}

func (logger grpcLogger) V(l int) bool {
	return logger.IsLevelEnabled(logrus.Level(l))
}

func TestStart(t *testing.T) {
	logrus.SetLevel(logrus.WarnLevel)
	grpclog.SetLoggerV2(grpcLogger{logrus.StandardLogger()})

	for name, tt := range map[string]struct {
		serverConfig config.ServerGRPC
	}{
		"unsecure": {
			serverConfig: config.ServerGRPC{Listen: "127.0.0.1:14293", TLSEnable: false, MTLSEnable: false},
		},
		"TLS": {
			serverConfig: config.ServerGRPC{
				Listen:      "127.0.0.1:14293",
				TLSEnable:   true,
				MTLSEnable:  false,
				TLSCAPath:   "testdata/grpc/ca.crt",
				TLSCertPath: "testdata/grpc/server.crt",
				TLSKeyPath:  "testdata/grpc/server.key",
			},
		},
		"mTLS": {
			serverConfig: config.ServerGRPC{
				Listen:      "127.0.0.1:14293",
				TLSEnable:   true,
				MTLSEnable:  true,
				TLSCAPath:   "testdata/grpc/ca.crt",
				TLSCertPath: "testdata/grpc/server.crt",
				TLSKeyPath:  "testdata/grpc/server.key",
			},
		},
	} {
		tc := tt // Use local variable to avoid closure-caused race condition
		t.Run(name, func(t *testing.T) {
			tc.serverConfig.KeepAlivePolicyMinTime = 5 * time.Minute
			tc.serverConfig.KeepAliveTime = 2 * time.Hour
			tc.serverConfig.KeepAliveTimeout = 20 * time.Second

			gracefulStop := Start(tc.serverConfig)
			t.Cleanup(gracefulStop)

			creds := insecure.NewCredentials()
			if tc.serverConfig.TLSEnable {
				caCerts, err := loadCA(tc.serverConfig.TLSCAPath)
				require.NoError(t, err)
				tlsConfig := &tls.Config{RootCAs: caCerts}
				if tc.serverConfig.MTLSEnable {
					certs, err := loadCertificatesTLS("testdata/grpc/client.crt", "testdata/grpc/client.key", "")
					require.NoError(t, err)
					tlsConfig.Certificates = certs
				}
				creds = credentials.NewTLS(tlsConfig)
			}
			conn, err := grpc.Dial(tc.serverConfig.Listen, grpc.WithTransportCredentials(creds),
				grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: time.Duration(1<<63 - 1), Timeout: 20 * time.Second, PermitWithoutStream: true}))
			require.NoError(t, err)

			cancelFunc := waitForPermanentConnectionState(t, conn)
			t.Cleanup(cancelFunc)

			assert.Equal(t, connectivity.Ready, conn.GetState())

			_ = conn.Close()

			assert.Equal(t, connectivity.Shutdown, conn.GetState())
		})
	}
}

func waitForPermanentConnectionState(t *testing.T, newConn *grpc.ClientConn) context.CancelFunc {
	t.Helper()
	ctx, cancelFunc := context.WithTimeout(context.Background(), 2*time.Second)
	if !newConn.WaitForStateChange(ctx, connectivity.Idle) {
		t.Fatal("Connection state is still IDLE after 2 seconds !")
	}
	if !newConn.WaitForStateChange(ctx, connectivity.Connecting) {
		t.Fatal("Connection state is still CONNECTING after 2 seconds !")
	}
	return cancelFunc
}

func TestServer_StoreCertificate(t *testing.T) {
	s := &Server{}
	var data [][]byte
	var files []string
	mock(t, &WritePemToFile, func(b []byte, file string) error {
		data = append(data, b)
		files = append(files, file)
		return nil
	})

	got, err := s.StoreCertificate(context.Background(), &Request{
		PublicKeyData:  []byte("public_key_data"),
		PublicKeyPath:  "public_key_path",
		PrivateKeyData: []byte("private_key_data"),
		PrivateKeyPath: "private_key_path",
		CaData:         []byte("ca_data"),
		CaPath:         "ca_path",
	})

	require.NoError(t, err)
	assert.Equal(t, &emptypb.Empty{}, got)
	assert.Equal(t, [][]byte{[]byte("public_key_data"), []byte("private_key_data"), []byte("ca_data")}, data)
	assert.Equal(t, []string{"public_key_path", "private_key_path", "ca_path"}, files)
}

func TestServer_StoreCertificate_WithError(t *testing.T) {
	s := &Server{}

	for name, tt := range map[string]struct {
		req           *Request
		expectedError error
	}{
		"Missing public_key_path": {
			req:           &Request{},
			expectedError: status.Error(codes.InvalidArgument, "Missing public_key_path"),
		},
		"Missing public_key_data": {
			req:           &Request{PublicKeyPath: "public_key"},
			expectedError: status.Error(codes.InvalidArgument, "Missing public_key_data"),
		},
		"Missing private_key_path": {
			req:           &Request{PublicKeyData: []byte("valid"), PublicKeyPath: "public_key"},
			expectedError: status.Error(codes.InvalidArgument, "Missing private_key_path"),
		},
		"Missing private_key_data": {
			req:           &Request{PublicKeyData: []byte("valid"), PublicKeyPath: "public_key", PrivateKeyPath: "private_key"},
			expectedError: status.Error(codes.InvalidArgument, "Missing private_key_data"),
		},
		"Missing ca_data": {
			req:           &Request{PublicKeyData: []byte("valid"), PublicKeyPath: "public_key", PrivateKeyData: []byte("valid"), PrivateKeyPath: "private_key", CaPath: "ca"},
			expectedError: status.Error(codes.InvalidArgument, "Missing ca_data"),
		},
		"Invalid public_key_data": {
			req:           &Request{PublicKeyData: []byte("invalid"), PublicKeyPath: "public_key", PrivateKeyData: []byte("valid"), PrivateKeyPath: "private_key"},
			expectedError: status.Error(codes.InvalidArgument, "Invalid public_key_data"),
		},
		"Invalid private_key_data": {
			req:           &Request{PublicKeyData: []byte("valid"), PublicKeyPath: "public_key", PrivateKeyData: []byte("invalid"), PrivateKeyPath: "private_key"},
			expectedError: status.Error(codes.InvalidArgument, "Invalid private_key_data"),
		},
		"Invalid ca_data": {
			req:           &Request{PublicKeyData: []byte("valid"), PublicKeyPath: "public_key", PrivateKeyData: []byte("valid"), PrivateKeyPath: "private_key", CaData: []byte("invalid"), CaPath: "ca"},
			expectedError: status.Error(codes.InvalidArgument, "Invalid ca_data"),
		},
		"Internal error on write public key": {
			req:           &Request{PublicKeyData: []byte("internal"), PublicKeyPath: "public_key", PrivateKeyData: []byte("valid"), PrivateKeyPath: "private_key"},
			expectedError: status.Error(codes.Internal, "Internal server error"),
		},
		"Internal error on write private key": {
			req:           &Request{PublicKeyData: []byte("valid"), PublicKeyPath: "public_key", PrivateKeyData: []byte("internal"), PrivateKeyPath: "private_key"},
			expectedError: status.Error(codes.Internal, "Internal server error"),
		},
		"Internal error on write ca": {
			req:           &Request{PublicKeyData: []byte("valid"), PublicKeyPath: "public_key", PrivateKeyData: []byte("valid"), PrivateKeyPath: "private_key", CaData: []byte("internal"), CaPath: "ca"},
			expectedError: status.Error(codes.Internal, "Internal server error"),
		},
	} {
		tc := tt // Use local variable to avoid closure-caused race condition
		t.Run(name, func(t *testing.T) {
			mock(t, &WritePemToFile, func(b []byte, _ string) error {
				switch string(b) {
				case "invalid":
					return ErrInvalidPEMBlock
				case "internal":
					return errors.New("error")
				}
				return nil
			})

			_, err := s.StoreCertificate(context.Background(), tc.req)

			assert.ErrorIs(t, err, tc.expectedError)
		})
	}
}
