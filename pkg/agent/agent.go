package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/goten4/ucerts/internal/config"
	"github.com/goten4/ucerts/internal/format"
	"github.com/goten4/ucerts/internal/funcs"
)

type Server struct {
	UnimplementedAgentServer
}

var (
	ErrInternal           = status.Error(codes.Internal, "Internal server error")
	ErrInvalidCertPath    = errors.New("invalid cert path")
	ErrInvalidKeyPath     = errors.New("invalid key path")
	ErrInvalidCaPath      = errors.New("invalid CA path")
	ErrInvalidX509KeyPair = errors.New("invalid X509 key pair")
	ErrAppendCA           = errors.New("could not append CA to pool")
	systemCertPool        = x509.SystemCertPool
)

func Start(conf config.ServerGRPC) funcs.Stop {

	lis, err := net.Listen("tcp", conf.Listen)
	if err != nil {
		logrus.Fatalf("Failed to listen: %v", err)
		return funcs.NoOp
	}

	opts := []grpc.ServerOption{
		// https://github.com/grpc/grpc/blob/master/doc/keepalive.md
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: conf.KeepAlivePolicyMinTime, PermitWithoutStream: true}),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: conf.KeepAliveTime, Timeout: conf.KeepAliveTimeout}),
		grpc.UnaryInterceptor(unaryTraceInterceptor),
	}

	if conf.TLSEnable {
		tlsCredentials, err := loadTLSServerCredentials(conf)
		if err != nil {
			logrus.Fatalf("Failed to load gRCP server TLS credentials: %v", err)
			return funcs.NoOp
		}
		opts = append(opts, grpc.Creds(tlsCredentials))
	}

	s := grpc.NewServer(opts...)
	RegisterAgentServer(s, &Server{})

	go func() {
		logrus.Infof("Starting agent gRPC server on %s", conf.Listen)
		if err := s.Serve(lis); err != nil {
			logrus.Fatalf("Failed to serve: %v", err)
		}
	}()

	return func() {
		s.GracefulStop()
	}
}

func (s *Server) StoreCertificate(_ context.Context, req *Request) (*emptypb.Empty, error) {

	if err := validate(req); err != nil {
		return &emptypb.Empty{}, err
	}

	if err := WritePemToFile(req.GetPublicKeyData(), req.GetPublicKeyPath()); err != nil {
		if errors.Is(err, ErrInvalidPEMBlock) {
			return &emptypb.Empty{}, status.Error(codes.InvalidArgument, "Invalid public_key_data")
		}
		return &emptypb.Empty{}, ErrInternal
	}

	if err := WritePemToFile(req.GetPrivateKeyData(), req.GetPrivateKeyPath()); err != nil {
		if errors.Is(err, ErrInvalidPEMBlock) {
			return &emptypb.Empty{}, status.Error(codes.InvalidArgument, "Invalid private_key_data")
		}
		return &emptypb.Empty{}, ErrInternal
	}

	if req.GetCaPath() == "" {
		return &emptypb.Empty{}, nil
	}

	if err := WritePemToFile(req.GetCaData(), req.GetCaPath()); err != nil {
		if errors.Is(err, ErrInvalidPEMBlock) {
			return &emptypb.Empty{}, status.Error(codes.InvalidArgument, "Invalid ca_data")
		}
		return &emptypb.Empty{}, ErrInternal
	}

	return &emptypb.Empty{}, nil
}

func validate(req *Request) error {
	if req.GetPublicKeyPath() == "" {
		return status.Error(codes.InvalidArgument, "Missing public_key_path")
	}
	if len(req.GetPublicKeyData()) == 0 {
		return status.Error(codes.InvalidArgument, "Missing public_key_data")
	}
	if req.GetPrivateKeyPath() == "" {
		return status.Error(codes.InvalidArgument, "Missing private_key_path")
	}
	if len(req.GetPrivateKeyData()) == 0 {
		return status.Error(codes.InvalidArgument, "Missing private_key_data")
	}
	if req.GetCaPath() != "" && len(req.GetCaData()) == 0 {
		return status.Error(codes.InvalidArgument, "Missing ca_data")
	}
	return nil
}

func unaryTraceInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	start := time.Now()
	logrus.Tracef("[%s] gRPC Request: <%v>", filepath.Base(info.FullMethod), req)
	resp, err := handler(ctx, req)
	if err != nil {
		logrus.Tracef("[%s] gRPC Failure in %s: %s", filepath.Base(info.FullMethod), time.Since(start), err)
		return resp, err
	}
	logrus.Tracef("[%s] gRPC Success in %s", filepath.Base(info.FullMethod), time.Since(start))
	return resp, nil
}

func loadTLSServerCredentials(conf config.ServerGRPC) (credentials.TransportCredentials, error) {

	certs, err := loadCertificatesTLS(conf.TLSCertPath, conf.TLSKeyPath, conf.TLSCAPath)
	if err != nil {
		return nil, err
	}

	// Create the credentials and return it
	tlsConfig := &tls.Config{
		Certificates: certs,
		MinVersion:   tls.VersionTLS13,
	}

	if conf.MTLSEnable {
		caCerts, err := loadCA(conf.TLSCAPath)
		if err != nil {
			return nil, err
		}
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = caCerts
	}

	return credentials.NewTLS(tlsConfig), nil
}

func loadCertificatesTLS(certPath, keyPath, caPath string) ([]tls.Certificate, error) {

	certPEMBlock, err := os.ReadFile(certPath)
	if err != nil {
		return []tls.Certificate{}, fmt.Errorf(format.WrapErrors, ErrInvalidCertPath, err)
	}

	keyPEMBlock, err := os.ReadFile(keyPath)
	if err != nil {
		return []tls.Certificate{}, fmt.Errorf(format.WrapErrors, ErrInvalidKeyPath, err)
	}

	if caPath != "" {
		caPEMBlock, err := os.ReadFile(caPath)
		if err != nil {
			return []tls.Certificate{}, fmt.Errorf(format.WrapErrors, ErrInvalidCaPath, err)
		}
		certPEMBlock = append(certPEMBlock, caPEMBlock...)
	}

	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return []tls.Certificate{}, fmt.Errorf(format.WrapErrors, ErrInvalidX509KeyPair, err)
	}

	return []tls.Certificate{cert}, nil
}

func loadCA(caPath string) (*x509.CertPool, error) {

	rootCAs, _ := systemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	if caPath != "" {
		caPEMBlock, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf(format.WrapErrors, ErrInvalidCaPath, err)
		}
		if !rootCAs.AppendCertsFromPEM(caPEMBlock) {
			return nil, ErrAppendCA
		}
	}

	return rootCAs, nil
}
