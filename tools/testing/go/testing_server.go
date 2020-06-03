// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

// Package main is implements an gRPC server for testing_api.
package main

import (
	"bytes"
	"context"
	"fmt"
	"net"

	"flag"
	// context is used to cancel outstanding requests
	"google3/base/go/log"
	"google3/net/grpc/go/grpcprod"
	"google3/third_party/golang/grpc/grpc"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testkeyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	pbgrpc "google3/third_party/tink/tools/testing/testing_api_go_grpc"
	pb "google3/third_party/tink/tools/testing/testing_api_go_proto"

	"github.com/golang/protobuf/proto"
)

var (
	port = flag.Int("port", 10000, "The server port")
)

// KeysetService implements the Keyset testing service.
type KeysetService struct {
}

func (s *KeysetService) Generate(ctx context.Context, req *pb.GenerateKeysetRequest) (*pb.KeysetResponse, error) {
	template := &tinkpb.KeyTemplate{}
	err := proto.Unmarshal(req.Template, template)
	if err != nil {
		return &pb.KeysetResponse{
			Result: &pb.KeysetResponse_Err{err.Error()}}, nil
	}
	handle, err := keyset.NewHandle(template)
	if err != nil {
		return &pb.KeysetResponse{
			Result: &pb.KeysetResponse_Err{err.Error()}}, nil
	}
	buf := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(buf)
	err = testkeyset.Write(handle, writer)
	if err != nil {
		return &pb.KeysetResponse{
			Result: &pb.KeysetResponse_Err{err.Error()}}, nil
	}
	return &pb.KeysetResponse{
		Result: &pb.KeysetResponse_Keyset{buf.Bytes()}}, nil
}

// AeadService implements the Aead testing service.
type AeadService struct {
}

func (s *AeadService) Encrypt(ctx context.Context, req *pb.AeadEncryptRequest) (*pb.CiphertextResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return &pb.CiphertextResponse{
			Result: &pb.CiphertextResponse_Err{err.Error()}}, nil
	}
	cipher, err := aead.New(handle)
	if err != nil {
		return &pb.CiphertextResponse{
			Result: &pb.CiphertextResponse_Err{err.Error()}}, nil
	}
	ciphertext, err := cipher.Encrypt(req.Plaintext, req.AssociatedData)
	if err != nil {
		return &pb.CiphertextResponse{
			Result: &pb.CiphertextResponse_Err{err.Error()}}, nil
	}
	return &pb.CiphertextResponse{
		Result: &pb.CiphertextResponse_Ciphertext{ciphertext}}, nil
}

func (s *AeadService) Decrypt(ctx context.Context, req *pb.AeadDecryptRequest) (*pb.PlaintextResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return &pb.PlaintextResponse{
			Result: &pb.PlaintextResponse_Err{err.Error()}}, nil
	}
	cipher, err := aead.New(handle)
	if err != nil {
		return &pb.PlaintextResponse{
			Result: &pb.PlaintextResponse_Err{err.Error()}}, nil
	}
	plaintext, err := cipher.Decrypt(req.Ciphertext, req.AssociatedData)
	if err != nil {
		return &pb.PlaintextResponse{
			Result: &pb.PlaintextResponse_Err{err.Error()}}, nil
	}
	return &pb.PlaintextResponse{
		Result: &pb.PlaintextResponse_Plaintext{plaintext}}, nil
}

func main() {
	google.Init()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Exitf("Server failed to listen: %v", err)
	}
	log.Infof("Server is now listening on port: %d", *port)
	var serverOpts []grpc.ServerOption
	serverConfig := grpcprod.DefaultServerConfig()
	server, err := grpcprod.NewServer(serverConfig, serverOpts...)
	if err != nil {
		log.Exitf("Failed to create new grpcprod server: %v", err)
	}
	pbgrpc.RegisterKeysetServer(server.GRPC, &KeysetService{})
	pbgrpc.RegisterAeadServer(server.GRPC, &AeadService{})
	server.Serve(lis)
}
