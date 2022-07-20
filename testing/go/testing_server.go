// Copyright 2020 Google LLC
//
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
	"fmt"
	"log"
	"net"

	"flag"
	// context is used to cancel outstanding requests
	"google.golang.org/grpc"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/testing/fakekms"
	"github.com/google/tink/testing/go/services"
	pbgrpc "github.com/google/tink/testing/go/proto/testing_api_go_grpc"
)

var (
	port = flag.Int("port", 10000, "The server port")
)

func main() {
	flag.Parse()
	client, err := fakekms.NewClient("fake-kms://")
	if err != nil {
		log.Fatalf("Failed to generate new FakeKMSClient: %v", err)
	}
	registry.RegisterKMSClient(client)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Server failed to listen: %v", err)
	}
	log.Printf("Server is now listening on port: %d", *port)
	server := grpc.NewServer()
	if err != nil {
		log.Fatalf("Failed to create new grpcprod server: %v", err)
	}
	pbgrpc.RegisterMetadataServer(server, &services.MetadataService{})
	pbgrpc.RegisterKeysetServer(server, &services.KeysetService{})
	pbgrpc.RegisterAeadServer(server, &services.AEADService{})
	pbgrpc.RegisterDeterministicAeadServer(server, &services.DeterministicAEADService{})
	pbgrpc.RegisterHybridServer(server, &services.HybridService{})
	pbgrpc.RegisterJwtServer(server, &services.JWTService{})
	pbgrpc.RegisterMacServer(server, &services.MacService{})
	pbgrpc.RegisterPrfSetServer(server, &services.PrfSetService{})
	pbgrpc.RegisterSignatureServer(server, &services.SignatureService{})
	pbgrpc.RegisterStreamingAeadServer(server, &services.StreamingAEADService{})
	server.Serve(lis)
}
