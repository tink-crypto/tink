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

package services

import (
	"bytes"
	"context"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/testkeyset"
	pb "github.com/google/tink/testing/go/proto/testing_api_go_grpc"
)

// SignatureService implements the Signature testing service.
type SignatureService struct {
	pb.SignatureServer
}

func (s *SignatureService) Sign(ctx context.Context, req *pb.SignatureSignRequest) (*pb.SignatureSignResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.PrivateKeyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return &pb.SignatureSignResponse{
			Result: &pb.SignatureSignResponse_Err{err.Error()}}, nil
	}
	signer, err := signature.NewSigner(handle)
	if err != nil {
		return &pb.SignatureSignResponse{
			Result: &pb.SignatureSignResponse_Err{err.Error()}}, nil
	}
	sigValue, err := signer.Sign(req.Data)
	if err != nil {
		return &pb.SignatureSignResponse{
			Result: &pb.SignatureSignResponse_Err{err.Error()}}, nil
	}
	return &pb.SignatureSignResponse{
		Result: &pb.SignatureSignResponse_Signature{sigValue}}, nil
}

func (s *SignatureService) Verify(ctx context.Context, req *pb.SignatureVerifyRequest) (*pb.SignatureVerifyResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.PublicKeyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return &pb.SignatureVerifyResponse{Err: err.Error()}, nil
	}
	verifier, err := signature.NewVerifier(handle)
	if err != nil {
		return &pb.SignatureVerifyResponse{Err: err.Error()}, nil
	}
	err = verifier.Verify(req.Signature, req.Data)
	if err != nil {
		return &pb.SignatureVerifyResponse{Err: err.Error()}, nil
	}
	return &pb.SignatureVerifyResponse{}, nil
}
