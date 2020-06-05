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

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testkeyset"
	pb "github.com/google/tink/proto/testing/testing_api_go_grpc"
)

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
