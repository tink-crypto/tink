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
	"fmt"
	"io"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/streamingaead"
	"github.com/google/tink/go/testkeyset"
	pb "github.com/google/tink/testing/go/proto/testing_api_go_grpc"
)

const (
	decryptChunkSize = 2
)

// StreamingAEADService implements the StreamingAead testing service.
type StreamingAEADService struct {
	pb.StreamingAeadServer
}

func (s *StreamingAEADService) Create(ctx context.Context, req *pb.CreationRequest) (*pb.CreationResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	_, err = streamingaead.New(handle)
	if err != nil {
		return &pb.CreationResponse{Err: err.Error()}, nil
	}
	return &pb.CreationResponse{}, nil
}

func (s *StreamingAEADService) Encrypt(ctx context.Context, req *pb.StreamingAeadEncryptRequest) (*pb.StreamingAeadEncryptResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return &pb.StreamingAeadEncryptResponse{
			Result: &pb.StreamingAeadEncryptResponse_Err{err.Error()}}, nil
	}
	cipher, err := streamingaead.New(handle)
	if err != nil {
		return &pb.StreamingAeadEncryptResponse{
			Result: &pb.StreamingAeadEncryptResponse_Err{err.Error()}}, nil
	}
	ciphertextBuf := &bytes.Buffer{}
	w, err := cipher.NewEncryptingWriter(ciphertextBuf, req.AssociatedData)
	if err != nil {
		errMsg := fmt.Sprintf("cannot create an encrypt writer: %v", err)
		return &pb.StreamingAeadEncryptResponse{
			Result: &pb.StreamingAeadEncryptResponse_Err{errMsg}}, nil
	}
	n, err := w.Write(req.Plaintext)
	if err != nil {
		errMsg := fmt.Sprintf("error writing to an encrypt writer: %v", err)
		return &pb.StreamingAeadEncryptResponse{
			Result: &pb.StreamingAeadEncryptResponse_Err{errMsg}}, nil
	}
	if n != len(req.Plaintext) {
		errMsg := fmt.Sprintf("unexpected number of bytes written. Got=%d;want=%d", n, len(req.Plaintext))
		return &pb.StreamingAeadEncryptResponse{
			Result: &pb.StreamingAeadEncryptResponse_Err{errMsg}}, nil
	}
	if err := w.Close(); err != nil {
		errMsg := fmt.Sprintf("error closing writer: %v", err)
		return &pb.StreamingAeadEncryptResponse{
			Result: &pb.StreamingAeadEncryptResponse_Err{errMsg}}, nil
	}
	return &pb.StreamingAeadEncryptResponse{
		Result: &pb.StreamingAeadEncryptResponse_Ciphertext{ciphertextBuf.Bytes()}}, nil
}

func (s *StreamingAEADService) Decrypt(ctx context.Context, req *pb.StreamingAeadDecryptRequest) (*pb.StreamingAeadDecryptResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return &pb.StreamingAeadDecryptResponse{
			Result: &pb.StreamingAeadDecryptResponse_Err{err.Error()}}, nil
	}
	cipher, err := streamingaead.New(handle)
	if err != nil {
		return &pb.StreamingAeadDecryptResponse{
			Result: &pb.StreamingAeadDecryptResponse_Err{err.Error()}}, nil
	}
	r, err := cipher.NewDecryptingReader(bytes.NewBuffer(req.Ciphertext), req.AssociatedData)
	if err != nil {
		errMsg := fmt.Sprintf("cannot create an encrypt reader: %v", err)
		return &pb.StreamingAeadDecryptResponse{
			Result: &pb.StreamingAeadDecryptResponse_Err{errMsg}}, nil
	}
	plaintextBuf := &bytes.Buffer{}
	var (
		chunk = make([]byte, decryptChunkSize)
		eof   = false
	)
	for !eof {
		n, err := r.Read(chunk)
		if err != nil && err != io.EOF {
			errMsg := fmt.Sprintf("error reading chunk: %v", err)
			return &pb.StreamingAeadDecryptResponse{
				Result: &pb.StreamingAeadDecryptResponse_Err{errMsg}}, nil
		}
		eof = err == io.EOF
		plaintextBuf.Write(chunk[:n])
	}
	return &pb.StreamingAeadDecryptResponse{
		Result: &pb.StreamingAeadDecryptResponse_Plaintext{plaintextBuf.Bytes()}}, nil
}
