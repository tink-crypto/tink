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
	"github.com/google/tink/go/prf"
	"github.com/google/tink/go/testkeyset"
	pb "github.com/google/tink/proto/testing/testing_api_go_grpc"
)

// PrfSetService implements the PrfSet testing service.
type PrfSetService struct {
	pb.PrfSetServer
}

func (s *PrfSetService) KeyIds(ctx context.Context, req *pb.PrfSetKeyIdsRequest) (*pb.PrfSetKeyIdsResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return &pb.PrfSetKeyIdsResponse{
			Result: &pb.PrfSetKeyIdsResponse_Err{err.Error()}}, nil
	}
	primitive, err := prf.NewPRFSet(handle)
	if err != nil {
		return &pb.PrfSetKeyIdsResponse{
			Result: &pb.PrfSetKeyIdsResponse_Err{err.Error()}}, nil
	}
	output := &pb.PrfSetKeyIdsResponse_Output{}
	output.PrimaryKeyId = primitive.PrimaryID
	for keyID := range primitive.PRFs {
		output.KeyId = append(output.KeyId, keyID)
	}
	return &pb.PrfSetKeyIdsResponse{
		Result: &pb.PrfSetKeyIdsResponse_Output_{output}}, nil
}

func (s *PrfSetService) Compute(ctx context.Context, req *pb.PrfSetComputeRequest) (*pb.PrfSetComputeResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return &pb.PrfSetComputeResponse{
			Result: &pb.PrfSetComputeResponse_Err{err.Error()}}, nil
	}
	primitive, err := prf.NewPRFSet(handle)
	if err != nil {
		return &pb.PrfSetComputeResponse{
			Result: &pb.PrfSetComputeResponse_Err{err.Error()}}, nil
	}
	output, err := primitive.PRFs[req.KeyId].ComputePRF(req.InputData, uint32(req.OutputLength))
	if err != nil {
		return &pb.PrfSetComputeResponse{
			Result: &pb.PrfSetComputeResponse_Err{err.Error()}}, nil
	}
	return &pb.PrfSetComputeResponse{
		Result: &pb.PrfSetComputeResponse_Output{output}}, nil
}
