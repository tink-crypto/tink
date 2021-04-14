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
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/testkeyset"
	pb "github.com/google/tink/proto/testing/testing_api_go_grpc"
)

// MacService implements the MAC testing service.
type MacService struct {
}

func (s *MacService) ComputeMac(ctx context.Context, req *pb.ComputeMacRequest) (*pb.ComputeMacResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return &pb.ComputeMacResponse{
			Result: &pb.ComputeMacResponse_Err{err.Error()}}, nil
	}
	primitive, err := mac.New(handle)
	if err != nil {
		return &pb.ComputeMacResponse{
			Result: &pb.ComputeMacResponse_Err{err.Error()}}, nil
	}
	macValue, err := primitive.ComputeMAC(req.Data)
	if err != nil {
		return &pb.ComputeMacResponse{
			Result: &pb.ComputeMacResponse_Err{err.Error()}}, nil
	}
	return &pb.ComputeMacResponse{
		Result: &pb.ComputeMacResponse_MacValue{macValue}}, nil
}

func (s *MacService) VerifyMac(ctx context.Context, req *pb.VerifyMacRequest) (*pb.VerifyMacResponse, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(req.Keyset))
	handle, err := testkeyset.Read(reader)
	if err != nil {
		return &pb.VerifyMacResponse{Err: err.Error()}, nil
	}
	primitive, err := mac.New(handle)
	if err != nil {
		return &pb.VerifyMacResponse{Err: err.Error()}, nil
	}
	err = primitive.VerifyMAC(req.MacValue, req.Data)
	if err != nil {
		return &pb.VerifyMacResponse{Err: err.Error()}, nil
	}
	return &pb.VerifyMacResponse{}, nil
}
