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

// Package services is implements gRPC services for testing_api.
package services

import (
	"bytes"
	"context"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testkeyset"
	pb "github.com/google/tink/proto/testing/testing_api_go_grpc"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/golang/protobuf/proto"
)

// KeysetService implements the Keyset testing service.
type KeysetService struct {
}

func (s *KeysetService) Generate(ctx context.Context, req *pb.KeysetGenerateRequest) (*pb.KeysetGenerateResponse, error) {
	template := &tinkpb.KeyTemplate{}
	err := proto.Unmarshal(req.Template, template)
	if err != nil {
		return &pb.KeysetGenerateResponse{
			Result: &pb.KeysetGenerateResponse_Err{err.Error()}}, nil
	}
	handle, err := keyset.NewHandle(template)
	if err != nil {
		return &pb.KeysetGenerateResponse{
			Result: &pb.KeysetGenerateResponse_Err{err.Error()}}, nil
	}
	buf := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(buf)
	err = testkeyset.Write(handle, writer)
	if err != nil {
		return &pb.KeysetGenerateResponse{
			Result: &pb.KeysetGenerateResponse_Err{err.Error()}}, nil
	}
	return &pb.KeysetGenerateResponse{
		Result: &pb.KeysetGenerateResponse_Keyset{buf.Bytes()}}, nil
}
