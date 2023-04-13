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

	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	pb "github.com/google/tink/testing/go/protos/testing_api_go_grpc"
)

func toKeysetHandle(annotatedKeyset *pb.AnnotatedKeyset) (*keyset.Handle, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(annotatedKeyset.GetSerializedKeyset()))
	a := annotatedKeyset.GetAnnotations()
	return insecurecleartextkeyset.Read(reader, keyset.WithAnnotations(a))
}
