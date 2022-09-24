// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package streamingprf_test

import (
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	commonpb "github.com/google/tink/go/proto/common_go_proto"
)

// limitFromHash returns the maximum output bytes from a HKDF using hash.
func limitFromHash(t *testing.T, hash commonpb.HashType) (limit int) {
	t.Helper()
	switch hash {
	case commonpb.HashType_SHA256:
		limit = sha256.Size * 255
	case commonpb.HashType_SHA512:
		limit = sha512.Size * 255
	default:
		t.Fatalf("unsupported hash type: %s", hash.String())
	}
	return
}
