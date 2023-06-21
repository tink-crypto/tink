// Copyright 2023 Google LLC
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

package aead_test

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/testing/fakekms"
	"github.com/google/tink/go/testutil"
	kmsenvpb "github.com/google/tink/go/proto/kms_envelope_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestNewKMSEnvelopeAEADKeyWithInvalidDEK(t *testing.T) {
	keyURI, err := fakekms.NewKeyURI()
	if err != nil {
		t.Fatalf("fakekms.NewKeyURI() err = %v", err)
	}

	// Create a KmsEnvelopeAeadKeyFormat with a DekTemplate that is not supported.
	format := &kmsenvpb.KmsEnvelopeAeadKeyFormat{
		KekUri:      keyURI,
		DekTemplate: mac.HMACSHA256Tag128KeyTemplate(),
	}
	serializedFormat, err := proto.Marshal(format)
	if err != nil {
		t.Fatalf("failed to marshal key format: %s", err)
	}
	keyTemplate := &tinkpb.KeyTemplate{
		Value:            serializedFormat,
		TypeUrl:          testutil.KMSEnvelopeAEADTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
	}

	_, err = keyset.NewHandle(keyTemplate)
	if err == nil {
		t.Errorf("keyset.NewHandle(keyTemplate) err = nil, want error")
	}
}
