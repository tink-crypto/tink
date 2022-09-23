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

package streamingprf

import (
	"google.golang.org/protobuf/proto"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	hkdfpb "github.com/google/tink/go/proto/hkdf_prf_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

// HKDFSHA256RawKeyTemplate generates a HKDF key with:
//   - Output prefix type: RAW
//   - Hash function: SHA256
//   - Salt: empty
//   - Key size: 32 bytes
func HKDFSHA256RawKeyTemplate() *tinkpb.KeyTemplate {
	return createHKDFKeyTemplate(commonpb.HashType_SHA256, []byte{}, 32)
}

// HKDFSHA512RawKeyTemplate generates a HKDF key with:
//   - Output prefix type: RAW
//   - Hash function: SHA512
//   - Salt: empty
//   - Key size: 32 bytes
func HKDFSHA512RawKeyTemplate() *tinkpb.KeyTemplate {
	return createHKDFKeyTemplate(commonpb.HashType_SHA512, []byte{}, 32)
}

func createHKDFKeyTemplate(hash commonpb.HashType, salt []byte, keySize uint32) *tinkpb.KeyTemplate {
	keyFormat := &hkdfpb.HkdfPrfKeyFormat{
		Params: &hkdfpb.HkdfPrfParams{
			Hash: hash,
			Salt: salt,
		},
		KeySize: keySize,
		Version: hkdfStreamingPRFKeyVersion,
	}
	serializedFormat, _ := proto.Marshal(keyFormat)
	return &tinkpb.KeyTemplate{
		TypeUrl:          hkdfStreamingPRFTypeURL,
		OutputPrefixType: tinkpb.OutputPrefixType_RAW,
		Value:            serializedFormat,
	}
}
