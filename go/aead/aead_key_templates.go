// Copyright 2017 Google Inc.
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
package aead

import (
  "github.com/golang/protobuf/proto"
  gcmpb "github.com/google/tink/proto/aes_gcm_go_proto"
  tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// This file contains pre-generated KeyTemplate for Aead keys. One can use these templates
// to generate new Keyset.

// Aes128GcmKeyTemplate is a KeyTemplate of AesGcmKey with the following parameters:
//   - Key size: 16 bytes
func Aes128GcmKeyTemplate() *tinkpb.KeyTemplate {
  return createAesGcmKeyTemplate(16)
}

// Aes256GcmKeyTemplate is a KeyTemplate of AesGcmKey with the following parameters:
//   - Key size: 32 bytes
func Aes256GcmKeyTemplate() *tinkpb.KeyTemplate {
  return createAesGcmKeyTemplate(32)
}

// createAesGcmKeyTemplate creates a new AES-GCM key template with the given key
// size in bytes.
func createAesGcmKeyTemplate(keySize uint32) *tinkpb.KeyTemplate {
  format := &gcmpb.AesGcmKeyFormat{
    KeySize: keySize,
    Params: nil,
  }
  serializedFormat, _ := proto.Marshal(format)
  return &tinkpb.KeyTemplate{
    TypeUrl: AES_GCM_TYPE_URL,
    Value: serializedFormat,
  }
}