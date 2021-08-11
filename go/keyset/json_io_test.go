// Copyright 2019 Google LLC
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

package keyset_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"

	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

func TestJSONIOUnencrypted(t *testing.T) {
	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)
	r := keyset.NewJSONReader(buf)

	manager := testutil.NewHMACKeysetManager()
	h, err := manager.Handle()
	if h == nil || err != nil {
		t.Fatalf("cannot get keyset handle: %v", err)
	}

	ks1 := testkeyset.KeysetMaterial(h)
	if err := w.Write(ks1); err != nil {
		t.Fatalf("cannot write keyset: %v", err)
	}

	ks2, err := r.Read()
	if err != nil {
		t.Fatalf("cannot read keyset: %v", err)
	}

	if !proto.Equal(ks1, ks2) {
		t.Errorf("written keyset (%s) doesn't match read keyset (%s)", ks1, ks2)
	}
}

func TestJSONReader(t *testing.T) {
	gcmkey := []byte(testutil.NewAESGCMKey(0, 16).String())
	eaxkey := []byte(testutil.NewHMACKey(commonpb.HashType_SHA512, 32).String())
	jsonKeyset := fmt.Sprintf(`{
         "primaryKeyId":42,
         "key":[
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": %q
               },
               "outputPrefixType":"TINK",
               "keyId":42,
               "status":"ENABLED"
            },
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesEaxKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": %q
               },
               "outputPrefixType":"RAW",
               "keyId":711,
               "status":"ENABLED"
            }
         ]
      }`, base64.StdEncoding.EncodeToString([]byte(gcmkey)), base64.StdEncoding.EncodeToString([]byte(eaxkey)))
	r := keyset.NewJSONReader(bytes.NewBufferString(jsonKeyset))

	got, err := r.Read()
	if err != nil {
		t.Fatalf("cannot read keyset: %v", err)
	}

	want := &tinkpb.Keyset{
		PrimaryKeyId: 42,
		Key: []*tinkpb.Keyset_Key{
			{
				KeyData: &tinkpb.KeyData{
					TypeUrl:         "type.googleapis.com/google.crypto.tink.AesGcmKey",
					KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					Value:           gcmkey,
				},
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				KeyId:            42,
				Status:           tinkpb.KeyStatusType_ENABLED,
			},
			{
				KeyData: &tinkpb.KeyData{
					TypeUrl:         "type.googleapis.com/google.crypto.tink.AesEaxKey",
					KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					Value:           eaxkey,
				},
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
				KeyId:            711,
				Status:           tinkpb.KeyStatusType_ENABLED,
			},
		},
	}

	if !proto.Equal(got, want) {
		t.Errorf("written keyset %q doesn't match expected keyset %q", got, want)
	}
}

func TestJSONReaderLargeIds(t *testing.T) {
	gcmkey := []byte(testutil.NewAESGCMKey(0, 16).String())
	jsonKeyset := fmt.Sprintf(`{
         "primaryKeyId":4294967275,
         "key":[
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": %q
               },
               "outputPrefixType":"TINK",
               "keyId":4294967275,
               "status":"ENABLED"
            }
         ]
      }`, base64.StdEncoding.EncodeToString([]byte(gcmkey)))
	r := keyset.NewJSONReader(bytes.NewBufferString(jsonKeyset))

	got, err := r.Read()
	if err != nil {
		t.Fatalf("cannot read keyset: %v", err)
	}

	want := &tinkpb.Keyset{
		PrimaryKeyId: 4294967275,
		Key: []*tinkpb.Keyset_Key{
			{
				KeyData: &tinkpb.KeyData{
					TypeUrl:         "type.googleapis.com/google.crypto.tink.AesGcmKey",
					KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					Value:           gcmkey,
				},
				OutputPrefixType: tinkpb.OutputPrefixType_TINK,
				KeyId:            4294967275,
				Status:           tinkpb.KeyStatusType_ENABLED,
			},
		},
	}

	if !proto.Equal(got, want) {
		t.Errorf("written keyset %q doesn't match expected keyset %q", got, want)
	}
}

func TestJSONReaderNegativeIds(t *testing.T) {
	gcmkey := []byte(testutil.NewAESGCMKey(0, 16).String())
	jsonKeyset := fmt.Sprintf(`{
         "primaryKeyId": -10,
         "key":[
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": %q
               },
               "outputPrefixType":"TINK",
               "keyId": -10,
               "status":"ENABLED"
            }
         ]
      }`, base64.StdEncoding.EncodeToString(gcmkey))
	r := keyset.NewJSONReader(bytes.NewBufferString(jsonKeyset))

	_, err := r.Read()
	if err == nil {
		t.Fatalf("Expected failure due to negative key id")
	}
}

// Tests that large IDs (>2^31) are written correctly.
func TestJSONWriterLargeId(t *testing.T) {
	eaxkey := []byte(testutil.NewHMACKey(commonpb.HashType_SHA512, 32).String())

	ks := tinkpb.Keyset{
		PrimaryKeyId: 4294967275,
		Key: []*tinkpb.Keyset_Key{
			{
				KeyData: &tinkpb.KeyData{
					TypeUrl:         "type.googleapis.com/google.crypto.tink.AesEaxKey",
					KeyMaterialType: tinkpb.KeyData_SYMMETRIC,
					Value:           eaxkey,
				},
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
				KeyId:            4294967275,
				Status:           tinkpb.KeyStatusType_ENABLED,
			},
		},
	}

	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)
	if err := w.Write(&ks); err != nil {
		t.Fatalf("cannot write keyset: %v", err)
	}

	if !strings.Contains(buf.String(), `"keyId":4294967275`) {
		t.Errorf("written keyset %q does not contain a key with keyId 4294967275", buf.Bytes())
	}
	if !strings.Contains(buf.String(), "\"primaryKeyId\":4294967275") {
		t.Errorf("written keyset %q does not contain have primaryKeyId 4294967275", buf.Bytes())
	}
}

func TestJSONIOEncrypted(t *testing.T) {
	buf := new(bytes.Buffer)
	w := keyset.NewJSONWriter(buf)
	r := keyset.NewJSONReader(buf)

	kse1 := &tinkpb.EncryptedKeyset{EncryptedKeyset: []byte(strings.Repeat("A", 32))}

	if err := w.WriteEncrypted(kse1); err != nil {
		t.Fatalf("cannot write encrypted keyset: %v", err)
	}

	kse2, err := r.ReadEncrypted()
	if err != nil {
		t.Fatalf("cannot read encryped keyset: %v", err)
	}

	if !proto.Equal(kse1, kse2) {
		t.Errorf("written encryped keyset %q doesn't match read encryped keyset %q", kse1, kse2)
	}
}

func TestReadWriteCompactJsonKeyset(t *testing.T) {
	compactJSONKeyset := `{"primaryKeyId":42,"key":[{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey","value":"a2V5X3ZhbHVlOiJceDExXHhhMnY/XHgwYj5UXHhkZU5QXHgwODM8XHhjYl0wIg==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":42,"outputPrefixType":"TINK"},{"keyData":{"typeUrl":"type.googleapis.com/google.crypto.tink.AesEaxKey","value":"cGFyYW1zOntoYXNoOlNIQTUxMiAgdGFnX3NpemU6MzJ9ICBrZXlfdmFsdWU6Ilx4YTTdl1ZceGYzXHgxMlx4ZjdceGI2Nlx4YjdceGEyXHhjY1x4ZTd9XHgwN3tceGZlNzFceGJjIg==","keyMaterialType":"SYMMETRIC"},"status":"ENABLED","keyId":711,"outputPrefixType":"RAW"}]}`
	r := keyset.NewJSONReader(bytes.NewBufferString(compactJSONKeyset))
	k, err := r.Read()
	if err != nil {
		t.Fatalf("cannot read keyset: %v", err)
	}
	output := &bytes.Buffer{}
	w := keyset.NewJSONWriter(output)
	err = w.Write(k)
	if err != nil {
		t.Fatalf("cannot read keyset: %v", err)
	}
	if output.String() != compactJSONKeyset {
		t.Fatalf("output of w.Write(k) is not equal, got %s, want %s", output.String(), compactJSONKeyset)
	}
}
