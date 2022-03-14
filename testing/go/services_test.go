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

package services_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/prf"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/streamingaead"
	pb "github.com/google/tink/proto/testing/testing_api_go_grpc"
	"github.com/google/tink/testing/go/services"
)

func genKeyset(ctx context.Context, keysetService *services.KeysetService, template []byte) ([]byte, error) {
	genRequest := &pb.KeysetGenerateRequest{Template: template}
	genResponse, err := keysetService.Generate(ctx, genRequest)
	if err != nil {
		return nil, err
	}
	switch r := genResponse.Result.(type) {
	case *pb.KeysetGenerateResponse_Keyset:
		return r.Keyset, nil
	case *pb.KeysetGenerateResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("genResponse.Result has unexpected type %T", r)
	}
}

func pubKeyset(ctx context.Context, keysetService *services.KeysetService, privateKeyset []byte) ([]byte, error) {
	request := &pb.KeysetPublicRequest{PrivateKeyset: privateKeyset}
	response, err := keysetService.Public(ctx, request)
	if err != nil {
		return nil, err
	}
	switch r := response.Result.(type) {
	case *pb.KeysetPublicResponse_PublicKeyset:
		return r.PublicKeyset, nil
	case *pb.KeysetPublicResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("response.Result has unexpected type %T", r)
	}
}

func keysetFromJSON(ctx context.Context, keysetService *services.KeysetService, jsonKeyset string) ([]byte, error) {
	request := &pb.KeysetFromJsonRequest{JsonKeyset: jsonKeyset}
	response, err := keysetService.FromJson(ctx, request)
	if err != nil {
		return nil, err
	}
	switch r := response.Result.(type) {
	case *pb.KeysetFromJsonResponse_Keyset:
		return r.Keyset, nil
	case *pb.KeysetFromJsonResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("response.Result has unexpected type %T", r)
	}
}

func keysetToJSON(ctx context.Context, keysetService *services.KeysetService, keyset []byte) (string, error) {
	request := &pb.KeysetToJsonRequest{Keyset: keyset}
	response, err := keysetService.ToJson(ctx, request)
	if err != nil {
		return "", err
	}
	switch r := response.Result.(type) {
	case *pb.KeysetToJsonResponse_JsonKeyset:
		return r.JsonKeyset, nil
	case *pb.KeysetToJsonResponse_Err:
		return "", errors.New(r.Err)
	default:
		return "", fmt.Errorf("response.Result has unexpected type %T", r)
	}
}

func TestFromJSON(t *testing.T) {
	keysetService := &services.KeysetService{}
	ctx := context.Background()
	jsonKeyset := `
        {
          "primaryKeyId": 42,
          "key": [
            {
              "keyData": {
                "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
                "keyMaterialType": "SYMMETRIC",
                "value": "GhCS/1+ejWpx68NfGt6ziYHd"
              },
              "outputPrefixType": "TINK",
              "keyId": 42,
              "status": "ENABLED"
            }
          ]
        }`
	keysetData, err := keysetFromJSON(ctx, keysetService, jsonKeyset)
	if err != nil {
		t.Fatalf("keysetFromJSON failed: %v", err)
	}
	reader := keyset.NewBinaryReader(bytes.NewReader(keysetData))
	keyset, err := reader.Read()
	if err != nil {
		t.Fatalf("reader.Read() failed: %v", err)
	}
	if keyset.GetPrimaryKeyId() != 42 {
		t.Fatalf("Got keyset.GetPrimaryKeyId() == %d, want 42", keyset.GetPrimaryKeyId())
	}
}

func TestGenerateToFromJSON(t *testing.T) {
	keysetService := &services.KeysetService{}
	ctx := context.Background()

	template, err := proto.Marshal(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("proto.Marshal(aead.AES128GCMKeyTemplate()) failed: %v", err)
	}
	keyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}
	jsonKeyset, err := keysetToJSON(ctx, keysetService, keyset)
	if err != nil {
		t.Fatalf("keysetToJSON failed: %v", err)
	}
	output, err := keysetFromJSON(ctx, keysetService, jsonKeyset)
	if err != nil {
		t.Fatalf("keysetFromJSON failed: %v", err)
	}
	if bytes.Compare(output, keyset) != 0 {
		t.Fatalf("output is %v, want %v", output, keyset)
	}
}

func TestKeysetFromJSONFail(t *testing.T) {
	keysetService := &services.KeysetService{}
	ctx := context.Background()
	if _, err := keysetFromJSON(ctx, keysetService, "bad JSON"); err == nil {
		t.Fatalf("keysetFromJSON from bad JSON succeeded unexpectedly.")
	}
}

func TestKeysetToJSONFail(t *testing.T) {
	keysetService := &services.KeysetService{}
	ctx := context.Background()
	if _, err := keysetToJSON(ctx, keysetService, []byte("badKeyset")); err == nil {
		t.Fatalf("keysetToJSON with bad keyset succeeded unexpectedly.")
	}
}

func keysetWriteEncrypted(ctx context.Context, keysetService *services.KeysetService, keyset []byte, masterKeyset []byte, associatedData []byte) ([]byte, error) {
	var request *pb.KeysetWriteEncryptedRequest
	if associatedData != nil {
		request = &pb.KeysetWriteEncryptedRequest{Keyset: keyset, MasterKeyset: masterKeyset, AssociatedData: &pb.BytesValue{Value: associatedData}}
	} else {
		request = &pb.KeysetWriteEncryptedRequest{Keyset: keyset, MasterKeyset: masterKeyset}
	}
	response, err := keysetService.WriteEncrypted(ctx, request)
	if err != nil {
		return nil, err
	}
	switch r := response.Result.(type) {
	case *pb.KeysetWriteEncryptedResponse_EncryptedKeyset:
		return r.EncryptedKeyset, nil
	case *pb.KeysetWriteEncryptedResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("response.Result has unexpected type %T", r)
	}
}

func keysetReadEncrypted(ctx context.Context, keysetService *services.KeysetService, encryptedKeyset []byte, masterKeyset []byte, associatedData []byte) ([]byte, error) {
	var request *pb.KeysetReadEncryptedRequest
	if associatedData != nil {
		request = &pb.KeysetReadEncryptedRequest{EncryptedKeyset: encryptedKeyset, MasterKeyset: masterKeyset, AssociatedData: &pb.BytesValue{Value: associatedData}}
	} else {
		request = &pb.KeysetReadEncryptedRequest{EncryptedKeyset: encryptedKeyset, MasterKeyset: masterKeyset}
	}
	response, err := keysetService.ReadEncrypted(ctx, request)
	if err != nil {
		return nil, err
	}
	switch r := response.Result.(type) {
	case *pb.KeysetReadEncryptedResponse_Keyset:
		return r.Keyset, nil
	case *pb.KeysetReadEncryptedResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("response.Result has unexpected type %T", r)
	}
}

func TestKeysetWriteReadEncrypted(t *testing.T) {
	keysetService := &services.KeysetService{}
	ctx := context.Background()

	template, err := proto.Marshal(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("proto.Marshal(aead.AES128GCMKeyTemplate()) failed: %v", err)
	}

	keyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}
	masterKeyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}

	encryptedKeyset, err := keysetWriteEncrypted(ctx, keysetService, keyset, masterKeyset, nil)
	if err != nil {
		t.Fatalf("keysetWriteEncrypted failed: %v", err)
	}

	readKeyset, err := keysetReadEncrypted(ctx, keysetService, encryptedKeyset, masterKeyset, nil)
	if err != nil {
		t.Fatalf("keysetReadEncrypted failed: %v", err)
	}
	if bytes.Compare(readKeyset, keyset) != 0 {
		t.Fatalf("readKeyset is %v, want %v", readKeyset, keyset)
	}

	if _, err := keysetWriteEncrypted(ctx, keysetService, []byte("badKeyset"), masterKeyset, nil); err == nil {
		t.Fatalf("keysetWriteEncrypted with bad keyset succeeded unexpectedly.")
	}
	if _, err := keysetWriteEncrypted(ctx, keysetService, keyset, []byte("badMasterKeyset"), nil); err == nil {
		t.Fatalf("keysetWriteEncrypted with bad masterKeyset succeeded unexpectedly.")
	}
	if _, err := keysetReadEncrypted(ctx, keysetService, []byte("badEncryptedKeyset"), masterKeyset, nil); err == nil {
		t.Fatalf("keysetReadEncrypted with bad encryptedKeyset succeeded unexpectedly.")
	}
	if _, err := keysetReadEncrypted(ctx, keysetService, encryptedKeyset, []byte("badMasterKeyset"), nil); err == nil {
		t.Fatalf("keysetService with bad masterKeyset succeeded unexpectedly.")
	}
}

func TestKeysetWriteReadEncryptedWithAssociatedData(t *testing.T) {
	keysetService := &services.KeysetService{}
	ctx := context.Background()

	template, err := proto.Marshal(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("proto.Marshal(aead.AES128GCMKeyTemplate()) failed: %v", err)
	}

	keyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}
	masterKeyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}
	associatedData := []byte("Associated Data")

	encryptedKeyset, err := keysetWriteEncrypted(ctx, keysetService, keyset, masterKeyset, associatedData)
	if err != nil {
		t.Fatalf("keysetWriteEncrypted failed: %v", err)
	}

	readKeyset, err := keysetReadEncrypted(ctx, keysetService, encryptedKeyset, masterKeyset, associatedData)
	if err != nil {
		t.Fatalf("keysetReadEncrypted failed: %v", err)
	}
	if bytes.Compare(readKeyset, keyset) != 0 {
		t.Fatalf("readKeyset is %v, want %v", readKeyset, keyset)
	}

	if _, err := keysetReadEncrypted(ctx, keysetService, encryptedKeyset, masterKeyset, []byte("Invalid Associated Data")); err == nil {
		t.Fatalf("keysetWriteEncrypted with bad associatedData succeeded unexpectedly.")
	}

	if _, err := keysetWriteEncrypted(ctx, keysetService, []byte("badKeyset"), masterKeyset, associatedData); err == nil {
		t.Fatalf("keysetWriteEncrypted with bad keyset succeeded unexpectedly.")
	}
	if _, err := keysetWriteEncrypted(ctx, keysetService, keyset, []byte("badMasterKeyset"), associatedData); err == nil {
		t.Fatalf("keysetWriteEncrypted with bad masterKeyset succeeded unexpectedly.")
	}
	if _, err := keysetReadEncrypted(ctx, keysetService, []byte("badEncryptedKeyset"), masterKeyset, associatedData); err == nil {
		t.Fatalf("keysetReadEncrypted with bad encryptedKeyset succeeded unexpectedly.")
	}
	if _, err := keysetReadEncrypted(ctx, keysetService, encryptedKeyset, []byte("badMasterKeyset"), associatedData); err == nil {
		t.Fatalf("keysetService with bad masterKeyset succeeded unexpectedly.")
	}
}

func aeadEncrypt(ctx context.Context, aeadService *services.AEADService, keyset []byte, plaintext []byte, associatedData []byte) ([]byte, error) {
	encRequest := &pb.AeadEncryptRequest{
		Keyset:         keyset,
		Plaintext:      plaintext,
		AssociatedData: associatedData,
	}
	encResponse, err := aeadService.Encrypt(ctx, encRequest)
	if err != nil {
		return nil, err
	}
	switch r := encResponse.Result.(type) {
	case *pb.AeadEncryptResponse_Ciphertext:
		return r.Ciphertext, nil
	case *pb.AeadEncryptResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("encResponse.Result has unexpected type %T", r)
	}
}

func aeadDecrypt(ctx context.Context, aeadService *services.AEADService, keyset []byte, ciphertext []byte, associatedData []byte) ([]byte, error) {
	decRequest := &pb.AeadDecryptRequest{
		Keyset:         keyset,
		Ciphertext:     ciphertext,
		AssociatedData: associatedData,
	}
	decResponse, err := aeadService.Decrypt(ctx, decRequest)
	if err != nil {
		return nil, err
	}
	switch r := decResponse.Result.(type) {
	case *pb.AeadDecryptResponse_Plaintext:
		return r.Plaintext, nil
	case *pb.AeadDecryptResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("encResponse.Result has unexpected type %T", r)
	}
}

func TestGenerateEncryptDecrypt(t *testing.T) {
	keysetService := &services.KeysetService{}
	aeadService := &services.AEADService{}
	ctx := context.Background()

	template, err := proto.Marshal(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("proto.Marshal(aead.AES128GCMKeyTemplate()) failed: %v", err)
	}

	keyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}

	plaintext := []byte("The quick brown fox jumps over the lazy dog")
	associatedData := []byte("Associated Data")
	ciphertext, err := aeadEncrypt(ctx, aeadService, keyset, plaintext, associatedData)
	if err != nil {
		t.Fatalf("Aead Encrypt failed: %v", err)
	}
	output, err := aeadDecrypt(ctx, aeadService, keyset, ciphertext, associatedData)
	if err != nil {
		t.Fatalf("aeadDecrypt failed: %v", err)
	}
	if bytes.Compare(output, plaintext) != 0 {
		t.Fatalf("Decrypted ciphertext is %v, want %v", output, plaintext)
	}

	if _, err := genKeyset(ctx, keysetService, []byte("badTemplate")); err == nil {
		t.Fatalf("genKeyset from bad template succeeded unexpectedly.")
	}
	if _, err := aeadEncrypt(ctx, aeadService, []byte("badKeyset"), plaintext, associatedData); err == nil {
		t.Fatalf("aeadEncrypt with bad keyset succeeded unexpectedly.")
	}
	if _, err := aeadDecrypt(ctx, aeadService, keyset, []byte("badCiphertext"), associatedData); err == nil {
		t.Fatalf("aeadDecrypt of bad ciphertext succeeded unexpectedly.")
	}
}

func daeadEncrypt(ctx context.Context, daeadService *services.DeterministicAEADService, keyset []byte, plaintext []byte, associatedData []byte) ([]byte, error) {
	encRequest := &pb.DeterministicAeadEncryptRequest{
		Keyset:         keyset,
		Plaintext:      plaintext,
		AssociatedData: associatedData,
	}
	encResponse, err := daeadService.EncryptDeterministically(ctx, encRequest)
	if err != nil {
		return nil, err
	}
	switch r := encResponse.Result.(type) {
	case *pb.DeterministicAeadEncryptResponse_Ciphertext:
		return r.Ciphertext, nil
	case *pb.DeterministicAeadEncryptResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("encResponse.Result has unexpected type %T", r)
	}
}

func daeadDecrypt(ctx context.Context, daeadService *services.DeterministicAEADService, keyset []byte, ciphertext []byte, associatedData []byte) ([]byte, error) {
	decRequest := &pb.DeterministicAeadDecryptRequest{
		Keyset:         keyset,
		Ciphertext:     ciphertext,
		AssociatedData: associatedData,
	}
	decResponse, err := daeadService.DecryptDeterministically(ctx, decRequest)
	if err != nil {
		return nil, err
	}
	switch r := decResponse.Result.(type) {
	case *pb.DeterministicAeadDecryptResponse_Plaintext:
		return r.Plaintext, nil
	case *pb.DeterministicAeadDecryptResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("encResponse.Result has unexpected type %T", r)
	}
}

func TestGenerateEncryptDecryptDeterministically(t *testing.T) {
	keysetService := &services.KeysetService{}
	daeadService := &services.DeterministicAEADService{}
	ctx := context.Background()

	template, err := proto.Marshal(daead.AESSIVKeyTemplate())
	if err != nil {
		t.Fatalf("proto.Marshal(daead.AESSIVKeyTemplate()) failed: %v", err)
	}

	keyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}

	plaintext := []byte("The quick brown fox jumps over the lazy dog")
	associatedData := []byte("Associated Data")
	ciphertext, err := daeadEncrypt(ctx, daeadService, keyset, plaintext, associatedData)
	if err != nil {
		t.Fatalf("Aead Encrypt failed: %v", err)
	}
	output, err := daeadDecrypt(ctx, daeadService, keyset, ciphertext, associatedData)
	if err != nil {
		t.Fatalf("daeadDecrypt failed: %v", err)
	}
	if bytes.Compare(output, plaintext) != 0 {
		t.Fatalf("Decrypted ciphertext is %v, want %v", output, plaintext)
	}

	if _, err := genKeyset(ctx, keysetService, []byte("badTemplate")); err == nil {
		t.Fatalf("genKeyset from bad template succeeded unexpectedly.")
	}
	if _, err := daeadEncrypt(ctx, daeadService, []byte("badKeyset"), plaintext, associatedData); err == nil {
		t.Fatalf("daeadEncrypt with bad keyset succeeded unexpectedly.")
	}
	if _, err := daeadDecrypt(ctx, daeadService, keyset, []byte("badCiphertext"), associatedData); err == nil {
		t.Fatalf("daeadDecrypt of bad ciphertext succeeded unexpectedly.")
	}
}

func streamingAEADEncrypt(ctx context.Context, streamingAEADService *services.StreamingAEADService, keyset []byte, plaintext []byte, associatedData []byte) ([]byte, error) {
	encRequest := &pb.StreamingAeadEncryptRequest{
		Keyset:         keyset,
		Plaintext:      plaintext,
		AssociatedData: associatedData,
	}
	encResponse, err := streamingAEADService.Encrypt(ctx, encRequest)
	if err != nil {
		return nil, err
	}
	switch r := encResponse.Result.(type) {
	case *pb.StreamingAeadEncryptResponse_Ciphertext:
		return r.Ciphertext, nil
	case *pb.StreamingAeadEncryptResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("encResponse.Result has unexpected type %T", r)
	}
}

func streamingAEADDecrypt(ctx context.Context, streamingAEADService *services.StreamingAEADService, keyset []byte, ciphertext []byte, associatedData []byte) ([]byte, error) {
	decRequest := &pb.StreamingAeadDecryptRequest{
		Keyset:         keyset,
		Ciphertext:     ciphertext,
		AssociatedData: associatedData,
	}
	decResponse, err := streamingAEADService.Decrypt(ctx, decRequest)
	if err != nil {
		return nil, err
	}
	switch r := decResponse.Result.(type) {
	case *pb.StreamingAeadDecryptResponse_Plaintext:
		return r.Plaintext, nil
	case *pb.StreamingAeadDecryptResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("encResponse.Result has unexpected type %T", r)
	}
}

func TestGenerateEncryptDecryptStreaming(t *testing.T) {
	keysetService := &services.KeysetService{}
	streamingAEADService := &services.StreamingAEADService{}
	ctx := context.Background()

	template, err := proto.Marshal(streamingaead.AES128GCMHKDF4KBKeyTemplate())
	if err != nil {
		t.Fatalf("proto.Marshal(streamingaead.AES128GCMHKDF4KBKeyTemplate()) failed: %v", err)
	}

	keyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}

	plaintext := []byte("The quick brown fox jumps over the lazy dog")
	associatedData := []byte("Associated Data")
	ciphertext, err := streamingAEADEncrypt(ctx, streamingAEADService, keyset, plaintext, associatedData)
	if err != nil {
		t.Fatalf("streamingAEADEncrypt failed: %v", err)
	}
	output, err := streamingAEADDecrypt(ctx, streamingAEADService, keyset, ciphertext, associatedData)
	if err != nil {
		t.Fatalf("streamingAEADDecrypt failed: %v", err)
	}
	if bytes.Compare(output, plaintext) != 0 {
		t.Errorf("Decrypted ciphertext is %v, want %v", output, plaintext)
	}

	if _, err := genKeyset(ctx, keysetService, []byte("badTemplate")); err == nil {
		t.Fatalf("genKeyset from bad template succeeded unexpectedly.")
	}
	if _, err := streamingAEADEncrypt(ctx, streamingAEADService, []byte("badKeyset"), plaintext, associatedData); err == nil {
		t.Fatalf("streamingAEADEncrypt with bad keyset succeeded unexpectedly.")
	}
	if _, err := streamingAEADDecrypt(ctx, streamingAEADService, keyset, []byte("badCiphertext"), associatedData); err == nil {
		t.Fatalf("streamingAEADDecrypt of bad ciphertext succeeded unexpectedly.")
	}
}

func computeMAC(ctx context.Context, macService *services.MacService, keyset []byte, data []byte) ([]byte, error) {
	encRequest := &pb.ComputeMacRequest{
		Keyset: keyset,
		Data:   data,
	}
	response, err := macService.ComputeMac(ctx, encRequest)
	if err != nil {
		return nil, err
	}
	switch r := response.Result.(type) {
	case *pb.ComputeMacResponse_MacValue:
		return r.MacValue, nil
	case *pb.ComputeMacResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("response.Result has unexpected type %T", r)
	}
}

func verifyMAC(ctx context.Context, macService *services.MacService, keyset []byte, macValue []byte, data []byte) error {
	request := &pb.VerifyMacRequest{
		Keyset:   keyset,
		MacValue: macValue,
		Data:     data,
	}
	response, err := macService.VerifyMac(ctx, request)
	if err != nil {
		return err
	}
	if response.Err != "" {
		return errors.New(response.Err)
	}
	return nil
}

func TestComputeVerifyMac(t *testing.T) {
	keysetService := &services.KeysetService{}
	macService := &services.MacService{}
	ctx := context.Background()

	template, err := proto.Marshal(mac.HMACSHA256Tag128KeyTemplate())
	if err != nil {
		t.Fatalf("proto.Marshal(mac.HMACSHA256Tag128KeyTemplate()) failed: %v", err)
	}

	keyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}

	data := []byte("The quick brown fox jumps over the lazy dog")
	macValue, err := computeMAC(ctx, macService, keyset, data)
	if err != nil {
		t.Fatalf("computeMAC failed: %v", err)
	}
	if err := verifyMAC(ctx, macService, keyset, macValue, data); err != nil {
		t.Fatalf("verifyMAC failed: %v", err)
	}

	if _, err := computeMAC(ctx, macService, []byte("badKeyset"), data); err == nil {
		t.Fatalf("computeMAC with bad keyset succeeded unexpectedly.")
	}
	if err := verifyMAC(ctx, macService, keyset, []byte("badMacValue"), data); err == nil {
		t.Fatalf("verifyMAC of bad MAC value succeeded unexpectedly.")
	}
}

func hybridEncrypt(ctx context.Context, hybridService *services.HybridService, publicKeyset []byte, plaintext []byte, contextInfo []byte) ([]byte, error) {
	encRequest := &pb.HybridEncryptRequest{
		PublicKeyset: publicKeyset,
		Plaintext:    plaintext,
		ContextInfo:  contextInfo,
	}
	encResponse, err := hybridService.Encrypt(ctx, encRequest)
	if err != nil {
		return nil, err
	}
	switch r := encResponse.Result.(type) {
	case *pb.HybridEncryptResponse_Ciphertext:
		return r.Ciphertext, nil
	case *pb.HybridEncryptResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("encResponse.Result has unexpected type %T", r)
	}
}

func hybridDecrypt(ctx context.Context, hybridService *services.HybridService, privateKeyset []byte, ciphertext []byte, contextInfo []byte) ([]byte, error) {
	decRequest := &pb.HybridDecryptRequest{
		PrivateKeyset: privateKeyset,
		Ciphertext:    ciphertext,
		ContextInfo:   contextInfo,
	}
	decResponse, err := hybridService.Decrypt(ctx, decRequest)
	if err != nil {
		return nil, err
	}
	switch r := decResponse.Result.(type) {
	case *pb.HybridDecryptResponse_Plaintext:
		return r.Plaintext, nil
	case *pb.HybridDecryptResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("decResponse.Result has unexpected type %T", r)
	}
}

func TestHybridGenerateEncryptDecrypt(t *testing.T) {
	keysetService := &services.KeysetService{}
	hybridService := &services.HybridService{}
	ctx := context.Background()

	template, err := proto.Marshal(hybrid.ECIESHKDFAES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("proto.Marshal(hybrid.ECIESHKDFAES128GCMKeyTemplate()) failed: %v", err)
	}

	privateKeyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}
	publicKeyset, err := pubKeyset(ctx, keysetService, privateKeyset)
	if err != nil {
		t.Fatalf("pubKeyset failed: %v", err)
	}

	plaintext := []byte("The quick brown fox jumps over the lazy dog")
	associatedData := []byte("Associated Data")
	ciphertext, err := hybridEncrypt(ctx, hybridService, publicKeyset, plaintext, associatedData)
	if err != nil {
		t.Fatalf("hybridEncrypt failed: %v", err)
	}
	output, err := hybridDecrypt(ctx, hybridService, privateKeyset, ciphertext, associatedData)
	if err != nil {
		t.Fatalf("hybridDecrypt failed: %v", err)
	}
	if bytes.Compare(output, plaintext) != 0 {
		t.Fatalf("Decrypted ciphertext is %v, want %v", output, plaintext)
	}

	if _, err := pubKeyset(ctx, keysetService, []byte("badPrivateKeyset")); err == nil {
		t.Fatalf("pubKeyset from bad private keyset succeeded unexpectedly.")
	}
	if _, err := hybridEncrypt(ctx, hybridService, []byte("badPublicKeyset"), plaintext, associatedData); err == nil {
		t.Fatalf("hybridEncrypt with bad public keyset succeeded unexpectedly.")
	}
	if _, err := hybridDecrypt(ctx, hybridService, []byte("badPrivateKeyset"), ciphertext, associatedData); err == nil {
		t.Fatalf("hybridDecrypt with bad private keyset succeeded unexpectedly.")
	}
	if _, err := hybridDecrypt(ctx, hybridService, privateKeyset, []byte("badCiphertext"), associatedData); err == nil {
		t.Fatalf("hybridDecrypt of bad ciphertext succeeded unexpectedly.")
	}
}

func signatureSign(ctx context.Context, signatureService *services.SignatureService, privateKeyset []byte, data []byte) ([]byte, error) {
	encRequest := &pb.SignatureSignRequest{
		PrivateKeyset: privateKeyset,
		Data:          data,
	}
	response, err := signatureService.Sign(ctx, encRequest)
	if err != nil {
		return nil, err
	}
	switch r := response.Result.(type) {
	case *pb.SignatureSignResponse_Signature:
		return r.Signature, nil
	case *pb.SignatureSignResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("response.Result has unexpected type %T", r)
	}
}

func signatureVerify(ctx context.Context, signatureService *services.SignatureService, publicKeyset []byte, signatureValue []byte, data []byte) error {
	request := &pb.SignatureVerifyRequest{
		PublicKeyset: publicKeyset,
		Signature:    signatureValue,
		Data:         data,
	}
	response, err := signatureService.Verify(ctx, request)
	if err != nil {
		return err
	}
	if response.Err != "" {
		return errors.New(response.Err)
	}
	return nil
}

func TestSignatureSignVerify(t *testing.T) {
	keysetService := &services.KeysetService{}
	signatureService := &services.SignatureService{}
	ctx := context.Background()

	template, err := proto.Marshal(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("proto.Marshal(signature.ECDSAP256KeyTemplate()) failed: %v", err)
	}

	privateKeyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}
	publicKeyset, err := pubKeyset(ctx, keysetService, privateKeyset)
	if err != nil {
		t.Fatalf("pubKeyset failed: %v", err)
	}

	data := []byte("The quick brown fox jumps over the lazy dog")
	signatureValue, err := signatureSign(ctx, signatureService, privateKeyset, data)
	if err != nil {
		t.Fatalf("signatureSign failed: %v", err)
	}
	if err := signatureVerify(ctx, signatureService, publicKeyset, signatureValue, data); err != nil {
		t.Fatalf("signatureVerify failed: %v", err)
	}

	if _, err := signatureSign(ctx, signatureService, []byte("badPrivateKeyset"), data); err == nil {
		t.Fatalf("signatureSign with bad private keyset succeeded unexpectedly.")
	}
	if err := signatureVerify(ctx, signatureService, publicKeyset, []byte("badSignature"), data); err == nil {
		t.Fatalf("signatureVerify of bad signature succeeded unexpectedly.")
	}
	if err := signatureVerify(ctx, signatureService, []byte("badPublicKeyset"), signatureValue, data); err == nil {
		t.Fatalf("signatureVerify of bad public keyset succeeded unexpectedly.")
	}
}

func prfSetKeyIds(ctx context.Context, prfSetService *services.PrfSetService, keyset []byte) (uint32, []uint32, error) {
	request := &pb.PrfSetKeyIdsRequest{
		Keyset: keyset,
	}
	response, err := prfSetService.KeyIds(ctx, request)
	if err != nil {
		return 0, nil, err
	}
	switch r := response.Result.(type) {
	case *pb.PrfSetKeyIdsResponse_Output_:
		return r.Output.PrimaryKeyId, r.Output.KeyId, nil
	case *pb.PrfSetKeyIdsResponse_Err:
		return 0, nil, errors.New(r.Err)
	default:
		return 0, nil, fmt.Errorf("response.Result has unexpected type %T", r)
	}
}

func prfSetCompute(ctx context.Context, prfSetService *services.PrfSetService, keyset []byte, keyID uint32, inputData []byte, outputLength int) ([]byte, error) {
	request := &pb.PrfSetComputeRequest{
		Keyset:       keyset,
		KeyId:        keyID,
		InputData:    inputData,
		OutputLength: int32(outputLength),
	}
	response, err := prfSetService.Compute(ctx, request)
	if err != nil {
		return nil, err
	}
	switch r := response.Result.(type) {
	case *pb.PrfSetComputeResponse_Output:
		return r.Output, nil
	case *pb.PrfSetComputeResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("response.Result has unexpected type %T", r)
	}
}

func TestComputePrf(t *testing.T) {
	keysetService := &services.KeysetService{}
	prfSetService := &services.PrfSetService{}
	ctx := context.Background()
	template, err := proto.Marshal(prf.HMACSHA256PRFKeyTemplate())
	if err != nil {
		t.Fatalf("proto.Marshal(prf.HMACSHA256PRFKeyTemplate()) failed: %v", err)
	}
	keyset, err := genKeyset(ctx, keysetService, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}

	primaryKeyID, keyIDs, err := prfSetKeyIds(ctx, prfSetService, keyset)
	if err != nil {
		t.Fatalf("prfSetKeyIds failed: %v", err)
	}
	if len(keyIDs) != 1 || keyIDs[0] != primaryKeyID {
		t.Fatalf("expected keyIDs = {primaryKeyID}, but go %v", keyIDs)
	}
	inputData := []byte("inputData")
	outputLength := 15
	output, err := prfSetCompute(ctx, prfSetService, keyset, primaryKeyID, inputData, outputLength)
	if err != nil {
		t.Fatalf("prfSetCompute failed: %v", err)
	}
	if len(output) != outputLength {
		t.Fatalf("expected output of length %d, but got length %d (%x)", outputLength, len(output), output)
	}
	badOutputLength := 123456
	if _, err := prfSetCompute(ctx, prfSetService, keyset, primaryKeyID, inputData, badOutputLength); err == nil {
		t.Fatalf("prfSetCompute with bad outputLength succeeded unexpectedly.")
	}
}

func TestPrfKeyIdsFail(t *testing.T) {
	prfSetService := &services.PrfSetService{}
	ctx := context.Background()
	if _, _, err := prfSetKeyIds(ctx, prfSetService, []byte("badKeyset")); err == nil {
		t.Fatalf("prfSetKeyIds with bad keyset succeeded unexpectedly.")
	}
}

func TestServerInfo(t *testing.T) {
	metadataService := &services.MetadataService{}
	ctx := context.Background()

	req := &pb.ServerInfoRequest{}
	rsp, err := metadataService.GetServerInfo(ctx, req)
	if err != nil {
		t.Fatalf("GetServerInfo failed: %v", err)
	}
	if strings.Compare(rsp.GetLanguage(), "go") != 0 {
		t.Fatalf("Expected language 'go', got: %v", rsp.GetLanguage())
	}
}
