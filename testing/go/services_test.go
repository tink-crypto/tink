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

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/daead"
	"github.com/google/tink/go/mac"
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
		return nil, fmt.Errorf("encResponse.Result has unexpected type %T", r)
	}
}

func aeadEncrypt(ctx context.Context, aeadService *services.AeadService, keyset []byte, plaintext []byte, associatedData []byte) ([]byte, error) {
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

func aeadDecrypt(ctx context.Context, aeadService *services.AeadService, keyset []byte, ciphertext []byte, associatedData []byte) ([]byte, error) {
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
	aeadService := &services.AeadService{}
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

func daeadEncrypt(ctx context.Context, daeadService *services.DeterministicAeadService, keyset []byte, plaintext []byte, associatedData []byte) ([]byte, error) {
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

func daeadDecrypt(ctx context.Context, daeadService *services.DeterministicAeadService, keyset []byte, ciphertext []byte, associatedData []byte) ([]byte, error) {
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
	daeadService := &services.DeterministicAeadService{}
	ctx := context.Background()

	template, err := proto.Marshal(daead.AESSIVKeyTemplate())
	if err != nil {
		t.Fatalf("proto.Marshal(aead.AES128GCMKeyTemplate()) failed: %v", err)
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
		t.Fatalf("proto.Marshal(aead.AES128GCMKeyTemplate()) failed: %v", err)
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
