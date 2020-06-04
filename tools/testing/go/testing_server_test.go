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

package testing_server_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"testing"
	"time"

	// TEST_SRCDIR to read the roots.pem
	"google3/net/grpc/go/grpcprod"
	"google3/net/util/go/portpicker"
	"google3/third_party/golang/grpc/grpc"
	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	pbgrpc "github.com/google/tink/go/proto/testing/testing_api_go_grpc"
	pb "github.com/google/tink/go/proto/testing/testing_api_go_proto"
)

const (
	serverPath = "google3/third_party/tink/tools/testing/go/testing_server"
)

func genKeyset(ctx context.Context, keysetClient pbgrpc.KeysetClient, template []byte) ([]byte, error) {
	genRequest := &pb.GenerateKeysetRequest{Template: template}
	genResponse, err := keysetClient.Generate(ctx, genRequest, grpc.WaitForReady(true))
	if err != nil {
		return nil, err
	}
	switch r := genResponse.Result.(type) {
	case *pb.KeysetResponse_Keyset:
		return r.Keyset, nil
	case *pb.KeysetResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("encResponse.Result has unexpected type %T", r)
	}
}

func aeadEncrypt(ctx context.Context, aeadClient pbgrpc.AeadClient, keyset []byte, plaintext []byte, associatedData []byte) ([]byte, error) {
	encRequest := &pb.AeadEncryptRequest{
		Keyset:         keyset,
		Plaintext:      plaintext,
		AssociatedData: associatedData,
	}
	encResponse, err := aeadClient.Encrypt(ctx, encRequest, grpc.WaitForReady(true))
	if err != nil {
		return nil, err
	}
	switch r := encResponse.Result.(type) {
	case *pb.CiphertextResponse_Ciphertext:
		return r.Ciphertext, nil
	case *pb.CiphertextResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("encResponse.Result has unexpected type %T", r)
	}
}

func aeadDecrypt(ctx context.Context, aeadClient pbgrpc.AeadClient, keyset []byte, ciphertext []byte, associatedData []byte) ([]byte, error) {
	decRequest := &pb.AeadDecryptRequest{
		Keyset:         keyset,
		Ciphertext:     ciphertext,
		AssociatedData: associatedData,
	}
	decResponse, err := aeadClient.Decrypt(ctx, decRequest, grpc.WaitForReady(true))
	if err != nil {
		return nil, err
	}
	switch r := decResponse.Result.(type) {
	case *pb.PlaintextResponse_Plaintext:
		return r.Plaintext, nil
	case *pb.PlaintextResponse_Err:
		return nil, errors.New(r.Err)
	default:
		return nil, fmt.Errorf("encResponse.Result has unexpected type %T", r)
	}
}

// TestTestingServer starts the testing server and does some basic RPC calls.
func TestTestingServer(t *testing.T) {
	port, _ := portpicker.PickUnusedPort()
	svrcmnd := exec.Command(runfiles.Path(serverPath), ("--port=" + strconv.Itoa(port)), "--logtostderr")
	if err := svrcmnd.Start(); err != nil {
		t.Fatalf("Error starting testing_server %v", err)
	}
	defer svrcmnd.Process.Kill()

	dialConfig := grpcprod.DefaultDialConfig()
	var dialOpts []grpc.DialOption
	conn, err := grpcprod.Dial("localhost:"+strconv.Itoa(port), dialConfig, dialOpts...)
	if err != nil {
		t.Fatalf("Fail to dial: %v", err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	keysetClient := pbgrpc.NewKeysetClient(conn)
	aeadClient := pbgrpc.NewAeadClient(conn)

	template, err := proto.Marshal(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("proto.Marshal(aead.AES128GCMKeyTemplate()) failed: %v", err)
	}
	keyset, err := genKeyset(ctx, keysetClient, template)
	if err != nil {
		t.Fatalf("genKeyset failed: %v", err)
	}

	plaintext := []byte("The quick brown fox jumps over the lazy dog")
	associatedData := []byte("Associated Data")
	ciphertext, err := aeadEncrypt(ctx, aeadClient, keyset, plaintext, associatedData)
	if err != nil {
		t.Fatalf("Aead Encrypt failed: %v", err)
	}
	output, err := aeadDecrypt(ctx, aeadClient, keyset, ciphertext, associatedData)
	if err != nil {
		t.Fatalf("aeadDecrypt failed: %v", err)
	}
	if bytes.Compare(output, plaintext) != 0 {
		t.Fatalf("Decrypted ciphertext is %v, want %v", output, plaintext)
	}

	if _, err := genKeyset(ctx, keysetClient, []byte("badTemplate")); err == nil {
		t.Fatalf("genKeyset from bad template succeeded unexpectedly.")
	}
	if _, err := aeadEncrypt(ctx, aeadClient, []byte("badKeyset"), plaintext, associatedData); err == nil {
		t.Fatalf("aeadEncrypt with bad keyset succeeded unexpectedly.")
	}
	if _, err := aeadDecrypt(ctx, aeadClient, keyset, []byte("badCiphertext"), associatedData); err == nil {
		t.Fatalf("aeadDecrypt of bad ciphertext succeeded unexpectedly.")
	}
}
