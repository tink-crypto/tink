// Copyright 2020 Google LLC
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

package awskms

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/tink/go/integration/awskms/internal/fakeawskms"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
)

func TestNewClientGoodUriPrefixWithAwsPartition(t *testing.T) {
	uriPrefix := "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	_, err := NewClient(uriPrefix)
	if err != nil {
		t.Fatalf("error getting new client with good URI prefix: %v", err)
	}
}

func TestNewClientGoodUriPrefixWithAwsUsGovPartition(t *testing.T) {
	uriPrefix := "aws-kms://arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	_, err := NewClient(uriPrefix)
	if err != nil {
		t.Fatalf("error getting new client with good URI prefix: %v", err)
	}
}

func TestNewClientGoodUriPrefixWithAwsCnPartition(t *testing.T) {
	uriPrefix := "aws-kms://arn:aws-cn:kms:cn-north-1:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	_, err := NewClient(uriPrefix)
	if err != nil {
		t.Fatalf("error getting new client with good URI prefix: %v", err)
	}
}

func TestNewClientBadUriPrefix(t *testing.T) {
	uriPrefix := "bad-prefix://arn:aws-cn:kms:cn-north-1:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"

	_, err := NewClient(uriPrefix)
	if err == nil {
		t.Fatalf("does not reject bad URI prefix: %s", uriPrefix)
	}
}

func TestNewClientWithCredentialsWithGoodCredentialsCsv(t *testing.T) {
	uriPrefix := "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"

	srcDir, ok := os.LookupEnv("TEST_SRCDIR")
	if !ok {
		t.Skip("TEST_SRCDIR not set")
	}
	goodCsvCredFile := filepath.Join(srcDir, "tink_go/testdata/aws/credentials.csv")

	_, err := NewClientWithCredentials(uriPrefix, goodCsvCredFile)
	if err != nil {
		t.Fatalf("reject good CSV cred file: %s", goodCsvCredFile)
	}
}

func TestNewClientWithCredentialsWithGoodCredentialsIni(t *testing.T) {
	uriPrefix := "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"

	srcDir, ok := os.LookupEnv("TEST_SRCDIR")
	if !ok {
		t.Skip("TEST_SRCDIR not set")
	}
	credINIFile := filepath.Join(srcDir, "tink_go/testdata/aws/credentials.cred")

	_, err := NewClientWithCredentials(uriPrefix, credINIFile)
	if err != nil {
		t.Fatalf("reject good CSV cred file: %s", credINIFile)
	}
}

func TestNewClientWithCredentialsWithBadCredentials(t *testing.T) {
	uriPrefix := "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"

	srcDir, ok := os.LookupEnv("TEST_SRCDIR")
	if !ok {
		t.Skip("TEST_SRCDIR not set")
	}
	badCredFile := filepath.Join(srcDir, "tink_go/testdata/aws/access_keys_bad.csv")

	_, err := NewClientWithCredentials(uriPrefix, badCredFile)
	if err == nil {
		t.Fatalf("awskms.NewClientWithCredentials(uriPrefix, badCredFile) err = nil, want error")
	}
}

func TestSupported(t *testing.T) {
	uriPrefix := "aws-kms://arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/"
	supportedKeyURI := "aws-kms://arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	nonSupportedKeyURI := "aws-kms://arn:aws-us-gov:kms:us-gov-east-DOES-NOT-EXIST:key/"

	client, err := NewClient(uriPrefix)
	if err != nil {
		t.Fatal(err)
	}

	if !client.Supported(supportedKeyURI) {
		t.Fatalf("client with URI prefix %s should support key URI %s", uriPrefix, supportedKeyURI)
	}

	if client.Supported(nonSupportedKeyURI) {
		t.Fatalf("client with URI prefix %s should NOT support key URI %s", uriPrefix, nonSupportedKeyURI)
	}
}

func TestGetAeadSupportedURI(t *testing.T) {
	uriPrefix := "aws-kms://arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/"
	supportedKeyURI := "aws-kms://arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"

	client, err := NewClient(uriPrefix)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.GetAEAD(supportedKeyURI)
	if err != nil {
		t.Fatalf("client with URI prefix %s should support key URI %s", uriPrefix, supportedKeyURI)
	}
}

func TestGetAeadEncryptDecrypt(t *testing.T) {
	keyARN := "arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	keyURI := "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	fakekms, err := fakeawskms.New([]string{keyARN})
	if err != nil {
		t.Fatal(err)
	}

	client, err := NewClientWithKMS("aws-kms://", fakekms)
	if err != nil {
		t.Fatal(err)
	}

	a, err := client.GetAEAD(keyURI)
	if err != nil {
		t.Fatalf("client.GetAEAD(keyURI) failed: %s", err)
	}

	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	ciphertext, err := a.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("a.Encrypt(plaintext, associatedData) err = %v, want nil", err)
	}
	decrypted, err := a.Decrypt(ciphertext, associatedData)
	if err != nil {
		t.Fatalf("a.Decrypt(ciphertext, associatedData) err = %v, want nil", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}

	_, err = a.Decrypt(ciphertext, []byte("invalidAssociatedData"))
	if err == nil {
		t.Error("a.Decrypt(ciphertext, []byte{'invalidAssociatedData'}) err = nil, want error")
	}

	_, err = a.Decrypt([]byte("invalidCiphertext"), associatedData)
	if err == nil {
		t.Error("a.Decrypt([]byte{'invalidCiphertext'}, associatedData) err = nil, want error")
	}
}

func TestUsesAdditionalDataAsContextName(t *testing.T) {
	keyARN := "arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	keyURI := "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	fakekms, err := fakeawskms.New([]string{keyARN})
	if err != nil {
		t.Fatal(err)
	}

	client, err := NewClientWithKMS("aws-kms://", fakekms)
	if err != nil {
		t.Fatal(err)
	}

	a, err := client.GetAEAD(keyURI)
	if err != nil {
		t.Fatalf("client.GetAEAD(keyURI) failed: %s", err)
	}

	plaintext := []byte("plaintext")
	associatedData := []byte("associatedData")
	ciphertext, err := a.Encrypt(plaintext, associatedData)
	if err != nil {
		t.Fatalf("a.Encrypt(plaintext, associatedData) err = %v, want nil", err)
	}

	hexAD := hex.EncodeToString(associatedData)
	context := map[string]*string{"additionalData": &hexAD}
	decRequest := &kms.DecryptInput{
		KeyId:             aws.String(keyARN),
		CiphertextBlob:    ciphertext,
		EncryptionContext: context,
	}
	decResponse, err := fakekms.Decrypt(decRequest)
	if err != nil {
		t.Fatalf("fakeKMS.Decrypt(decRequest) err = %s, want nil", err)
	}
	if !bytes.Equal(decResponse.Plaintext, plaintext) {
		t.Fatalf("decResponse.Plaintext = %q, want %q", decResponse.Plaintext, plaintext)
	}
	if strings.Compare(*decResponse.KeyId, keyARN) != 0 {
		t.Fatalf("decResponse.KeyId = %q, want %q", *decResponse.KeyId, keyARN)
	}
}
