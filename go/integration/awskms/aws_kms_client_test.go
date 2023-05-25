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

func TestNewClient_URIPrefix(t *testing.T) {
	tests := []struct {
		name      string
		uriPrefix string
		valid     bool
	}{
		{
			name:      "AWS partition",
			uriPrefix: "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f",
			valid:     true,
		},
		{
			name:      "AWS US government partition",
			uriPrefix: "aws-kms://arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f",
			valid:     true,
		},
		{
			name:      "AWS CN partition",
			uriPrefix: "aws-kms://arn:aws-cn:kms:cn-north-1:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f",
			valid:     true,
		},
		{
			name:      "invalid",
			uriPrefix: "bad-prefix://arn:aws-cn:kms:cn-north-1:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f",
			valid:     false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewClient(test.uriPrefix)
			if test.valid && err != nil {
				t.Errorf("NewClient(%q) err = %v, want nil", test.uriPrefix, err)
			}
			if !test.valid && err == nil {
				t.Errorf("NewClient(%q) err = nil, want error", test.uriPrefix)
			}
		})
	}
}

func TestNewClient_credentialPath(t *testing.T) {
	srcDir, ok := os.LookupEnv("TEST_SRCDIR")
	if !ok {
		t.Skip("TEST_SRCDIR not set")
	}

	uriPrefix := "aws-kms://arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/"

	tests := []struct {
		name     string
		credFile string
		valid    bool
	}{
		{
			name:     "valid CSV credentials file",
			credFile: filepath.Join(srcDir, "tink_go/testdata/aws/credentials.csv"),
			valid:    true,
		},
		{
			name:     "valid INI credentials file",
			credFile: filepath.Join(srcDir, "tink_go/testdata/aws/credentials.cred"),
			valid:    true,
		},
		{
			name:     "invalid credentials file",
			credFile: filepath.Join(srcDir, "tink_go/testdata/aws/access_keys_bad.csv"),
			valid:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewClientWithCredentials(uriPrefix, test.credFile)
			if test.valid && err != nil {
				t.Errorf("NewClientWithCredentials(uriPrefix, %q) err = %v, want nil", test.credFile, err)
			}
			if !test.valid && err == nil {
				t.Errorf("NewClientWithCredentials(uriPrefix, %q) err = nil, want error", test.credFile)
			}
		})
	}
}

func TestSupported(t *testing.T) {
	uriPrefix := "aws-kms://arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/"
	supportedKeyURI := "aws-kms://arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	nonSupportedKeyURI := "aws-kms://arn:aws-us-gov:kms:us-gov-east-DOES-NOT-EXIST:key/"

	client, err := NewClient(uriPrefix)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	if !client.Supported(supportedKeyURI) {
		t.Errorf("client with URI prefix %q should support key URI %q", uriPrefix, supportedKeyURI)
	}

	if client.Supported(nonSupportedKeyURI) {
		t.Errorf("client with URI prefix %q should NOT support key URI %q", uriPrefix, nonSupportedKeyURI)
	}
}

func TestGetAEADSupportedURI(t *testing.T) {
	uriPrefix := "aws-kms://arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/"
	supportedKeyURI := "aws-kms://arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"

	client, err := NewClient(uriPrefix)
	if err != nil {
		t.Fatalf("NewClient() failed: %v", err)
	}

	_, err = client.GetAEAD(supportedKeyURI)
	if err != nil {
		t.Errorf("client with URI prefix %q should support key URI %q", uriPrefix, supportedKeyURI)
	}
}

func TestGetAEADEncryptDecrypt(t *testing.T) {
	keyARN := "arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	keyURI := "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	fakekms, err := fakeawskms.New([]string{keyARN})
	if err != nil {
		t.Fatalf("fakekms.New() failed: %v", err)
	}

	client, err := NewClientWithKMS("aws-kms://", fakekms)
	if err != nil {
		t.Fatalf("NewClientWithKMS() failed: %v", err)
	}

	a, err := client.GetAEAD(keyURI)
	if err != nil {
		t.Fatalf("client.GetAEAD(keyURI) err = %v, want nil", err)
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
		t.Error("a.Decrypt(ciphertext, []byte(\"invalidAssociatedData\")) err = nil, want error")
	}

	_, err = a.Decrypt([]byte("invalidCiphertext"), associatedData)
	if err == nil {
		t.Error("a.Decrypt([]byte(\"invalidCiphertext\"), associatedData) err = nil, want error")
	}
}

func TestUsesAdditionalDataAsContextName(t *testing.T) {
	keyARN := "arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	keyURI := "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f"
	fakekms, err := fakeawskms.New([]string{keyARN})
	if err != nil {
		t.Fatalf("fakeawskms.New() failed: %v", err)
	}

	client, err := NewClientWithKMS("aws-kms://", fakekms)
	if err != nil {
		t.Fatalf("NewClientWithKMS() failed: %v", err)
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
		t.Errorf("decResponse.Plaintext = %q, want %q", decResponse.Plaintext, plaintext)
	}
	if strings.Compare(*decResponse.KeyId, keyARN) != 0 {
		t.Errorf("decResponse.KeyId = %q, want %q", *decResponse.KeyId, keyARN)
	}
}
