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
	"os"
	"path/filepath"
	"testing"
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
	goodCsvCredFile := filepath.Join(srcDir, "tink_go/testdata/credentials_aws.csv")

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
	credINIFile := filepath.Join(srcDir, "tink_go/testdata/credentials_aws.cred")

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
	badCredFile := filepath.Join(srcDir, "tink_go/testdata/bad_access_keys_aws.csv")

	_, err := NewClientWithCredentials(uriPrefix, badCredFile)
	if err == nil {
		t.Fatalf("does not reject two-column csv file, expect error : %v", errCredCSV)
	}
	if err != errCredCSV {
		t.Fatalf("expect error : %v, got: %v", errCredCSV, err)
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

func TestGetAeadNonSupportedURI(t *testing.T) {
	uriPrefix := "aws-kms://arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/"
	nonSupportedKeyURI := "aws-kms://arn:aws-us-gov:kms:us-gov-east-DOES-NOT-EXIST:key/"

	client, err := NewClient(uriPrefix)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.GetAEAD(nonSupportedKeyURI)
	if err == nil {
		t.Fatalf("client with URI prefix %s should NOT support key URI %s", uriPrefix, nonSupportedKeyURI)
	}
}
