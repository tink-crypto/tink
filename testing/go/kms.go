// Copyright 2023 Google LLC
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

// Package kms registers all KMS clients
package kms

import (
	"context"
	"log"

	// place-holder to import crypto/tls
	"flag"
	"google.golang.org/api/option"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/integration/awskms"
	"github.com/google/tink/go/integration/gcpkms"
	"github.com/google/tink/go/testing/fakekms"
	// place-holder to import tink-go-hcvault
)

var (
	gcpCredFilePath     = flag.String("gcp_credentials_path", "", "Google Cloud KMS credentials path")
	gcpKeyURI           = flag.String("gcp_key_uri", "", "Google Cloud KMS key URI of the form: gcp-kms://projects/*/locations/*/keyRings/*/cryptoKeys/*.")
	awsCredFilePath     = flag.String("aws_credentials_path", "", "AWS KMS credentials path")
	awsKeyURI           = flag.String("aws_key_uri", "", "AWS KMS key URI of the form: aws-kms://arn:aws:kms:<region>:<account-id>:key/<key-id>.")
	hcvaultKeyURIPrefix = flag.String("hcvault_key_uri_prefix", "", "HC Vault key URI prefix of the form: hcvault://example.com:8200/key/path")
	hcvaultToken        = flag.String("hcvault_token", "", "HC Vault token")
)

// RegisterAll registers all KMS clients.
func RegisterAll() {
	client, err := fakekms.NewClient("fake-kms://")
	if err != nil {
		log.Fatalf("fakekms.NewClient failed: %v", err)
	}
	registry.RegisterKMSClient(client)

	gcpClient, err := gcpkms.NewClientWithOptions(context.Background(), *gcpKeyURI, option.WithCredentialsFile(*gcpCredFilePath))
	if err != nil {
		log.Fatalf("gcpkms.NewClientWithOptions failed: %v", err)
	}
	registry.RegisterKMSClient(gcpClient)

	awsClient, err := awskms.NewClientWithOptions(*awsKeyURI, awskms.WithCredentialPath(*awsCredFilePath))
	if err != nil {
		log.Fatalf("awskms.NewClientWithOptions failed: %v", err)
	}
	registry.RegisterKMSClient(awsClient)

	// place-holder to register hcvault client
}
