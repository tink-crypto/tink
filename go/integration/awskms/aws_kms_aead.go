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

// Package awskms provides integration with the AWS Cloud KMS.
package awskms

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

// AWSAEAD represents a AWS KMS service to a particular URI.
type AWSAEAD struct {
	keyURI string
	kms    kmsiface.KMSAPI
}

// newAWSAEAD returns a new AWS KMS service.
// keyURI must have the following format: 'arn:<partition>:kms:<region>:[:path]'.
// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
func newAWSAEAD(keyURI string, kms kmsiface.KMSAPI) *AWSAEAD {
	return &AWSAEAD{
		keyURI: keyURI,
		kms:    kms,
	}
}

// Encrypt encrypts the plaintext with associatedData.
func (a *AWSAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	ad := hex.EncodeToString(associatedData)
	req := &kms.EncryptInput{
		KeyId:             aws.String(a.keyURI),
		Plaintext:         plaintext,
		EncryptionContext: map[string]*string{"additionalData": &ad},
	}
	if ad == "" {
		req = &kms.EncryptInput{
			KeyId:     aws.String(a.keyURI),
			Plaintext: plaintext,
		}
	}
	resp, err := a.kms.Encrypt(req)
	if err != nil {
		return nil, err
	}

	return resp.CiphertextBlob, nil
}

// Decrypt AEAD decrypts the data and verified the associated data.
//
// Returns an error if the KeyId field in the response does not match the KeyURI
// provided when creating the client. If we don't do this, the possibility exists
// for the ciphertext to be replaced by one under a key we don't control/expect,
// but do have decrypt permissions on.
//
// This check is disabled if AWSAEAD.keyURI is not in key ARN format.
//
// See https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id.
func (a *AWSAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	ad := hex.EncodeToString(associatedData)
	req := &kms.DecryptInput{
		KeyId:             aws.String(a.keyURI),
		CiphertextBlob:    ciphertext,
		EncryptionContext: map[string]*string{"additionalData": &ad},
	}
	if ad == "" {
		req = &kms.DecryptInput{
			CiphertextBlob: ciphertext,
		}
	}
	resp, err := a.kms.Decrypt(req)
	if err != nil {
		return nil, err
	}
	if isKeyArnFormat(a.keyURI) && strings.Compare(*resp.KeyId, a.keyURI) != 0 {
		return nil, errors.New("decryption failed: wrong key id")
	}
	return resp.Plaintext, nil
}

// isKeyArnFormat returns true if the keyURI is the KMS Key ARN format; false otherwise.
func isKeyArnFormat(keyURI string) bool {
	tokens := strings.Split(keyURI, ":")
	return len(tokens) == 6 && strings.HasPrefix(tokens[5], "key/")
}
