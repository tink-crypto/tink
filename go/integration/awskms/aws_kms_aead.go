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
	"encoding/base64"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/tink"
)

// AWSAEAD represents a AWS KMS service to a particular URI.
type AWSAEAD struct {
	keyURI string
	kms    *kms.KMS
}

var (
	_       tink.AEAD = (*AWSAEAD)(nil)
	awsaead           = aead.New
)

// NewAWSAEAD returns a new AWS KMS service.
func NewAWSAEAD(keyURI string, kms *kms.KMS) *AWSAEAD {
	return &AWSAEAD{
		keyURI: keyURI,
		kms:    kms,
	}
}

// Encrypt AEAD encrypts the plaintext data and uses addtionaldata from authentication.
func (a *AWSAEAD) Encrypt(plaintext, additionalData []byte) ([]byte, error) {
	ad := base64.StdEncoding.EncodeToString(additionalData)
	req := &kms.EncryptInput{
		KeyId:             aws.String(a.keyURI),
		Plaintext:         plaintext,
		EncryptionContext: map[string]*string{"additionalData": &ad},
	}
	resp, err := a.kms.Encrypt(req)
	if err != nil {
		return nil, err
	}

	return resp.CiphertextBlob, nil
}

// Decrypt AEAD decrypts the data and verified the additional data.
func (a *AWSAEAD) Decrypt(ciphertext, additionalData []byte) ([]byte, error) {
	ad := base64.StdEncoding.EncodeToString(additionalData)
	req := &kms.DecryptInput{
		CiphertextBlob:    ciphertext,
		EncryptionContext: map[string]*string{"additionalData": &ad},
	}
	resp, err := a.kms.Decrypt(req)
	if strings.Compare(*resp.KeyId, a.keyURI) != 0 {
		return nil, errors.New("decryption failed: wrong key id")
	}
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}
