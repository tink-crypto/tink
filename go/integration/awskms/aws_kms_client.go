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

package awskms

import (
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/tink"
)

const (
	awsPrefix = "aws-kms://"
)

var (
	errCred    = errors.New("invalid credential path")
	errBadFile = errors.New("cannot open credential path")
	errCredCSV = errors.New("malformed credential CSV file")
)

// awsClient is a wrapper around an AWS SDK provided KMS client that can
// instantiate Tink primitives.
type awsClient struct {
	keyURIPrefix          string
	kms                   kmsiface.KMSAPI
	encryptionContextName EncryptionContextName
}

// ClientOption is an interface for defining options that are passed to
// [NewClientWithOptions].
type ClientOption interface{ set(*awsClient) error }

type option func(*awsClient) error

func (o option) set(a *awsClient) error { return o(a) }

// WithCredentialPath instantiates the underlying AWS KMS client using the
// credentials located at credentialPath.
//
// credentialPath can specify a file in CSV format as provided in the IAM
// console or an INI-style credentials file.
//
// See https://docs.aws.amazon.com/cli/latest/userguide/cli-authentication-user.html#cli-authentication-user-configure-csv
// and https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html#cli-configure-files-format.
func WithCredentialPath(credentialPath string) ClientOption {
	return option(func(a *awsClient) error {
		if a.kms != nil {
			return errors.New("WithCredentialPath option cannot be used, KMS client already set")
		}

		k, err := getKMSFromCredentialPath(a.keyURIPrefix, credentialPath)
		if err != nil {
			return err
		}

		a.kms = k
		return nil
	})
}

// WithKMS sets the underlying AWS KMS client to kms, a preexisting AWS KMS
// client instance.
//
// It's the callers responsibility to ensure that the configured region of kms
// aligns with the region in key URIs passed to this client. Otherwise, API
// requests will fail.
func WithKMS(kms kmsiface.KMSAPI) ClientOption {
	return option(func(a *awsClient) error {
		if a.kms != nil {
			return errors.New("WithKMS option cannot be used, KMS client already set")
		}
		a.kms = kms
		return nil
	})
}

// EncryptionContextName specifies the name used in the EncryptionContext field
// of EncryptInput and DecryptInput requests. See [WithEncryptionContextName]
// for further details.
type EncryptionContextName uint

const (
	// AssociatedData will set the EncryptionContext name to "associatedData".
	AssociatedData EncryptionContextName = 1 + iota
	// LegacyAdditionalData will set the EncryptionContext name to "additionalData".
	LegacyAdditionalData
)

var encryptionContextNames = map[EncryptionContextName]string{
	AssociatedData: "associatedData",
	LegacyAdditionalData: "additionalData",
}

func (n EncryptionContextName) valid() bool {
	_, ok := encryptionContextNames[n]
	return ok
}

func (n EncryptionContextName) String() string {
	if !n.valid() {
		return "unrecognized value " + strconv.Itoa(int(n))
	}
	return encryptionContextNames[n]
}

// WithEncryptionContextName sets the name which maps to the base64 encoded
// associated data within the EncryptionContext field of EncrypInput and
// DecryptInput requests.
//
// The default is [AssociatedData], which is compatible with the Tink AWS KMS
// extensions in other languages. In older versions of this packge, before this
// option was present, "additionalData" was hardcoded.
//
// This option is provided to facilitate compatibility with older ciphertexts.
func WithEncryptionContextName(name EncryptionContextName) ClientOption {
	return option(func(a *awsClient) error {
		if !name.valid() {
			return fmt.Errorf("invalid EncryptionContextName: %v", name)
		}
		if a.encryptionContextName != 0 {
			return errors.New("encryptionContextName already set")
		}
		a.encryptionContextName = name
		return nil
	})
}

// NewClientWithOptions returns a [registry.KMSClient] which wraps an AWS KMS
// client and will handle keys whose URIs start with uriPrefix.
//
// By default, the client will use default credentials.
//
// AEAD primitives produced by this client will use [AssociatedData] when
// serializing associated data.
func NewClientWithOptions(uriPrefix string, opts ...ClientOption) (registry.KMSClient, error) {
	if !strings.HasPrefix(strings.ToLower(uriPrefix), awsPrefix) {
		return nil, fmt.Errorf("uriPrefix must start with %q, but got %q", awsPrefix, uriPrefix)
	}

	a := &awsClient{
		keyURIPrefix: uriPrefix,
	}

	// Process options, if any.
	for _, opt := range opts {
		if err := opt.set(a); err != nil {
			return nil, fmt.Errorf("failed setting option: %v", err)
		}
	}

	// Populate values not defined via options.
	if a.kms == nil {
		k, err := getKMS(uriPrefix)
		if err != nil {
			return nil, err
		}
		a.kms = k
	}
	if a.encryptionContextName == 0 {
		a.encryptionContextName = AssociatedData
	}

	return a, nil
}

// NewClient returns a KMSClient backed by AWS KMS using default credentials to
// handle keys whose URIs start with uriPrefix.
//
// uriPrefix must have the following format:
//
//	aws-kms://arn:<partition>:kms:<region>:[<path>]
//
// See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html
//
// AEAD primitives produced by this client will use [LegacyAdditionalData] when
// serializing associated data.
//
// Deprecated: Instead, use [NewClientWithOptions].
//
//	awskms.NewClientWithOptions(uriPrefix)
func NewClient(uriPrefix string) (registry.KMSClient, error) {
	return NewClientWithOptions(uriPrefix, WithEncryptionContextName(LegacyAdditionalData))
}

// NewClientWithCredentials returns a KMSClient backed by AWS KMS using the given
// credentials to handle keys whose URIs start with uriPrefix.
//
// uriPrefix must have the following format:
//
//	aws-kms://arn:<partition>:kms:<region>:[<path>]
//
// See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html
//
// credentialPath can specify a file in CSV format as provided in the IAM
// console or an INI-style credentials file.
//
// See https://docs.aws.amazon.com/cli/latest/userguide/cli-authentication-user.html#cli-authentication-user-configure-csv
// and https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html#cli-configure-files-format.
//
// AEAD primitives produced by this client will use [LegacyAdditionalData] when
// serializing associated data.
//
// Deprecated: Instead use [NewClientWithOptions] and [WithCredentialPath].
//
//	awskms.NewClientWithOptions(uriPrefix, awskms.WithCredentialPath(credentialPath))
func NewClientWithCredentials(uriPrefix string, credentialPath string) (registry.KMSClient, error) {
	return NewClientWithOptions(uriPrefix, WithCredentialPath(credentialPath), WithEncryptionContextName(LegacyAdditionalData))
}

// NewClientWithKMS returns a KMSClient backed by AWS KMS using the provided
// instance of the AWS SDK KMS client.
//
// The caller is responsible for ensuring that the region specified in the KMS
// client is consitent with the region specified within uriPrefix.
//
// uriPrefix must have the following format:
//
//	aws-kms://arn:<partition>:kms:<region>:[<path>]
//
// See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html
//
// AEAD primitives produced by this client will use [LegacyAdditionalData] when
// serializing associated data.
//
// Deprecated: Instead use [NewClientWithOptions] and [WithKMS].
//
//	awskms.NewClientWithOptions(uriPrefix, awskms.WithKMS(kms))
func NewClientWithKMS(uriPrefix string, kms kmsiface.KMSAPI) (registry.KMSClient, error) {
	return NewClientWithOptions(uriPrefix, WithKMS(kms), WithEncryptionContextName(LegacyAdditionalData))
}

// Supported returns true if keyURI starts with the URI prefix provided when
// creating the client.
func (c *awsClient) Supported(keyURI string) bool {
	return strings.HasPrefix(keyURI, c.keyURIPrefix)
}

// GetAEAD returns an implementation of the AEAD interface which performs
// cryptographic operations remotely via AWS KMS using keyURI.
//
// keyUri must be supported by this client and must have the following format:
//
//	aws-kms://arn:<partition>:kms:<region>:<path>
//
// See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html
func (c *awsClient) GetAEAD(keyURI string) (tink.AEAD, error) {
	if !c.Supported(keyURI) {
		return nil, fmt.Errorf("keyURI must start with prefix %s, but got %s", c.keyURIPrefix, keyURI)
	}

	uri := strings.TrimPrefix(keyURI, awsPrefix)
	return newAWSAEAD(uri, c.kms, c.encryptionContextName), nil
}

func getKMS(uriPrefix string) (*kms.KMS, error) {
	r, err := getRegion(uriPrefix)
	if err != nil {
		return nil, err
	}

	session, err := session.NewSession(&aws.Config{
		Region: aws.String(r),
	})
	if err != nil {
		return nil, err
	}

	return kms.New(session), nil
}

func getKMSFromCredentialPath(uriPrefix string, credentialPath string) (*kms.KMS, error) {
	r, err := getRegion(uriPrefix)
	if err != nil {
		return nil, err
	}

	var creds *credentials.Credentials
	if len(credentialPath) == 0 {
		return nil, errCred
	}
	c, err := extractCredsCSV(credentialPath)
	switch err {
	case nil:
		creds = credentials.NewStaticCredentialsFromCreds(*c)
	case errBadFile, errCredCSV:
		return nil, err
	default:
		// Fallback to load the credential path as .ini shared credentials.
		creds = credentials.NewSharedCredentials(credentialPath, "default")
	}

	session, err := session.NewSession(&aws.Config{
		Credentials: creds,
		Region:      aws.String(r),
	})
	if err != nil {
		return nil, err
	}

	return kms.New(session), nil
}

// extractCredsCSV extracts credentials from a CSV file.
//
// A CSV formatted credentials file can be obtained when an AWS IAM user is
// created through the IAM console.
//
// Properties of a properly formatted CSV file:
//
//  1. The first line consists of the headers:
//     "User name,Password,Access key ID,Secret access key,Console login link"
//  2. The second line contains 5 comma separated values.
func extractCredsCSV(file string) (*credentials.Value, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, errBadFile
	}
	defer f.Close()

	lines, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, err
	}

	// It is possible that the file is an AWS .ini credential file, and it can be
	// parsed as 1-column CSV file as well. A real AWS credentials.csv is never 1 column.
	if len(lines) > 0 && len(lines[0]) == 1 {
		return nil, errors.New("not a valid CSV credential file")
	}

	if len(lines) < 2 {
		return nil, errCredCSV
	}

	if len(lines[1]) < 4 {
		return nil, errCredCSV
	}

	return &credentials.Value{
		AccessKeyID:     lines[1][2],
		SecretAccessKey: lines[1][3],
	}, nil
}

// getRegion extracts the region from keyURI.
func getRegion(keyURI string) (string, error) {
	re1, err := regexp.Compile(`aws-kms://arn:(aws[a-zA-Z0-9-_]*):kms:([a-z0-9-]+):`)
	if err != nil {
		return "", err
	}
	r := re1.FindStringSubmatch(keyURI)
	if len(r) != 3 {
		return "", errors.New("extracting region from URI failed")
	}
	return r[2], nil
}
