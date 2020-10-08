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
	errCredCSV = errors.New("malformed credential csv file")
)

// awsClient represents a client that connects to the AWS KMS backend.
type awsClient struct {
	keyURIPrefix string
	kms          kmsiface.KMSAPI
}

// NewClient returns a new AWS KMS client which will use default
// credentials to handle keys with uriPrefix prefix.
// uriPrefix must have the following format: 'aws-kms://arn:<partition>:kms:<region>:[:path]'.
// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
func NewClient(uriPrefix string) (registry.KMSClient, error) {
	r, err := getRegion(uriPrefix)
	if err != nil {
		return nil, err
	}

	session := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(r),
	}))

	return NewClientWithKMS(uriPrefix, kms.New(session))
}

// NewClientWithCredentials returns a new AWS KMS client which will use given
// credentials to handle keys with uriPrefix prefix.
// uriPrefix must have the following format: 'aws-kms://arn:<partition>:kms:<region>:[:path]'.
// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
func NewClientWithCredentials(uriPrefix string, credentialPath string) (registry.KMSClient, error) {
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
		// fallback to load the credential path as .ini shared credentials.
		creds = credentials.NewSharedCredentials(credentialPath, "default")
	}
	session := session.Must(session.NewSession(&aws.Config{
		Credentials: creds,
		Region:      aws.String(r),
	}))

	return NewClientWithKMS(uriPrefix, kms.New(session))
}

// NewClientWithKMS returns a new AWS KMS client with user created KMS client.
// Client is responsible for keeping the region consistency between key URI and KMS client.
// uriPrefix must have the following format: 'aws-kms://arn:<partition>:kms:<region>:[:path]'.
// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
func NewClientWithKMS(uriPrefix string, kms kmsiface.KMSAPI) (registry.KMSClient, error) {
	if !strings.HasPrefix(strings.ToLower(uriPrefix), awsPrefix) {
		return nil, fmt.Errorf("uriPrefix must start with %s, but got %s", awsPrefix, uriPrefix)
	}

	return &awsClient{
		keyURIPrefix: uriPrefix,
		kms:          kms,
	}, nil
}

// Supported true if this client does support keyURI
func (c *awsClient) Supported(keyURI string) bool {
	return strings.HasPrefix(keyURI, c.keyURIPrefix)
}

// GetAEAD gets an AEAD backend by keyURI.
// keyURI must have the following format: 'aws-kms://arn:<partition>:kms:<region>:[:path]'.
// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
func (c *awsClient) GetAEAD(keyURI string) (tink.AEAD, error) {
	if !c.Supported(keyURI) {
		return nil, fmt.Errorf("keyURI must start with prefix %s, but got %s", c.keyURIPrefix, keyURI)
	}

	uri := strings.TrimPrefix(keyURI, awsPrefix)
	return newAWSAEAD(uri, c.kms), nil
}

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

	// credentials.csv can be obtained when a AWS IAM user is created through IAM console.
	// The first line of the csv file is "User name,Password,Access key ID,Secret access key,Console login link"
	// The 2nd line of it contains 5 comma separated values.
	// Parse the file with a strict format assumption as follows:
	// 1. There must be at least 4 columns and 2 rows.
	// 2. The access key id and the secret access key must be on (0-based) column 2 and 3.
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

func getRegion(keyURI string) (string, error) {
	// keyURI must have the following format: 'aws-kms://arn:<partition>:kms:<region>:[:path]'.
	// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
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
