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
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/tink"
)

const (
	awsPrefix = "aws-kms://"
)

var (
	errCred = errors.New("invalid credential path")
)

// AWSClient represents a client that connects to the AWS KMS backend.
type AWSClient struct {
	keyURI string
	kms    *kms.KMS
	region string
}

var _ registry.KMSClient = (*AWSClient)(nil)

// NewAWSClient returns a new client to AWS KMS. It does not have an established session.
func NewAWSClient(URI string) (*AWSClient, error) {
	if !strings.HasPrefix(strings.ToLower(URI), awsPrefix) {
		return nil, fmt.Errorf("key URI must start with %s", awsPrefix)
	}
	r, err := getRegion(URI)
	if err != nil {
		return nil, err
	}
	return &AWSClient{
		keyURI: URI,
		region: r,
	}, nil

}

// Supported true if this client does support keyURI
func (g *AWSClient) Supported(keyURI string) bool {
	if (len(g.keyURI) > 0) && (strings.Compare(strings.ToLower(g.keyURI), strings.ToLower(keyURI)) == 0) {
		return true
	}
	return ((len(g.keyURI) == 0) && (strings.HasPrefix(strings.ToLower(keyURI), awsPrefix)))
}

// LoadCredentials loads the credentials in credentialPath. If credentialPath is  null, loads the
// default credentials.
func (g *AWSClient) LoadCredentials(credentialPath string) (interface{}, error) {
	var creds *credentials.Credentials
	if len(credentialPath) <= 0 {
		return nil, errCred
	}
	c, err := extractCredsCSV(credentialPath)
	if err != nil {
		creds = credentials.NewSharedCredentials(credentialPath, "default")
	} else {
		creds = credentials.NewStaticCredentialsFromCreds(*c)
	}
	session := session.Must(session.NewSession(&aws.Config{
		Credentials: creds,
		Region:      aws.String(g.region),
	}))

	g.kms = kms.New(session)
	return g, nil
}

// LoadDefaultCredentials loads with the default credentials.
func (g *AWSClient) LoadDefaultCredentials() (interface{}, error) {
	session := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(g.region),
	}))
	g.kms = kms.New(session)
	return g, nil
}

// GetAEAD gets an AEAD backend by keyURI.
func (g *AWSClient) GetAEAD(keyURI string) (tink.AEAD, error) {
	if len(g.keyURI) > 0 && strings.Compare(strings.ToLower(g.keyURI), strings.ToLower(keyURI)) != 0 {
		return nil, fmt.Errorf("this client is bound to %s, cannot load keys bound to %s", g.keyURI, keyURI)
	}
	uri, err := validateTrimKMSPrefix(g.keyURI, awsPrefix)
	if err != nil {
		return nil, err
	}
	return NewAWSAEAD(uri, g.kms), nil
}

func validateKMSPrefix(keyURI, prefix string) bool {
	if len(keyURI) > 0 && strings.HasPrefix(strings.ToLower(keyURI), awsPrefix) {
		return true
	}
	return false
}

func validateTrimKMSPrefix(keyURI, prefix string) (string, error) {
	if !validateKMSPrefix(keyURI, prefix) {
		return "", fmt.Errorf("key URI must start with %s", prefix)
	}
	return strings.TrimPrefix(keyURI, prefix), nil
}

func extractCredsCSV(file string) (*credentials.Value, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	lines, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, err
	}
	if len(lines) < 2 {
		return nil, errors.New("invalid csv file")
	}
	return &credentials.Value{
		AccessKeyID:     lines[1][2],
		SecretAccessKey: lines[1][3],
	}, nil

}

func getRegion(keyURI string) (string, error) {
	re1, err := regexp.Compile(`aws-kms://arn:aws:kms:([a-z0-9-]+):`)
	if err != nil {
		return "", err
	}
	r := re1.FindStringSubmatch(keyURI)
	if len(r) != 2 {
		return "", errors.New("extracting region from URI failed")
	}
	return r[1], nil
}
