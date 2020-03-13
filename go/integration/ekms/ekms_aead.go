package ekms

import (
	"bytes"
	"context"
	"fmt"
	"github.com/ThalesIgnite/gose"
	"github.com/ThalesIgnite/gose/jose"
	"github.com/google/tink/go/integration/ekms/google_cloud_ekms_v0"
	"strings"
)

type ekmsAEAD struct {
	aead        gose.AuthenticatedEncryptionKey
	e           gose.JweEncryptor
	d           gose.JweDecryptor
	WrappedBlob []byte
	ClearBlob   []byte // TODO: Remove once EKMS Client OpenSourced for easy hook up to gRPC
	c           google_cloud_ekms_v0.GCPExternalKeyManagementServiceClient
}

func newEkmsAEAD(ctx context.Context, keyURL string, wrappedBlob []byte, c google_cloud_ekms_v0.GCPExternalKeyManagementServiceClient) (a *ekmsAEAD, err error) {
	var jwk jose.Jwk
	var jwkString string
	a = &ekmsAEAD{
		WrappedBlob: wrappedBlob,
		c:           c,
	}

	keyPath := strings.Replace(keyURL, "/v0/", "", 1)
	// Wrapped Key is empty so lets generate and then try to encrypt the
	if a.WrappedBlob == nil {
		gen := &gose.AuthenticatedEncryptionKeyGenerator{}
		if a.aead, jwk, err = gen.Generate(jose.AlgA256GCM, []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt}); err != nil {
			return
		}
		if jwkString, err = gose.JwkToString(jwk); err != nil {
			return
		}

		a.ClearBlob = []byte(jwkString)
		var resp *google_cloud_ekms_v0.WrapResponse
		if resp, err = c.Wrap(ctx, &google_cloud_ekms_v0.WrapRequest{
			KeyPath:   keyPath,
			Plaintext: a.ClearBlob,
		}); err != nil {
			return
		}
		a.WrappedBlob = resp.WrappedBlob
		fmt.Println(string(a.WrappedBlob))
	} else {
		var resp *google_cloud_ekms_v0.UnwrapResponse
		if resp, err = a.c.Unwrap(ctx, &google_cloud_ekms_v0.UnwrapRequest{
			KeyPath:     keyPath,
			WrappedBlob: wrappedBlob,
		}); err != nil {
			return
		}
		if jwk, err = gose.LoadJwk(bytes.NewReader(resp.Plaintext), []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt}); err != nil {
			return
		}
		a.ClearBlob = resp.Plaintext

		return
	}

	a.e = gose.NewJweDirectEncryptorImpl(a.aead)
	a.d = gose.NewJweDirectDecryptorImpl([]gose.AuthenticatedEncryptionKey{a.aead})
	return
}

func (e *ekmsAEAD) Encrypt(plaintext, additionalData []byte) (cipherText []byte, err error) {
	var s string
	if s, err = e.e.Encrypt(plaintext, additionalData); err != nil {
		return
	}

	cipherText = []byte(s)
	return
}

func (e *ekmsAEAD) Decrypt(ciphertext, additionalData []byte) (plaintext []byte, err error) {

	if plaintext, additionalData, err = e.d.Decrypt(string(ciphertext)); err != nil {
		return
	}

	return
}
