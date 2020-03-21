package pkcs11kms

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"github.com/google/tink/go/tink"
	"io"

	"github.com/ThalesIgnite/crypto11"
	"github.com/ThalesIgnite/gose"
	"github.com/ThalesIgnite/gose/jose"
)

type pkcs11AEAD struct {
	ctx  *crypto11.Context
	jwee gose.JweEncryptor
	jwed gose.JweDecryptor
}

var _ tink.AEAD = (*pkcs11AEAD)(nil)

func newPkcs11AEAD(ctx *crypto11.Context, keyURI string, autogen bool) (p *pkcs11AEAD, err error) {

	p = &pkcs11AEAD{ctx: ctx}

	// Warm up Device...
	var k *Key
	if k, err = parseKeyURI(keyURI); err != nil {
		return
	}
	var aead cipher.AEAD
	var sk *crypto11.SecretKey
	if sk, err = ctx.FindKey([]byte(k.id.String()), nil); err != nil {
		return
	} else if sk == nil {
		// Generate
		if autogen {
			//err = fmt.Errorf("Generate key that doesn't exist: %s", k.id)
			if sk, err = ctx.GenerateSecretKey([]byte(k.id.String()), 256, crypto11.CipherAES); err != nil {
				return
			}
		} else {
			err = fmt.Errorf("key not found: %s", k.id)
			return
		}

	}

	if aead, err = sk.NewGCM(); err != nil {
		return
	}
	var rng io.Reader
	if rng, err = ctx.NewRandomReader(); err != nil {
		return
	}

	var aek gose.AuthenticatedEncryptionKey
	if aek, err = gose.NewAesGcmCryptor(aead, rng, k.id.String(), jose.AlgA256GCM, []jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt}); err != nil {
		return
	}

	// Load encryptor/decryptor
	if k.wrappedBlob != nil {
		// UnWrap the blob for usage as our JWEEncrptor and JWEDecryptor
		var clearkey []byte
		if clearkey, _, err = gose.NewJweDirectDecryptorImpl([]gose.AuthenticatedEncryptionKey{aek}).Decrypt(string(k.wrappedBlob)); err != nil {
			return
		}
		var jwk jose.Jwk
		if jwk, err = gose.LoadJwk(bytes.NewReader(clearkey), []jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt}); err != nil {
			return
		}

		if aek, err = gose.NewAesGcmCryptorFromJwk(jwk, []jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt}); err != nil {
			return
		}
	}
	p.jwee = gose.NewJweDirectEncryptorImpl(aek)
	p.jwed = gose.NewJweDirectDecryptorImpl([]gose.AuthenticatedEncryptionKey{aek})

	return
}

func (p *pkcs11AEAD) Encrypt(plaintext, additionalData []byte) (cipherText []byte, err error) {
	var cipherString string
	if cipherString, err = p.jwee.Encrypt(plaintext, additionalData); err != nil {
		return
	}
	cipherText = []byte(cipherString)
	return
}

func (p *pkcs11AEAD) Decrypt(ciphertext, additionalData []byte) (clearText []byte, err error) {

	if clearText, additionalData, err = p.jwed.Decrypt(string(ciphertext)); err != nil {
		return
	}

	return
}
