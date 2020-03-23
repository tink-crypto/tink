package pkcs11kms

import (
	"context"
	"fmt"
	"github.com/google/tink/go/tink"
	"github.com/google/uuid"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"github.com/ThalesIgnite/crypto11"
)

var (
	testCtx context.Context

	// SoftHSM setup
	testHSMConfigured bool
	testHSMConfig     *crypto11.Config
	testHSMCtx        *crypto11.Context
	testHSMClient     *pkcs11Client
	testHSMAEAD       *pkcs11AEAD
	testWrappedAEAD   *pkcs11AEAD

	testKeyID = uuid.Must(uuid.Parse("ee2c5de3-335c-428b-8168-5daf299e97f3"))

	// Use this JWK as the test "Wrapping" Key to make sure it can be wrapped up and unwrapped by the Device
	knownJWKClear     = `{"key_ops":["decrypt","encrypt"],"alg":"A256GCM","kid":"6b8bf21153f86574c5da942fc0a5634965d1787279662cd849296ec37988909a","k":"WmID-SANWBiq_gEy82dNx7DvctF27ZFQHcjvtrxlwDw","kty":"oct"}`
	knownJWKEncrypted = `eyJhbGciOiJkaXIiLCJraWQiOiJlZTJjNWRlMy0zMzVjLTQyOGItODE2OC01ZGFmMjk5ZTk3ZjMiLCJlbmMiOiJBMjU2R0NNIn0..gdC9cTZntv9QFEsk.EyiZKw3NkPzMIXtyRY7eS_kpMC6pE0VJvbiPA0-epqMq28L-bhxgut1O_smeZ_udVUBr3lYHd2Lrd2Vdv5UXZ3snnE_wx0HZuiTWOn87Jxb8kR9Bz8jcKKaWsIjEZflRGKCpKaZmq4A2VFrG6UI1c5SCXQDBaRteou_SAnwX_k7QkcQZLgprYrPsKXOeB7gJByq7_kpp28EiZVvhOU-m2UEGnB0nBdwhu5Z64l7CAvU5i7Y6V8Kdlw.wO_EE-PVNO36iof68_sZxw`

	// URL to device key
	testHSMKeyURL = "pkcs11://ee2c5de3-335c-428b-8168-5daf299e97f3"
	// URL + WrappedJWK from the device key
	testWrappedKeyURL = fmt.Sprintf("pkcs11://ee2c5de3-335c-428b-8168-5daf299e97f3?blob=%s", knownJWKEncrypted)

	testClearText         []byte
	testHSMCipherText     []byte
	testWrappedCipherText []byte
)

func setupTests(t testing.TB) func(t testing.TB) {

	testCtx = context.Background()
	var err error

	if os.Getenv("SOFTHSM_LIBRARY") != "" {
		testHSMConfigured = true
	}

	if testHSMConfigured {

		// Allow the MasterKey to be created if missing to be created
		testHSMConfig = &crypto11.Config{
			Path:       os.Getenv("SOFTHSM_LIBRARY"),
			TokenLabel: os.Getenv("SOFTHSM_TOKEN"),
			Pin:        os.Getenv("SOFTHSM_PIN"),
		}

		if testHSMCtx, err = crypto11.Configure(testHSMConfig); err != nil {
			t.Fatal(err)
		}

	} else {
		t.Skip("SOFTHSM not configured... check environment variables... SOFTHSM_LIBRARY, SOFTHSM_TOKEN, SOFTHSM_PIN")
	}

	// Load the test files
	if testClearText, err = ioutil.ReadFile("./testdata/secret-clear.txt"); err != nil {
		t.Fatal(err)
	}

	if testHSMCipherText, err = ioutil.ReadFile("./testdata/secret-hsm-cipher.txt"); err != nil {
		t.Fatal(err)
	}
	if testWrappedCipherText, err = ioutil.ReadFile("./testdata/secret-wrapped-cipher.txt"); err != nil {
		t.Fatal(err)
	}
	// Load the Client

	testHSMClient = NewClient(testCtx, testHSMConfig, false)
	var aead1 tink.AEAD
	if aead1, err = testHSMClient.GetAEAD(testHSMKeyURL); err != nil {
		t.Fatal(err)
	}
	testHSMAEAD = aead1.(*pkcs11AEAD)

	var aead2 tink.AEAD
	if aead2, err = testHSMClient.GetAEAD(testWrappedKeyURL); err != nil {
		t.Fatal(err)
	}
	testWrappedAEAD = aead2.(*pkcs11AEAD)

	return func(t testing.TB) {

	}
}

func Test_parseKeyURI(t *testing.T) {
	teardown := setupTests(t)
	defer teardown(t)
	type args struct {
		keyURI string
	}
	tests := []struct {
		name    string
		args    args
		wantK   *Key
		wantErr bool
	}{
		{
			name: "OK",
			args: args{
				testHSMKeyURL,
			},
			wantK: &Key{
				id: testKeyID,
			},
			wantErr: false,
		}, {
			name: "Wrapped",
			args: args{
				testWrappedKeyURL,
			},
			wantK: &Key{
				id:          testKeyID,
				wrappedBlob: []byte(knownJWKEncrypted),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotK, err := parseKeyURI(tt.args.keyURI)
			if (err != nil) != tt.wantErr {

				t.Errorf("parseKeyURI() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(gotK, tt.wantK) {
				t.Errorf("parseKeyURI() gotK = %v, want %v", gotK, tt.wantK)
			}
		})
	}
}
