package pkcs11kms

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/ThalesIgnite/crypto11"
	"github.com/ThalesIgnite/gose"
)

func Test_newPcks11AEAD(t *testing.T) {
	teardown := setupTests(t)
	defer teardown(t)
	type args struct {
		ctx     *crypto11.Context
		keyURI  string
		autogen bool
	}
	tests := []struct {
		name    string
		args    args
		wantP   bool
		wantErr bool
	}{
		{
			name: "OK",
			args: args{
				ctx:     testHSMCtx,
				keyURI:  testHSMKeyURL,
				autogen: false,
			},
			wantP:   true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotP, err := newPkcs11AEAD(tt.args.ctx, tt.args.keyURI, tt.args.autogen)
			if (err != nil) != tt.wantErr {
				t.Errorf("newPcks11AEAD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (gotP != nil) != tt.wantP {
				t.Errorf("newPcks11AEAD() gotP = %v, wantP %v", (gotP != nil), tt.wantP)
				return
			}
		})
	}
}

func Test_pcks11AEAD_Decrypt(t *testing.T) {
	teardown := setupTests(t)
	defer teardown(t)
	type fields struct {
		ctx  *crypto11.Context
		jwee gose.JweEncryptor
		jwed gose.JweDecryptor
	}
	type args struct {
		ciphertext     []byte
		additionalData []byte
	}
	tests := []struct {
		name          string
		fields        fields
		args          args
		wantClearText []byte
		wantErr       bool
	}{
		{
			name: "OK - HSM AEAD",
			fields: fields{
				ctx:  testHSMAEAD.ctx,
				jwee: testHSMAEAD.jwee,
				jwed: testHSMAEAD.jwed,
			},
			args: args{
				ciphertext:     testHSMCipherText,
				additionalData: nil,
			},
			wantClearText: testClearText,
			wantErr:       false,
		}, {
			name: "OK - Wrapped AEAD",
			fields: fields{
				ctx:  testWrappedAEAD.ctx,
				jwee: testWrappedAEAD.jwee,
				jwed: testWrappedAEAD.jwed,
			},
			args: args{
				ciphertext:     testWrappedCipherText,
				additionalData: nil,
			},
			wantClearText: testClearText,
			wantErr:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &pkcs11AEAD{
				ctx:  tt.fields.ctx,
				jwee: tt.fields.jwee,
				jwed: tt.fields.jwed,
			}
			gotClearText, err := p.Decrypt(tt.args.ciphertext, tt.args.additionalData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotClearText, tt.wantClearText) {
				t.Errorf("Decrypt() gotClearText = %v, want %v", gotClearText, tt.wantClearText)
			}
		})
	}
}

func Test_pcks11AEAD_Encrypt(t *testing.T) {
	teardown := setupTests(t)
	defer teardown(t)
	type fields struct {
		ctx  *crypto11.Context
		jwee gose.JweEncryptor
		jwed gose.JweDecryptor
	}
	type args struct {
		plaintext      []byte
		additionalData []byte
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		wantCipherText bool
		wantErr        bool
	}{
		{
			name: "OK - HSM AEAD",
			fields: fields{
				ctx:  testHSMAEAD.ctx,
				jwee: testHSMAEAD.jwee,
				jwed: testHSMAEAD.jwed,
			},
			args: args{
				plaintext:      testClearText,
				additionalData: nil,
			},
			wantCipherText: true,
			wantErr:        false,
		}, {
			name: "OK - wraooed AEAD",
			fields: fields{
				ctx:  testWrappedAEAD.ctx,
				jwee: testWrappedAEAD.jwee,
				jwed: testWrappedAEAD.jwed,
			},
			args: args{
				plaintext:      testClearText,
				additionalData: nil,
			},
			wantCipherText: true,
			wantErr:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &pkcs11AEAD{
				ctx:  tt.fields.ctx,
				jwee: tt.fields.jwee,
				jwed: tt.fields.jwed,
			}
			gotCipherText, err := p.Encrypt(tt.args.plaintext, tt.args.additionalData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			fmt.Println(string(gotCipherText))
			if (gotCipherText != nil) != tt.wantCipherText {
				t.Errorf("Encrypt() gotCipherText = %v, wantCipherText %v", gotCipherText, tt.wantCipherText)
				return
			}
		})
	}
}

func BenchmarkPkcs11AEAD_HSM_Encrypt(b *testing.B) {
	teardown := setupTests(b)
	defer teardown(b)
	for i := 0; i < b.N; i++ {
		if _, err := testHSMAEAD.Encrypt(testClearText, nil); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkPkcs11AEAD_HSM_Decrypt(b *testing.B) {
	teardown := setupTests(b)
	defer teardown(b)

	for i := 0; i < b.N; i++ {
		if _, err := testHSMAEAD.Decrypt(testHSMCipherText, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPkcs11AEAD_Wrapped_Encrypt(b *testing.B) {
	teardown := setupTests(b)
	defer teardown(b)
	for i := 0; i < b.N; i++ {
		if _, err := testWrappedAEAD.Encrypt(testClearText, nil); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkPkcs11AEAD_Wrapped_Decrypt(b *testing.B) {
	teardown := setupTests(b)
	defer teardown(b)

	for i := 0; i < b.N; i++ {
		if _, err := testWrappedAEAD.Decrypt(testWrappedCipherText, nil); err != nil {
			b.Fatal(err)
		}
	}
}
