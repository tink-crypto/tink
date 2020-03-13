package ekms

import (
	"bytes"
	"github.com/ThalesIgnite/gose"
	"github.com/ThalesIgnite/gose/jose"
	"reflect"
	"testing"
)

const ()

var (
	testGenerator       *gose.AuthenticatedEncryptionKeyGenerator
	testAEAD            gose.AuthenticatedEncryptionKey
	testJWK             jose.Jwk
	testEKMSAEAD        *ekmsAEAD
	testKnownJWKCleared = []byte(`{"key_ops":["decrypt","encrypt"],"alg":"A256GCM","kid":"59b4730b6fa839cda4e75568eb9954090efebb64200e184cf971f05ee4b4511e","k":"EJGF7UyFUUcAqeXDKGz8ya8wsOnKTaJOa_JJ5qM6O00","kty":"oct"}`)
	testKnownJWKWrapped = []byte("eyJhbGciOiJkaXIiLCJraWQiOiI1MDNmNjZmNzU0ZDQ0YzBjYWIzYmIwMjVmZDgyMjliNzY5NmNjMWY5OWE2MDM3ZmI5ZWJiNTZjNmM4ZDNkYmEzIiwiZW5jIjoiQTI1NkdDTSJ9..xm0gf8bcIwP4BH8z.vS5MSEu030KGsLDn9bCXoiBtBmRIlChvbg5Mdc_6mAQa5oAD3lfD21zBONLx41OUTyHBdKqMcGGhXURH_x3DU7GRRnFIPDTLdUTJI-SYpCGtsVxUo_nlBopO__OW4FCKEhI5iuZXf0NluX4fCBW5hEsm9-Aw1ou7Ssb6bR9c8pkid9i0PF-7P4HmUdtuAXOs2FMUzTWiw6rXYco2ICGmJnboDKEfp7EARSf_yOH_mk5fCHD1M1ThmQ.RVbNgJPl9lKXeqkox-G2DQ")
	testKeyURL          = "https://ekms.ekms.thalescpl.io/v0/ee26e849-9649-4d84-8b94-929d054f9248/7c63629d-b06b-441c-909a-35f20ab5435d"
	testPlainText       = []byte("Hello User")
	testCipherText      = []byte("eyJhbGciOiJkaXIiLCJraWQiOiI1MDNmNjZmNzU0ZDQ0YzBjYWIzYmIwMjVmZDgyMjliNzY5NmNjMWY5OWE2MDM3ZmI5ZWJiNTZjNmM4ZDNkYmEzIiwiZW5jIjoiQTI1NkdDTSJ9..kiX0f2J1Yb5GDc3L.Mq859A.Hgzq-ElCLnQvDHESc6e8OQ")
)

func setupAEADTests(t testing.TB) func(t testing.TB) {
	testGenerator = &gose.AuthenticatedEncryptionKeyGenerator{}
	var err error
	//if testAEAD, testJWK, err = testGenerator.Generate(jose.AlgA256GCM, []jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt}); err != nil {
	//	t.Fatal(err)
	//}

	if testJWK, err = gose.LoadJwk(bytes.NewReader(testKnownJWKCleared), []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt}); err != nil {
		t.Fatal(err)
	}

	if testAEAD, err = gose.NewAesGcmCryptorFromJwk(testJWK, []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt}); err != nil {
		t.Fatal(err)
	}
	//var u *url.URL
	//if u, err = url.Parse(testKeyURL); err != nil {
	//	t.Fatal(err)
	//}

	//ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	//defer cancel()
	//
	//options := []grpc.DialOption{grpc.WithDefaultCallOptions()}
	//options = append(options, grpc.WithInsecure())
	//var conn *grpc.ClientConn
	//if conn, err = grpc.DialContext(ctx, u.Host, options...); err != nil {
	//	t.Fatal(err)
	//}
	//testEKMSClient := google_cloud_ekms_v0.NewGCPExternalKeyManagementServiceClient(conn)
	//testEKMSAEAD = &ekmsAEAD{
	//	aead:        testAEAD,
	//	e:           gose.NewJweDirectEncryptorImpl(testAEAD),
	//	d:           gose.NewJweDirectDecryptorImpl([]gose.AuthenticatedEncryptionKey{testAEAD}),
	//	WrappedBlob: testKnownJWKWrapped,
	//	ClearBlob:   testKnownJWKCleared,
	//	c:           testEKMSClient,
	//}
	if testEKMSAEAD, err = newEkmsAEAD(testKeyURL, testKnownJWKWrapped); err != nil {
		t.Fatal(err)
	}
	return func(t testing.TB) {

	}
}

func Test_ekmsAEAD_Decrypt(t *testing.T) {
	teardown := setupAEADTests(t)
	defer teardown(t)
	type fields struct {
		aead        gose.AuthenticatedEncryptionKey
		e           gose.JweEncryptor
		d           gose.JweDecryptor
		wrappedBlob []byte
		clearBlob   []byte
	}
	type args struct {
		ciphertext     []byte
		additionalData []byte
	}
	tests := []struct {
		name          string
		fields        fields
		args          args
		wantPlaintext []byte
		wantErr       bool
	}{
		{
			name: "OK",
			fields: fields{
				aead:        testEKMSAEAD.aead,
				e:           testEKMSAEAD.e,
				d:           testEKMSAEAD.d,
				wrappedBlob: testEKMSAEAD.WrappedBlob,
				clearBlob:   testEKMSAEAD.ClearBlob,
			},
			args: args{
				ciphertext:     testCipherText,
				additionalData: nil,
			},
			wantPlaintext: testPlainText,
			wantErr:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := ekmsAEAD{
				aead:        tt.fields.aead,
				e:           tt.fields.e,
				d:           tt.fields.d,
				WrappedBlob: tt.fields.wrappedBlob,
				ClearBlob:   tt.fields.clearBlob,
			}
			gotPlaintext, err := e.Decrypt(tt.args.ciphertext, tt.args.additionalData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotPlaintext, tt.wantPlaintext) {
				t.Errorf("Decrypt() gotPlaintext = %v, want %v", gotPlaintext, tt.wantPlaintext)
			}
		})
	}
}

func Test_ekmsAEAD_Encrypt(t *testing.T) {
	teardown := setupAEADTests(t)
	defer teardown(t)
	type fields struct {
		aead        gose.AuthenticatedEncryptionKey
		e           gose.JweEncryptor
		d           gose.JweDecryptor
		wrappedBlob []byte
		clearBlob   []byte
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
			name: "OK",
			fields: fields{
				aead:        testEKMSAEAD.aead,
				e:           testEKMSAEAD.e,
				d:           testEKMSAEAD.d,
				wrappedBlob: testEKMSAEAD.WrappedBlob,
				clearBlob:   testEKMSAEAD.ClearBlob,
			},
			args: args{
				plaintext:      testPlainText,
				additionalData: nil,
			},
			wantCipherText: true,
			wantErr:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := ekmsAEAD{
				aead:        tt.fields.aead,
				e:           tt.fields.e,
				d:           tt.fields.d,
				WrappedBlob: tt.fields.wrappedBlob,
				ClearBlob:   tt.fields.clearBlob,
			}
			gotCipherText, err := e.Encrypt(tt.args.plaintext, tt.args.additionalData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (gotCipherText != nil) != tt.wantCipherText {
				t.Errorf("Encrypt() return = %v, gotCipherText %v", err, tt.wantErr)
				return
			}
		})
	}
}
