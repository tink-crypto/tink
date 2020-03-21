package pkcs11kms

import (
	"context"
	"reflect"
	"testing"

	"github.com/ThalesIgnite/crypto11"
)

func TestNewClient(t *testing.T) {
	teardown := setupTests(t)
	defer teardown(t)
	type args struct {
		ctx     context.Context
		cfg     *crypto11.Config
		autogen bool
	}
	tests := []struct {
		name string
		args args
		want *pkcs11Client
	}{
		{
			name: "OK",
			args: args{
				ctx:     testCtx,
				cfg:     testHSMConfig,
				autogen: false,
			},
			want: &pkcs11Client{
				ctx:     testCtx,
				cfg:     testHSMConfig,
				autogen: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewClient(tt.args.ctx, tt.args.cfg, tt.args.autogen); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewClient() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pkcs11Client_GetAEAD(t *testing.T) {
	teardown := setupTests(t)
	defer teardown(t)
	type fields struct {
		ctx     context.Context
		cfg     *crypto11.Config
		autogen bool
	}
	type args struct {
		keyURI string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantA   bool
		wantErr bool
	}{
		{
			name: "OK",
			fields: fields{
				ctx:     testCtx,
				cfg:     testHSMConfig,
				autogen: false,
			},
			args: args{
				keyURI: testHSMKeyURL,
			},
			wantA:   true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := pkcs11Client{
				ctx:     tt.fields.ctx,
				cfg:     tt.fields.cfg,
				autogen: tt.fields.autogen,
			}
			gotA, err := p.GetAEAD(tt.args.keyURI)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAEAD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (gotA != nil) != tt.wantA {
				t.Errorf("GetAEAD() gotA = %v, wantA %v", gotA, tt.wantA)
				return
			}
		})
	}
}

func Test_pkcs11Client_Supported(t *testing.T) {
	teardown := setupTests(t)
	defer teardown(t)
	type fields struct {
		ctx     context.Context
		cfg     *crypto11.Config
		autogen bool
	}
	type args struct {
		keyURI string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "OK",
			fields: fields{
				ctx:     testCtx,
				cfg:     testHSMConfig,
				autogen: false,
			},
			args: args{
				keyURI: testHSMKeyURL,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := pkcs11Client{
				ctx:     tt.fields.ctx,
				cfg:     tt.fields.cfg,
				autogen: tt.fields.autogen,
			}
			if got := p.Supported(tt.args.keyURI); got != tt.want {
				t.Errorf("Supported() = %v, want %v", got, tt.want)
			}
		})
	}
}
