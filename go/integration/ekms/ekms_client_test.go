package ekms

import (
	"github.com/google/tink/go/tink"
	"reflect"
	"testing"
)


func Test_ekmsClient_GetAEAD(t *testing.T) {
	type args struct {
		keyURI string
	}
	tests := []struct {
		name     string
		args     args
		wantAead tink.AEAD
		wantErr  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := ekmsClient{}
			gotAead, err := e.GetAEAD(tt.args.keyURI)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAEAD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotAead, tt.wantAead) {
				t.Errorf("GetAEAD() gotAead = %v, want %v", gotAead, tt.wantAead)
			}
		})
	}
}

func Test_ekmsClient_Supported(t *testing.T) {
	type args struct {
		keyURI string
	}
	tests := []struct {
		name          string
		args          args
		wantSupported bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := ekmsClient{}
			if gotSupported := e.Supported(tt.args.keyURI); gotSupported != tt.wantSupported {
				t.Errorf("Supported() = %v, want %v", gotSupported, tt.wantSupported)
			}
		})
	}
}

func Test_newEkmsClient(t *testing.T) {
	tests := []struct {
		name string
		want *ekmsClient
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewClient(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newEkmsClient() = %v, want %v", got, tt.want)
			}
		})
	}
}