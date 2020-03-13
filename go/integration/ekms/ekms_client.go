package ekms

import (
	"github.com/google/tink/go/integration/ekms/google_cloud_ekms_v0"
	"github.com/google/tink/go/tink"
)

const (
	ekmsPrefix = "ekms://"
)

type ekmsClient struct {
	c google_cloud_ekms_v0.GCPExternalKeyManagementServiceClient
}

func NewClient() (client *ekmsClient) {
	client =  &ekmsClient{

	}


	return
}

func (e *ekmsClient) s ()(err error) {

	return
}

func (e *ekmsClient) Supported(keyURI string) (supported bool) {

	return
}

func (e *ekmsClient) GetAEAD(keyURI string) (aead tink.AEAD, err error) {
	aead = &ekmsAEAD{

	}

	return
}
