package pkcs11kms

import (
	"context"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/tink"
	"strings"

	"github.com/ThalesIgnite/crypto11"
)

const (
	prefix = "pkcs11://"
)

type pkcs11Client struct {
	ctx     context.Context
	cfg     *crypto11.Config
	autogen bool
}

var _ registry.KMSClient = (*pkcs11Client)(nil)

func NewClient(ctx context.Context, cfg *crypto11.Config, autogen bool) *pkcs11Client {
	return &pkcs11Client{
		ctx:     ctx,
		cfg:     cfg,
		autogen: autogen,
	}

}

func (p pkcs11Client) Supported(keyURI string) bool {
	return strings.HasPrefix(keyURI, prefix)
}

func (p pkcs11Client) GetAEAD(keyURI string) (a tink.AEAD, err error) {

	// let's go direct first... we'll do cached later
	var ctx11 *crypto11.Context
	if ctx11, err = crypto11.Configure(p.cfg); err != nil {
		return
	}

	return newPkcs11AEAD(ctx11, keyURI, p.autogen)

}
