package pkcs11kms

import (
	"github.com/google/uuid"
	"net/url"
)

// Key used to map the location of the key in the HSM, and optionally provide it's protected wrapped key
type Key struct {
	id          uuid.UUID
	wrappedBlob []byte
}

// key URI for pkcs11 is pcks11://keyid pkcs11://keyid?blob=<jose.JWK.String()>

func parseKeyURI(keyURI string) (k *Key, err error) {
	k = &Key{}
	var u *url.URL
	if u, err = url.Parse(keyURI); err != nil {
		return
	}
	if k.id, err = uuid.Parse(u.Host); err != nil {
		return
	}

	if q := u.Query(); q != nil {
		if blob := q.Get("blob"); blob != "" {
			k.wrappedBlob = []byte(blob)

		}
	} else {

	}
	return
}
