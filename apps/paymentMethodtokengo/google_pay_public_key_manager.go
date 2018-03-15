package paymentmethodtokengo

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

const KEYS_URL_PRODUCTION = "https://payments.developers.google.com/paymentmethodtoken/keys.json"
const KEYS_URL_TEST = "https://payments.developers.google.com/paymentmethodtoken/test/keys.json"

type KeysResponse struct {
	Keys []Key `json:"keys"`
}

type Key struct {
	KeyValue        string `json:"keyValue"`
	ProtocolVersion string `json:"protocolVersion"`
}

//GooglePaymentsPublicKeyManager regularly rotates public keys
//	for ecdsa verification, so this both stores and refreshes signingKeys
type GooglePaymentsPublicKeyManager struct {
	KeysUrl     string
	CurrentKeys KeysResponse
}

func (g *GooglePaymentsPublicKeyManager) RefreshSigningKeys() error {
	resp, _ := http.Get(g.KeysUrl)
	defer resp.Body.Close()
	respBody, _ := ioutil.ReadAll(resp.Body)
	return json.Unmarshal(respBody, g.CurrentKeys)
}
