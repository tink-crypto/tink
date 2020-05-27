import EcdsaSign from 'goog:tink.subtle.EcdsaSign'; // from //third_party/tink/javascript/subtle:signature
export {EcdsaSign};
export const ecdsaSignFromJsonWebKey = EcdsaSign.fromJsonWebKey;
export {EcdsaSignatureEncodingType, exportCryptoKey, generateKeyPair, importPrivateKey, importPublicKey} from 'goog:tink.subtle.EllipticCurves';  // from //third_party/tink/javascript/subtle
