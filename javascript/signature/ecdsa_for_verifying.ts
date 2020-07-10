import Registry from 'goog:tink.Registry'; // from //third_party/tink/javascript:registry_legacy
import EcdsaPublicKeyManager from 'goog:tink.signature.EcdsaPublicKeyManager'; // from //third_party/tink/javascript/signature:ecdsa_key_managers

export function register() {
  Registry.registerKeyManager(new EcdsaPublicKeyManager());
}
