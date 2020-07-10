import EciesAeadHkdfPublicKeyManager from 'goog:tink.hybrid.EciesAeadHkdfPublicKeyManager'; // from //third_party/tink/javascript/hybrid:ecies_aead_hkdf_key_managers
import Registry from 'goog:tink.Registry'; // from //third_party/tink/javascript:registry_legacy

export function register() {
  Registry.registerKeyManager(new EciesAeadHkdfPublicKeyManager());
}
