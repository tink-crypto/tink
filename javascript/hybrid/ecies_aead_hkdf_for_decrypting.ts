import EciesAeadHkdfPrivateKeyManager from 'goog:tink.hybrid.EciesAeadHkdfPrivateKeyManager'; // from //third_party/tink/javascript/hybrid:ecies_aead_hkdf_key_managers
import * as Registry from '../internal/registry';

export function register() {
  Registry.registerKeyManager(new EciesAeadHkdfPrivateKeyManager());
}
