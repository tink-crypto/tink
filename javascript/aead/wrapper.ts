import AeadWrapper from 'goog:tink.aead.AeadWrapper'; // from //third_party/tink/javascript/aead:aead_wrapper
import Registry from 'goog:tink.Registry'; // from //third_party/tink/javascript:registry_legacy

export function register() {
  Registry.registerPrimitiveWrapper(new AeadWrapper());
}
