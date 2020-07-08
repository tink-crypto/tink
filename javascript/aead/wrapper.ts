import AeadWrapper from 'goog:tink.aead.AeadWrapper'; // from //third_party/tink/javascript/aead:aead_wrapper
import * as Registry from '../internal/registry';

export function register() {
  Registry.registerPrimitiveWrapper(new AeadWrapper());
}
