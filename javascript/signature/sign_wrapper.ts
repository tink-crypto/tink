import Registry from 'goog:tink.Registry'; // from //third_party/tink/javascript:registry_legacy
import PublicKeySignWrapper from 'goog:tink.signature.PublicKeySignWrapper'; // from //third_party/tink/javascript/signature:wrappers

export function register() {
  Registry.registerPrimitiveWrapper(new PublicKeySignWrapper());
}
