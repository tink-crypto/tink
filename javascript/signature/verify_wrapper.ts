import Registry from 'goog:tink.Registry'; // from //third_party/tink/javascript:registry_legacy
import PublicKeyVerifyWrapper from 'goog:tink.signature.PublicKeyVerifyWrapper'; // from //third_party/tink/javascript/signature:wrappers

export function register() {
  Registry.registerPrimitiveWrapper(new PublicKeyVerifyWrapper());
}
