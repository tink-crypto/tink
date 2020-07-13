import PublicKeyVerifyWrapper from 'goog:tink.signature.PublicKeyVerifyWrapper'; // from //third_party/tink/javascript/signature:wrappers

import * as Registry from '../internal/registry';

export function register() {
  Registry.registerPrimitiveWrapper(new PublicKeyVerifyWrapper());
}
