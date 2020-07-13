import PublicKeySignWrapper from 'goog:tink.signature.PublicKeySignWrapper'; // from //third_party/tink/javascript/signature:wrappers

import * as Registry from '../internal/registry';

export function register() {
  Registry.registerPrimitiveWrapper(new PublicKeySignWrapper());
}
