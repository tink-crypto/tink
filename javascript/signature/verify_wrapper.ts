/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import PublicKeyVerifyWrapper from 'goog:tink.signature.PublicKeyVerifyWrapper'; // from //third_party/tink/javascript/signature:wrappers

import * as Registry from '../internal/registry';

export function register() {
  Registry.registerPrimitiveWrapper(new PublicKeyVerifyWrapper());
}
