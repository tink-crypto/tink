/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import EcdsaPublicKeyManager from 'goog:tink.signature.EcdsaPublicKeyManager'; // from //third_party/tink/javascript/signature:ecdsa_key_managers

import * as Registry from '../internal/registry';

export function register() {
  Registry.registerKeyManager(new EcdsaPublicKeyManager());
}
