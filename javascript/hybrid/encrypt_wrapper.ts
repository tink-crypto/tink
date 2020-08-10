/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as Registry from '../internal/registry';
import {HybridEncryptWrapper} from './hybrid_encrypt_wrapper';

export function register() {
  Registry.registerPrimitiveWrapper(new HybridEncryptWrapper());
}
