/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as Registry from '../internal/registry';
import {HybridDecryptWrapper} from './hybrid_decrypt_wrapper';

export function register() {
  Registry.registerPrimitiveWrapper(new HybridDecryptWrapper());
}
