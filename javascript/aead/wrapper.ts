/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as Registry from '../internal/registry';
import {AeadWrapper} from './aead_wrapper';

export function register() {
  Registry.registerPrimitiveWrapper(new AeadWrapper());
}
