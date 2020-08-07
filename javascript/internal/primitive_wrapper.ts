/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as PrimitiveSet from './primitive_set';
import {Constructor} from './util';

/**
 * Basic interface for wrapping a primitive.
 *
 * A PrimitiveSet can be wrapped by a single primitive in order to fulfil a
 * cryptographic task. This is done by the PrimitiveWrapper. Whenever a new
 * primitive type is added to Tink, the user should define a new
 * PrimitiveWrapper and register it with the Registry.
 */
export interface PrimitiveWrapper<P> {
  /**
   * Wraps a PrimitiveSet and returns a single instance.
   *
   */
  wrap(primitiveSet: PrimitiveSet.PrimitiveSet<P>): P;

  /**
   * Returns the type of the managed primitive. Used for internal management.
   *
   */
  getPrimitiveType(): Constructor<P>;
}
