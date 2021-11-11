/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import * as PrimitiveSet from '../internal/primitive_set';
import {PrimitiveWrapper} from '../internal/primitive_wrapper';
import * as Bytes from '../subtle/bytes';
import * as Validators from '../subtle/validators';

import {PublicKeySign} from './internal/public_key_sign';

/**
 * @final
 */
class WrappedPublicKeySign extends PublicKeySign {
  // The constructor should be @private, but it is not supported by Closure
  // (see https://github.com/google/closure-compiler/issues/2761).
  constructor(private readonly primitiveSet:
                  PrimitiveSet.PrimitiveSet<PublicKeySign>) {
    super();
  }

  static newPublicKeySign(
      primitiveSet: PrimitiveSet.PrimitiveSet<PublicKeySign>): PublicKeySign {
    if (!primitiveSet) {
      throw new SecurityException('Primitive set has to be non-null.');
    }
    if (!primitiveSet.getPrimary()) {
      throw new SecurityException('Primary has to be non-null.');
    }
    return new WrappedPublicKeySign(primitiveSet);
  }

  async sign(data: Uint8Array) {
    Validators.requireUint8Array(data);
    const primary = this.primitiveSet.getPrimary();
    if (!primary) {
      throw new SecurityException('Primary not set.');
    }
    const primitive = primary.getPrimitive();
    const signature = await primitive.sign(data);
    const keyId = primary.getIdentifier();
    return Bytes.concat(keyId, signature);
  }
}

export class PublicKeySignWrapper implements PrimitiveWrapper<PublicKeySign> {
  /**
   */
  wrap(primitiveSet: PrimitiveSet.PrimitiveSet<PublicKeySign>) {
    return WrappedPublicKeySign.newPublicKeySign(primitiveSet);
  }

  /**
   */
  getPrimitiveType() {
    return PublicKeySign;
  }
}
