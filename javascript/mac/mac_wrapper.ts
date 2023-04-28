/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import {CryptoFormat} from '../internal/crypto_format';
import * as PrimitiveSet from '../internal/primitive_set';
import {PrimitiveWrapper} from '../internal/primitive_wrapper';
import {PbKeyStatusType, PbOutputPrefixType} from '../internal/proto';
import * as registry from '../internal/registry';
import {Constructor} from '../internal/util';
import * as bytes from '../subtle/bytes';

import {Mac} from './internal/mac';

/**
 * @final
 */
class WrappedMac extends Mac {
  // The constructor should be @private, but it is not supported by Closure
  // (see https://github.com/google/closure-compiler/issues/2761).
  constructor(private readonly macSet: PrimitiveSet.PrimitiveSet<Mac>) {
    super();
  }

  static newMac(macSet: PrimitiveSet.PrimitiveSet<Mac>): Mac {
    if (!macSet) {
      throw new SecurityException('Primitive set has to be non-null.');
    }
    if (!macSet.getPrimary()) {
      throw new SecurityException('Primary has to be non-null.');
    }
    return new WrappedMac(macSet);
  }

  async computeMac(data: Uint8Array): Promise<Uint8Array> {
    const primary = this.macSet.getPrimary();
    if (!primary) {
      throw new SecurityException('Primary has to be non-null.');
    }
    /**
     * Add a \x00 byte to the end of the data being MACed when operating on
     * keys with LEGACY OutputPrefixType.
     */
    let data2 = data;
    if (primary.getOutputPrefixType() === PbOutputPrefixType.LEGACY) {
      data2 = bytes.concat(data, new Uint8Array([0]));
    }

    const primitive = primary.getPrimitive();
    const tag = await primitive.computeMac(data2);
    const keyId = primary.getIdentifier();

    return bytes.concat(keyId, tag);
  }

  async verifyMac(tag: Uint8Array, data: Uint8Array): Promise<boolean> {
    if (tag.length > CryptoFormat.NON_RAW_PREFIX_SIZE) {
      const keyId = tag.subarray(0, CryptoFormat.NON_RAW_PREFIX_SIZE);
      const entries = this.macSet.getPrimitives(keyId);
      const rawTag = tag.subarray(CryptoFormat.NON_RAW_PREFIX_SIZE, tag.length);
      let isValid = false;
      try {
        isValid = await this.tryVerification(entries, rawTag, data);
      } catch (e) {
      }
      if (isValid) {
        return isValid;
      }
    }
    const entries = this.macSet.getRawPrimitives();
    const isValid = await this.tryVerification(entries, tag, data);
    return isValid;
  }

  /**
   * Tries to verify the tag using each entry in primitives. It
   * returns false if no entry succeeds.
   */
  private async tryVerification(
      primitives: Array<PrimitiveSet.Entry<Mac>>, tag: Uint8Array,
      data: Uint8Array): Promise<boolean> {
    const primitivesLength = primitives.length;
    for (let i = 0; i < primitivesLength; i++) {
      if (primitives[i].getKeyStatus() !== PbKeyStatusType.ENABLED) {
        continue;
      }
      const primitive = primitives[i].getPrimitive();
      let isValid: boolean;
      try {
        isValid = await primitive.verifyMac(tag, data);
      } catch (e) {
        continue;
      }
      if (isValid) {
        return isValid;
      }
    }
    return false;
  }
}

/**
 * MacWrapper is the implementation of PrimitiveWrapper for the Mac primitive.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To
 * compute a MAC tag, it uses the primary key in the keyset. For non-raw prefix
 * types, the tag is prepended with a certain prefix associated with the
 * primary key. To verify a tag, the primitive uses the prefix of the tag to
 * efficiently select the right key in the set. If the keys associated with the
 * prefix do not validate the tag, the primitive tries all keys with {@link
 * com.google.crypto.tink.proto.OutputPrefixType#RAW}.
 */
export class MacWrapper implements PrimitiveWrapper<Mac> {
  wrap(primitiveSet: PrimitiveSet.PrimitiveSet<Mac>): Mac {
    return WrappedMac.newMac(primitiveSet);
  }

  getPrimitiveType(): Constructor<Mac> {
    return Mac;
  }

  static register() {
    registry.registerPrimitiveWrapper(new MacWrapper());
  }
}
