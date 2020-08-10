/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {SecurityException} from '../exception/security_exception';
import {PbEciesAeadHkdfPrivateKey, PbEciesAeadHkdfPublicKey} from '../internal/proto';
import * as Util from '../internal/util';
import * as EllipticCurves from '../subtle/elliptic_curves';

// This file contains only functions which are useful for implementation of
// private and public ECIES AEAD HKDF key manager.

/**
 * WARNING: This method assumes that the given key proto is valid.
 *
 */
export function getJsonWebKeyFromProto(key: PbEciesAeadHkdfPrivateKey|
                                       PbEciesAeadHkdfPublicKey): JsonWebKey {
  let publicKey: PbEciesAeadHkdfPublicKey;
  let d: Uint8Array|null = null;
  if (key instanceof PbEciesAeadHkdfPrivateKey) {
    publicKey = (key.getPublicKey() as PbEciesAeadHkdfPublicKey);
  } else {
    publicKey = key;
  }
  const params = publicKey.getParams();
  if (!params) {
    throw new SecurityException('Params not set');
  }
  const kemParams = params.getKemParams();
  if (!kemParams) {
    throw new SecurityException('KEM params not set');
  }
  const curveType = Util.curveTypeProtoToSubtle(kemParams.getCurveType());
  const expectedLength = EllipticCurves.fieldSizeInBytes(curveType);
  const x = Util.bigEndianNumberToCorrectLength(
      publicKey.getX_asU8(), expectedLength);
  const y = Util.bigEndianNumberToCorrectLength(
      publicKey.getY_asU8(), expectedLength);
  if (key instanceof PbEciesAeadHkdfPrivateKey) {
    d = Util.bigEndianNumberToCorrectLength(
        key.getKeyValue_asU8(), expectedLength);
  }
  return EllipticCurves.getJsonWebKey(curveType, x, y, d);
}
