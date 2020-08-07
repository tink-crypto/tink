/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

goog.module('tink.hybrid.EciesAeadHkdfUtil');

const EllipticCurves = goog.require('google3.third_party.tink.javascript.subtle.elliptic_curves');
const Util = goog.require('google3.third_party.tink.javascript.internal.util');
const {PbEciesAeadHkdfPrivateKey, PbEciesAeadHkdfPublicKey} = goog.require('google3.third_party.tink.javascript.internal.proto');

// This file contains only functions which are useful for implementation of
// private and public ECIES AEAD HKDF key manager.

/**
 * WARNING: This method assumes that the given key proto is valid.
 *
 * @package
 * @param {!PbEciesAeadHkdfPrivateKey|!PbEciesAeadHkdfPublicKey} key
 * @return {!webCrypto.JsonWebKey}
 */
const getJsonWebKeyFromProto = function(key) {
  let /** @type {!PbEciesAeadHkdfPublicKey} */ publicKey;
  let /** @type {!Uint8Array} */ d;
  if (key instanceof PbEciesAeadHkdfPrivateKey) {
    publicKey = /** @type{!PbEciesAeadHkdfPublicKey} */ (key.getPublicKey());
  } else {
    publicKey = key;
  }

  const curveType = Util.curveTypeProtoToSubtle(
      publicKey.getParams().getKemParams().getCurveType());
  const expectedLength = EllipticCurves.fieldSizeInBytes(curveType);
  let x = Util.bigEndianNumberToCorrectLength(
      publicKey.getX_asU8(), expectedLength);
  let y = Util.bigEndianNumberToCorrectLength(
      publicKey.getY_asU8(), expectedLength);
  if (key instanceof PbEciesAeadHkdfPrivateKey) {
    d = Util.bigEndianNumberToCorrectLength(
        key.getKeyValue_asU8(), expectedLength);
  }
  return EllipticCurves.getJsonWebKey(curveType, x, y, d);
};

exports = {
  getJsonWebKeyFromProto,
};
