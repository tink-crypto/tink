/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {InvalidArgumentsException} from '../../../exception/invalid_arguments_exception';
import {PbHpkeKem, PbHpkePrivateKey} from '../../../internal/proto';
import {bytesAsU8} from '../../../internal/proto_shims';

import {HpkeKemPrivateKey} from './hpke_kem_private_key';
import * as hpkeUtil from './hpke_util';
import * as nistCurvesHpkeKemPrivateKey from './nist_curves_hpke_kem_private_key';

/** Helper class for creating HPKE KEM asymmetric keys. */
export class HpkeKemKeyFactory {
  private constructor() {}

  static createPrivate(privateKey: PbHpkePrivateKey):
      Promise<HpkeKemPrivateKey> {
    const publicKey = privateKey.getPublicKey();
    if (!publicKey) {
      throw new InvalidArgumentsException('Public key not set');
    }
    const params = publicKey.getParams();
    if (!params) {
      throw new InvalidArgumentsException('Params not set');
    }
    switch (params.getKem()) {
      case PbHpkeKem.DHKEM_P256_HKDF_SHA256:
      case PbHpkeKem.DHKEM_P521_HKDF_SHA512:
        return nistCurvesHpkeKemPrivateKey.fromBytes({
          privateKey: bytesAsU8(privateKey.getPrivateKey()),
          publicKey: bytesAsU8(publicKey.getPublicKey()),
          curveType: hpkeUtil.nistHpkeKemToCurve(params.getKem())
        });
      default:
        throw new InvalidArgumentsException('Unrecognized HPKE KEM identifier');
    }
  }
}
