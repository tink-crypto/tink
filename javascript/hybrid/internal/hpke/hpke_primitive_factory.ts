/**
 * @license
 * Copyright 2023 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {InvalidArgumentsException} from '../../../exception/invalid_arguments_exception';
import {PbHpkeAead, PbHpkeKdf, PbHpkeKem, PbHpkeParams} from '../../../internal/proto';
import * as ellipticCurves from '../../../subtle/elliptic_curves';

import {AesGcmHpkeAead} from './aes_gcm_hpke_aead';
import {HkdfHpkeKdf} from './hkdf_hpke_kdf';
import {HpkeAead} from './hpke_aead';
import {HpkeKdf} from './hpke_kdf';
import {HpkeKem} from './hpke_kem';
import * as hpkeUtil from './hpke_util';
import {NistCurvesHpkeKem} from './nist_curves_hpke_kem';


/**
 * Helper class for creating HPKE primitives from either algorithm identifiers
 * or HpkeParams.
 */
export class HpkePrimitiveFactory {
  private constructor() {}

  /** Returns an HpkeKem primitive corresponding to the kemId. */
  static createKemFromId(kemId: Uint8Array): HpkeKem {
    switch (kemId) {
      case hpkeUtil.P256_HKDF_SHA256_KEM_ID:
        return NistCurvesHpkeKem.fromCurve(ellipticCurves.CurveType.P256);
      case hpkeUtil.P521_HKDF_SHA512_KEM_ID:
        return NistCurvesHpkeKem.fromCurve(ellipticCurves.CurveType.P521);
      default:
        throw new InvalidArgumentsException('Unrecognized HPKE KEM identifier');
    }
  }

  /** Returns an HpkeKem primitive corresponding to the given parameters. */
  static createKemFromParams(params: PbHpkeParams): HpkeKem {
    switch (params.getKem()) {
      case PbHpkeKem.DHKEM_P256_HKDF_SHA256:
        return NistCurvesHpkeKem.fromCurve(ellipticCurves.CurveType.P256);
      case PbHpkeKem.DHKEM_P521_HKDF_SHA512:
        return NistCurvesHpkeKem.fromCurve(ellipticCurves.CurveType.P521);
      default:
        throw new InvalidArgumentsException('Unrecognized HPKE KEM identifier');
    }
  }

  /** Returns an HpkeKdf primitive corresponding to the kdfId. */
  static createKdfFromId(kdfId: Uint8Array): HpkeKdf {
    switch (kdfId) {
      case hpkeUtil.HKDF_SHA256_KDF_ID:
        return new HkdfHpkeKdf('SHA-256');
      case hpkeUtil.HKDF_SHA512_KDF_ID:
        return new HkdfHpkeKdf('SHA-512');
      default:
        throw new InvalidArgumentsException('Unrecognized HPKE KDF identifier');
    }
  }

  /** Returns an HpkeKdf primitive corresponding to the given parameters. */
  static createKdfFromParams(params: PbHpkeParams): HpkeKdf {
    switch (params.getKdf()) {
      case PbHpkeKdf.HKDF_SHA256:
        return new HkdfHpkeKdf('SHA-256');
      case PbHpkeKdf.HKDF_SHA512:
        return new HkdfHpkeKdf('SHA-512');
      default:
        throw new InvalidArgumentsException('Unrecognized HPKE KDF identifier');
    }
  }

  /** Returns an HpkeAead primitive corresponding to the aeadId. */
  static createAeadFromId(aeadId: Uint8Array): HpkeAead {
    switch (aeadId) {
      case hpkeUtil.AES_128_GCM_AEAD_ID:
        return new AesGcmHpkeAead(16);
      case hpkeUtil.AES_256_GCM_AEAD_ID:
        return new AesGcmHpkeAead(32);
      default:
        throw new InvalidArgumentsException(
            'Unrecognized HPKE AEAD identifier');
    }
  }

  /** Returns an HpkeAead primitive corresponding to the given parameters. */
  static createAeadFromParams(params: PbHpkeParams): HpkeAead {
    switch (params.getAead()) {
      case PbHpkeAead.AES_128_GCM:
        return new AesGcmHpkeAead(16);
      case PbHpkeAead.AES_256_GCM:
        return new AesGcmHpkeAead(32);
      default:
        throw new InvalidArgumentsException(
            'Unrecognized HPKE AEAD identifier');
    }
  }
}
