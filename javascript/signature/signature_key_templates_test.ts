/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {PbEcdsaKeyFormat, PbEcdsaSignatureEncoding, PbEllipticCurveType, PbHashType, PbOutputPrefixType} from '../internal/proto';

import {EcdsaPrivateKeyManager} from './ecdsa_private_key_manager';
import {SignatureKeyTemplates} from './signature_key_templates';

describe('signature key templates test', function() {
  it('ecdsa p256', function() {
    // Expects function to create a key with following parameters.
    const expectedCurve = PbEllipticCurveType.NIST_P256;
    const expectedHashFunction = PbHashType.SHA256;
    const expectedEncoding = PbEcdsaSignatureEncoding.DER;
    const expectedOutputPrefix = PbOutputPrefixType.TINK;

    // Expected type URL is the one supported by EcdsaPrivateKeyManager.
    const manager = new EcdsaPrivateKeyManager();
    const expectedTypeUrl = manager.getKeyType();

    const keyTemplate = SignatureKeyTemplates.ecdsaP256();

    expect(keyTemplate.getTypeUrl()).toBe(expectedTypeUrl);
    expect(keyTemplate.getOutputPrefixType()).toBe(expectedOutputPrefix);

    // Test values in key format.
    const keyFormat =
        PbEcdsaKeyFormat.deserializeBinary(keyTemplate.getValue_asU8());
    const params = keyFormat.getParams();
    expect(params!.getEncoding()).toBe(expectedEncoding);

    // Test key params.
    expect(params!.getCurve()).toBe(expectedCurve);
    expect(params!.getHashType()).toBe(expectedHashFunction);

    // Test that the template works with EcdsaPrivateKeyManager.
    manager.getKeyFactory().newKey(keyTemplate.getValue_asU8());
  });
});
