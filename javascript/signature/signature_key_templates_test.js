// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

goog.module('tink.signature.SignatureKeyTemplatesTest');
goog.setTestOnly('tink.signature.SignatureKeyTemplatesTest');

const EcdsaPrivateKeyManager = goog.require('tink.signature.EcdsaPrivateKeyManager');
const PbEcdsaKeyFormat = goog.require('proto.google.crypto.tink.EcdsaKeyFormat');
const PbEcdsaSignatureEncoding = goog.require('proto.google.crypto.tink.EcdsaSignatureEncoding');
const PbEllipticCurveType = goog.require('proto.google.crypto.tink.EllipticCurveType');
const PbHashType = goog.require('proto.google.crypto.tink.HashType');
const PbOutputPrefixType = goog.require('proto.google.crypto.tink.OutputPrefixType');
const SignatureKeyTemplates = goog.require('tink.signature.SignatureKeyTemplates');

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
        PbEcdsaKeyFormat.deserializeBinary(keyTemplate.getValue());
    const params = keyFormat.getParams();
    expect(params.getEncoding()).toBe(expectedEncoding);

    // Test key params.
    expect(params.getCurve()).toBe(expectedCurve);
    expect(params.getHashType()).toBe(expectedHashFunction);

    // Test that the template works with EcdsaPrivateKeyManager.
    manager.getKeyFactory().newKey(keyTemplate.getValue_asU8());
  });
});
