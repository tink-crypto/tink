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
package com.google.crypto.tink.jwt;

import static java.nio.charset.StandardCharsets.US_ASCII;

import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.proto.JwtRsaSsaPkcs1Algorithm;
import com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.Enums;
import com.google.crypto.tink.subtle.RsaSsaPkcs1VerifyJce;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

/**
 * This key manager produces new instances of {@code JwtRsaSsaPkcs11Verify}. It doesn't support key
 * generation.
 */
class JwtRsaSsaPkcs1VerifyKeyManager extends KeyTypeManager<JwtRsaSsaPkcs1PublicKey> {
  static final String getKeyAlgorithm(JwtRsaSsaPkcs1Algorithm algorithmProto)
      throws GeneralSecurityException {
    // Note: each algorithm defines not just the modulo size, but also the
    // hash length and salt length to use.
    // See https://www.rfc-editor.org/rfc/rfc7518.html#section-3.5
    switch (algorithmProto) {
      case RS256:
        return "RS256";
      case RS384:
        return "RS384";
      case RS512:
        return "RS512";
      default:
        throw new GeneralSecurityException("unknown algorithm " + algorithmProto.name());
    }
  }

  private static final RSAPublicKey createPublicKey(JwtRsaSsaPkcs1PublicKey keyProto)
      throws GeneralSecurityException {
    java.security.KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
    BigInteger modulus = new BigInteger(1, keyProto.getN().toByteArray());
    BigInteger exponent = new BigInteger(1, keyProto.getE().toByteArray());
    return (RSAPublicKey) kf.generatePublic(new RSAPublicKeySpec(modulus, exponent));
  }

  public JwtRsaSsaPkcs1VerifyKeyManager() {
    super(
        JwtRsaSsaPkcs1PublicKey.class,
        new KeyTypeManager.PrimitiveFactory<JwtPublicKeyVerify, JwtRsaSsaPkcs1PublicKey>(
            JwtPublicKeyVerify.class) {
          @Override
          public JwtPublicKeyVerify getPrimitive(JwtRsaSsaPkcs1PublicKey keyProto)
              throws GeneralSecurityException {
            final String algorithm = getKeyAlgorithm(keyProto.getAlgorithm());
            RSAPublicKey publickey = createPublicKey(keyProto);
            Enums.HashType hash = JwtSigUtil.hashForPkcs1Algorithm(algorithm);
            final RsaSsaPkcs1VerifyJce verifier = new RsaSsaPkcs1VerifyJce(publickey, hash);

            return new JwtPublicKeyVerify() {
              @Override
              public VerifiedJwt verify(String compact, JwtValidator validator)
                  throws GeneralSecurityException {
                JwtFormat.validateASCII(compact);
                String[] parts = compact.split("\\.", -1);
                if (parts.length != 3) {
                  throw new JwtInvalidException(
                      "only tokens in JWS compact serialization format are supported");
                }
                String unsignedCompact = parts[0] + "." + parts[1];
                byte[] expectedSignature = JwtFormat.decodeSignature(parts[2]);

                verifier.verify(expectedSignature, unsignedCompact.getBytes(US_ASCII));
                JwtFormat.validateHeader(algorithm, JwtFormat.decodeHeader(parts[0]));
                String payload = JwtFormat.decodePayload(parts[1]);
                RawJwt token = RawJwt.fromJsonPayload(payload);
                return validator.validate(token);
              }
            };
          }
        });
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PUBLIC;
  }

  @Override
  public JwtRsaSsaPkcs1PublicKey parseKey(ByteString byteString)
      throws InvalidProtocolBufferException {
    return JwtRsaSsaPkcs1PublicKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public void validateKey(JwtRsaSsaPkcs1PublicKey pubKey) throws GeneralSecurityException {
    Validators.validateVersion(pubKey.getVersion(), getVersion());
    Validators.validateRsaModulusSize(new BigInteger(1, pubKey.getN().toByteArray()).bitLength());
    Validators.validateRsaPublicExponent(new BigInteger(1, pubKey.getE().toByteArray()));
  }
}
