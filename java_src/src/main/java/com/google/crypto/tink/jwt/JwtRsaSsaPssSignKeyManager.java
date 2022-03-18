// Copyright 2020 Google LLC
//
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

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.PrivateKeyTypeManager;
import com.google.crypto.tink.proto.JwtRsaSsaPssAlgorithm;
import com.google.crypto.tink.proto.JwtRsaSsaPssKeyFormat;
import com.google.crypto.tink.proto.JwtRsaSsaPssPrivateKey;
import com.google.crypto.tink.proto.JwtRsaSsaPssPublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.Enums;
import com.google.crypto.tink.subtle.RsaSsaPssSignJce;
import com.google.crypto.tink.subtle.SelfKeyTestValidators;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * This key manager generates new {@code JwtRsaSsaPssPrivateKey} keys and produces new instances of
 * {@code JwtPublicKeySign}.
 */
public final class JwtRsaSsaPssSignKeyManager
    extends PrivateKeyTypeManager<JwtRsaSsaPssPrivateKey, JwtRsaSsaPssPublicKey> {

  private static final void selfTestKey(
      RSAPrivateCrtKey privateKey, JwtRsaSsaPssPrivateKey keyProto)
      throws GeneralSecurityException {
    java.security.KeyFactory factory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPublicKey publicKey =
        (RSAPublicKey)
            factory.generatePublic(
                new RSAPublicKeySpec(
                    new BigInteger(1, keyProto.getPublicKey().getN().toByteArray()),
                    new BigInteger(1, keyProto.getPublicKey().getE().toByteArray())));
    // Sign and verify a test message to make sure that the key is correct.
    JwtRsaSsaPssAlgorithm algorithm = keyProto.getPublicKey().getAlgorithm();
    Enums.HashType hash = JwtRsaSsaPssVerifyKeyManager.hashForPssAlgorithm(algorithm);
    int saltLength = JwtRsaSsaPssVerifyKeyManager.saltLengthForPssAlgorithm(algorithm);
    SelfKeyTestValidators.validateRsaSsaPss(privateKey, publicKey, hash, hash, saltLength);
  }

  private static final RSAPrivateCrtKey createPrivateKey(JwtRsaSsaPssPrivateKey keyProto)
      throws GeneralSecurityException {
    java.security.KeyFactory factory = EngineFactory.KEY_FACTORY.getInstance("RSA");
    return (RSAPrivateCrtKey)
        factory.generatePrivate(
            new RSAPrivateCrtKeySpec(
                new BigInteger(1, keyProto.getPublicKey().getN().toByteArray()),
                new BigInteger(1, keyProto.getPublicKey().getE().toByteArray()),
                new BigInteger(1, keyProto.getD().toByteArray()),
                new BigInteger(1, keyProto.getP().toByteArray()),
                new BigInteger(1, keyProto.getQ().toByteArray()),
                new BigInteger(1, keyProto.getDp().toByteArray()),
                new BigInteger(1, keyProto.getDq().toByteArray()),
                new BigInteger(1, keyProto.getCrt().toByteArray())));
  }

  private static class JwtPublicKeySignFactory
      extends KeyTypeManager.PrimitiveFactory<JwtPublicKeySignInternal, JwtRsaSsaPssPrivateKey> {
    public JwtPublicKeySignFactory() {
      super(JwtPublicKeySignInternal.class);
    }

    @Override
    public JwtPublicKeySignInternal getPrimitive(JwtRsaSsaPssPrivateKey keyProto)
        throws GeneralSecurityException {
      RSAPrivateCrtKey privateKey = createPrivateKey(keyProto);
      selfTestKey(privateKey, keyProto);
      JwtRsaSsaPssAlgorithm algorithm = keyProto.getPublicKey().getAlgorithm();
      Enums.HashType hash = JwtRsaSsaPssVerifyKeyManager.hashForPssAlgorithm(algorithm);
      int saltLength = JwtRsaSsaPssVerifyKeyManager.saltLengthForPssAlgorithm(algorithm);
      final RsaSsaPssSignJce signer = new RsaSsaPssSignJce(privateKey, hash, hash, saltLength);
      final String algorithmName = algorithm.name();
      final Optional<String> customKid =
          keyProto.getPublicKey().hasCustomKid()
              ? Optional.of(keyProto.getPublicKey().getCustomKid().getValue())
              : Optional.empty();

      return new JwtPublicKeySignInternal() {
        @Override
        public String signAndEncodeWithKid(RawJwt rawJwt, Optional<String> kid)
            throws GeneralSecurityException {
          if (customKid.isPresent()) {
            if (kid.isPresent()) {
              throw new JwtInvalidException("custom_kid can only be set for RAW keys.");
            }
            kid = customKid;
          }
          String unsignedCompact = JwtFormat.createUnsignedCompact(algorithmName, kid, rawJwt);
          return JwtFormat.createSignedCompact(
              unsignedCompact, signer.sign(unsignedCompact.getBytes(US_ASCII)));
        }
      };
    }
  }

  JwtRsaSsaPssSignKeyManager() {
    super(JwtRsaSsaPssPrivateKey.class, JwtRsaSsaPssPublicKey.class, new JwtPublicKeySignFactory());
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public JwtRsaSsaPssPublicKey getPublicKey(JwtRsaSsaPssPrivateKey privKeyProto) {
    return privKeyProto.getPublicKey();
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PRIVATE;
  }

  @Override
  public JwtRsaSsaPssPrivateKey parseKey(ByteString byteString)
      throws InvalidProtocolBufferException {
    return JwtRsaSsaPssPrivateKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public void validateKey(JwtRsaSsaPssPrivateKey privKey) throws GeneralSecurityException {
    Validators.validateVersion(privKey.getVersion(), getVersion());
    Validators.validateRsaModulusSize(
        new BigInteger(1, privKey.getPublicKey().getN().toByteArray()).bitLength());
    Validators.validateRsaPublicExponent(
        new BigInteger(1, privKey.getPublicKey().getE().toByteArray()));
  }

  @Override
  public KeyFactory<JwtRsaSsaPssKeyFormat, JwtRsaSsaPssPrivateKey> keyFactory() {
    return new KeyFactory<JwtRsaSsaPssKeyFormat, JwtRsaSsaPssPrivateKey>(
        JwtRsaSsaPssKeyFormat.class) {
      @Override
      public void validateKeyFormat(JwtRsaSsaPssKeyFormat keyFormat)
          throws GeneralSecurityException {
        Validators.validateRsaModulusSize(keyFormat.getModulusSizeInBits());
        Validators.validateRsaPublicExponent(
            new BigInteger(1, keyFormat.getPublicExponent().toByteArray()));
      }

      @Override
      public JwtRsaSsaPssKeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return JwtRsaSsaPssKeyFormat.parseFrom(
            byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public JwtRsaSsaPssPrivateKey deriveKey(
          JwtRsaSsaPssKeyFormat format, InputStream inputStream) {
        throw new UnsupportedOperationException();
      }

      @Override
      public JwtRsaSsaPssPrivateKey createKey(JwtRsaSsaPssKeyFormat format)
          throws GeneralSecurityException {
        JwtRsaSsaPssAlgorithm algorithm = format.getAlgorithm();
        KeyPairGenerator keyGen = EngineFactory.KEY_PAIR_GENERATOR.getInstance("RSA");
        RSAKeyGenParameterSpec spec =
            new RSAKeyGenParameterSpec(
                format.getModulusSizeInBits(),
                new BigInteger(1, format.getPublicExponent().toByteArray()));
        keyGen.initialize(spec);
        KeyPair keyPair = keyGen.generateKeyPair();
        RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        // Creates JwtRsaSsaPssPublicKey.
        JwtRsaSsaPssPublicKey pssPubKey =
            JwtRsaSsaPssPublicKey.newBuilder()
                .setVersion(getVersion())
                .setAlgorithm(algorithm)
                .setE(ByteString.copyFrom(pubKey.getPublicExponent().toByteArray()))
                .setN(ByteString.copyFrom(pubKey.getModulus().toByteArray()))
                .build();
        // Creates JwtRsaSsaPssPrivateKey.
        return JwtRsaSsaPssPrivateKey.newBuilder()
            .setVersion(getVersion())
            .setPublicKey(pssPubKey)
            .setD(ByteString.copyFrom(privKey.getPrivateExponent().toByteArray()))
            .setP(ByteString.copyFrom(privKey.getPrimeP().toByteArray()))
            .setQ(ByteString.copyFrom(privKey.getPrimeQ().toByteArray()))
            .setDp(ByteString.copyFrom(privKey.getPrimeExponentP().toByteArray()))
            .setDq(ByteString.copyFrom(privKey.getPrimeExponentQ().toByteArray()))
            .setCrt(ByteString.copyFrom(privKey.getCrtCoefficient().toByteArray()))
            .build();
      }

      /**
       * List of default templates to generate tokens with algorithms "PS256", "PS384" or "PS512".
       * Use the template with the "_RAW" suffix if you want to generate tokens without a "kid"
       * header.
       */
      @Override
      public Map<String, KeyFactory.KeyFormat<JwtRsaSsaPssKeyFormat>> keyFormats() {
        Map<String, KeyFactory.KeyFormat<JwtRsaSsaPssKeyFormat>> result = new HashMap<>();
        result.put(
            "JWT_PS256_2048_F4_RAW",
            createKeyFormat(
                JwtRsaSsaPssAlgorithm.PS256,
                2048,
                RSAKeyGenParameterSpec.F4,
                KeyTemplate.OutputPrefixType.RAW));
        result.put(
            "JWT_PS256_2048_F4",
            createKeyFormat(
                JwtRsaSsaPssAlgorithm.PS256,
                2048,
                RSAKeyGenParameterSpec.F4,
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "JWT_PS256_3072_F4_RAW",
            createKeyFormat(
                JwtRsaSsaPssAlgorithm.PS256,
                3072,
                RSAKeyGenParameterSpec.F4,
                KeyTemplate.OutputPrefixType.RAW));
        result.put(
            "JWT_PS256_3072_F4",
            createKeyFormat(
                JwtRsaSsaPssAlgorithm.PS256,
                3072,
                RSAKeyGenParameterSpec.F4,
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "JWT_PS384_3072_F4_RAW",
            createKeyFormat(
                JwtRsaSsaPssAlgorithm.PS384,
                3072,
                RSAKeyGenParameterSpec.F4,
                KeyTemplate.OutputPrefixType.RAW));
        result.put(
            "JWT_PS384_3072_F4",
            createKeyFormat(
                JwtRsaSsaPssAlgorithm.PS384,
                3072,
                RSAKeyGenParameterSpec.F4,
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "JWT_PS512_4096_F4_RAW",
            createKeyFormat(
                JwtRsaSsaPssAlgorithm.PS512,
                4096,
                RSAKeyGenParameterSpec.F4,
                KeyTemplate.OutputPrefixType.RAW));
        result.put(
            "JWT_PS512_4096_F4",
            createKeyFormat(
                JwtRsaSsaPssAlgorithm.PS512,
                4096,
                RSAKeyGenParameterSpec.F4,
                KeyTemplate.OutputPrefixType.TINK));
        return Collections.unmodifiableMap(result);
      }
    };
  }

  /**
   * Registers the {@link RsaSsaPssSignKeyManager} and the {@link RsaSsaPssVerifyKeyManager} with
   * the registry, so that the the RsaSsaPss-Keys can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerAsymmetricKeyManagers(
        new JwtRsaSsaPssSignKeyManager(), new JwtRsaSsaPssVerifyKeyManager(), newKeyAllowed);
  }

  private static KeyFactory.KeyFormat<JwtRsaSsaPssKeyFormat> createKeyFormat(
      JwtRsaSsaPssAlgorithm algorithm,
      int modulusSize,
      BigInteger publicExponent,
      KeyTemplate.OutputPrefixType prefixType) {
    JwtRsaSsaPssKeyFormat format =
        JwtRsaSsaPssKeyFormat.newBuilder()
            .setAlgorithm(algorithm)
            .setModulusSizeInBits(modulusSize)
            .setPublicExponent(ByteString.copyFrom(publicExponent.toByteArray()))
            .build();
    return new KeyFactory.KeyFormat<>(format, prefixType);
  }
}
