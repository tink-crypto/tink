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
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.PrivateKeyTypeManager;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.JwtRsaSsaPkcs1Algorithm;
import com.google.crypto.tink.proto.JwtRsaSsaPkcs1KeyFormat;
import com.google.crypto.tink.proto.JwtRsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.proto.JwtRsaSsaPkcs1PublicKey;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.Enums;
import com.google.crypto.tink.subtle.RsaSsaPkcs1SignJce;
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
 * This key manager generates new {@code JwtRsaSsaPkcs1PrivateKey} keys and produces new instances
 * of {@code JwtPublicKeySign}.
 */
public final class JwtRsaSsaPkcs1SignKeyManager
    extends PrivateKeyTypeManager<JwtRsaSsaPkcs1PrivateKey, JwtRsaSsaPkcs1PublicKey> {
  private static final void selfTestKey(
      RSAPrivateCrtKey privateKey, JwtRsaSsaPkcs1PrivateKey keyProto)
      throws GeneralSecurityException {
    java.security.KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
    RSAPublicKey publicKey =
        (RSAPublicKey)
            kf.generatePublic(
                new RSAPublicKeySpec(
                    new BigInteger(1, keyProto.getPublicKey().getN().toByteArray()),
                    new BigInteger(1, keyProto.getPublicKey().getE().toByteArray())));
    // Sign and verify a test message to make sure that the key is correct.
    JwtRsaSsaPkcs1Algorithm algorithm = keyProto.getPublicKey().getAlgorithm();
    Enums.HashType hash = JwtRsaSsaPkcs1VerifyKeyManager.hashForPkcs1Algorithm(algorithm);
    SelfKeyTestValidators.validateRsaSsaPkcs1(privateKey, publicKey, hash);
  }

  private static final RSAPrivateCrtKey createPrivateKey(JwtRsaSsaPkcs1PrivateKey keyProto)
      throws GeneralSecurityException {
    java.security.KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
    return (RSAPrivateCrtKey)
        kf.generatePrivate(
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
      extends KeyTypeManager.PrimitiveFactory<JwtPublicKeySignInternal, JwtRsaSsaPkcs1PrivateKey> {
    public JwtPublicKeySignFactory() {
      super(JwtPublicKeySignInternal.class);
    }

    @Override
    public JwtPublicKeySignInternal getPrimitive(JwtRsaSsaPkcs1PrivateKey keyProto)
        throws GeneralSecurityException {
      RSAPrivateCrtKey privateKey = createPrivateKey(keyProto);
      selfTestKey(privateKey, keyProto);

      JwtRsaSsaPkcs1Algorithm algorithm = keyProto.getPublicKey().getAlgorithm();
      // This function also validates the algorithm.
      Enums.HashType hash = JwtRsaSsaPkcs1VerifyKeyManager.hashForPkcs1Algorithm(algorithm);
      final RsaSsaPkcs1SignJce signer = new RsaSsaPkcs1SignJce(privateKey, hash);
      final String algorithmName = algorithm.name();
      return new JwtPublicKeySignInternal() {
        @Override
        public String signAndEncodeWithKid(RawJwt rawJwt, Optional<String> kid)
            throws GeneralSecurityException {
          String unsignedCompact = JwtFormat.createUnsignedCompact(algorithmName, kid, rawJwt);
          return JwtFormat.createSignedCompact(
              unsignedCompact, signer.sign(unsignedCompact.getBytes(US_ASCII)));
        }
      };
    }
  }

  JwtRsaSsaPkcs1SignKeyManager() {
    super(
        JwtRsaSsaPkcs1PrivateKey.class,
        JwtRsaSsaPkcs1PublicKey.class,
        new JwtPublicKeySignFactory());
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public JwtRsaSsaPkcs1PublicKey getPublicKey(JwtRsaSsaPkcs1PrivateKey privKeyProto) {
    return privKeyProto.getPublicKey();
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PRIVATE;
  }

  @Override
  public JwtRsaSsaPkcs1PrivateKey parseKey(ByteString byteString)
      throws InvalidProtocolBufferException {
    return JwtRsaSsaPkcs1PrivateKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public void validateKey(JwtRsaSsaPkcs1PrivateKey privKey) throws GeneralSecurityException {
    Validators.validateVersion(privKey.getVersion(), getVersion());
    Validators.validateRsaModulusSize(
        new BigInteger(1, privKey.getPublicKey().getN().toByteArray()).bitLength());
    Validators.validateRsaPublicExponent(
        new BigInteger(1, privKey.getPublicKey().getE().toByteArray()));
  }

  @Override
  public KeyFactory<JwtRsaSsaPkcs1KeyFormat, JwtRsaSsaPkcs1PrivateKey> keyFactory() {
    return new KeyFactory<JwtRsaSsaPkcs1KeyFormat, JwtRsaSsaPkcs1PrivateKey>(
        JwtRsaSsaPkcs1KeyFormat.class) {
      @Override
      public void validateKeyFormat(JwtRsaSsaPkcs1KeyFormat keyFormat)
          throws GeneralSecurityException {
        Validators.validateRsaModulusSize(keyFormat.getModulusSizeInBits());
        Validators.validateRsaPublicExponent(
            new BigInteger(1, keyFormat.getPublicExponent().toByteArray()));
      }

      @Override
      public JwtRsaSsaPkcs1KeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return JwtRsaSsaPkcs1KeyFormat.parseFrom(
            byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public JwtRsaSsaPkcs1PrivateKey deriveKey(
          JwtRsaSsaPkcs1KeyFormat format, InputStream inputStream) {
        throw new UnsupportedOperationException();
      }

      @Override
      public JwtRsaSsaPkcs1PrivateKey createKey(JwtRsaSsaPkcs1KeyFormat format)
          throws GeneralSecurityException {
        JwtRsaSsaPkcs1Algorithm algorithm = format.getAlgorithm();
        KeyPairGenerator keyGen = EngineFactory.KEY_PAIR_GENERATOR.getInstance("RSA");
        RSAKeyGenParameterSpec spec =
            new RSAKeyGenParameterSpec(
                format.getModulusSizeInBits(),
                new BigInteger(1, format.getPublicExponent().toByteArray()));
        keyGen.initialize(spec);
        KeyPair keyPair = keyGen.generateKeyPair();
        RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        // Creates JwtRsaSsaPkcs1PublicKey.
        JwtRsaSsaPkcs1PublicKey pkcs1PubKey =
            JwtRsaSsaPkcs1PublicKey.newBuilder()
                .setVersion(getVersion())
                .setAlgorithm(algorithm)
                .setE(ByteString.copyFrom(pubKey.getPublicExponent().toByteArray()))
                .setN(ByteString.copyFrom(pubKey.getModulus().toByteArray()))
                .build();
        // Creates JwtRsaSsaPkcs1PrivateKey.
        return JwtRsaSsaPkcs1PrivateKey.newBuilder()
            .setVersion(getVersion())
            .setPublicKey(pkcs1PubKey)
            .setD(ByteString.copyFrom(privKey.getPrivateExponent().toByteArray()))
            .setP(ByteString.copyFrom(privKey.getPrimeP().toByteArray()))
            .setQ(ByteString.copyFrom(privKey.getPrimeQ().toByteArray()))
            .setDp(ByteString.copyFrom(privKey.getPrimeExponentP().toByteArray()))
            .setDq(ByteString.copyFrom(privKey.getPrimeExponentQ().toByteArray()))
            .setCrt(ByteString.copyFrom(privKey.getCrtCoefficient().toByteArray()))
            .build();
      }

      /**
       * List of default templates to generate tokens with algorithms "RS256", "RS384" or "RS512".
       * Use the template with the "_RAW" suffix if you want to generate tokens without a "kid"
       * header.
       */
      @Override
      public Map<String, KeyFactory.KeyFormat<JwtRsaSsaPkcs1KeyFormat>> keyFormats() {
        Map<String, KeyFactory.KeyFormat<JwtRsaSsaPkcs1KeyFormat>> result = new HashMap<>();
        result.put(
            "JWT_RS256_2048_F4_RAW",
            createKeyFormat(
                JwtRsaSsaPkcs1Algorithm.RS256,
                2048,
                RSAKeyGenParameterSpec.F4,
                KeyTemplate.OutputPrefixType.RAW));
        result.put(
            "JWT_RS256_2048_F4",
            createKeyFormat(
                JwtRsaSsaPkcs1Algorithm.RS256,
                2048,
                RSAKeyGenParameterSpec.F4,
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "JWT_RS256_3072_F4_RAW",
            createKeyFormat(
                JwtRsaSsaPkcs1Algorithm.RS256,
                3072,
                RSAKeyGenParameterSpec.F4,
                KeyTemplate.OutputPrefixType.RAW));
        result.put(
            "JWT_RS256_3072_F4",
            createKeyFormat(
                JwtRsaSsaPkcs1Algorithm.RS256,
                3072,
                RSAKeyGenParameterSpec.F4,
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "JWT_RS384_3072_F4_RAW",
            createKeyFormat(
                JwtRsaSsaPkcs1Algorithm.RS384,
                3072,
                RSAKeyGenParameterSpec.F4,
                KeyTemplate.OutputPrefixType.RAW));
        result.put(
            "JWT_RS384_3072_F4",
            createKeyFormat(
                JwtRsaSsaPkcs1Algorithm.RS384,
                3072,
                RSAKeyGenParameterSpec.F4,
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "JWT_RS512_4096_F4_RAW",
            createKeyFormat(
                JwtRsaSsaPkcs1Algorithm.RS512,
                4096,
                RSAKeyGenParameterSpec.F4,
                KeyTemplate.OutputPrefixType.RAW));
        result.put(
            "JWT_RS512_4096_F4",
            createKeyFormat(
                JwtRsaSsaPkcs1Algorithm.RS512,
                4096,
                RSAKeyGenParameterSpec.F4,
                KeyTemplate.OutputPrefixType.TINK));
        return Collections.unmodifiableMap(result);
      }
    };
  }

  /**
   * Registers the {@link RsaSsapkcs1SignKeyManager} and the {@link RsaSsapkcs1VerifyKeyManager}
   * with the registry, so that the the RsaSsapkcs1-Keys can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerAsymmetricKeyManagers(
        new JwtRsaSsaPkcs1SignKeyManager(), new JwtRsaSsaPkcs1VerifyKeyManager(), newKeyAllowed);
  }


  private static KeyFactory.KeyFormat<JwtRsaSsaPkcs1KeyFormat> createKeyFormat(
      JwtRsaSsaPkcs1Algorithm algorithm,
      int modulusSize,
      BigInteger publicExponent,
      KeyTemplate.OutputPrefixType prefixType) {
    JwtRsaSsaPkcs1KeyFormat format =
        JwtRsaSsaPkcs1KeyFormat.newBuilder()
            .setAlgorithm(algorithm)
            .setModulusSizeInBits(modulusSize)
            .setPublicExponent(ByteString.copyFrom(publicExponent.toByteArray()))
            .build();
    return new KeyFactory.KeyFormat<>(format, prefixType);
  }
}
