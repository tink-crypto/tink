// Copyright 2018 Google Inc.
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

package com.google.crypto.tink.signature;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTypeManager;
import com.google.crypto.tink.PrivateKeyTypeManager;
import com.google.crypto.tink.PublicKeySign;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.RsaSsaPkcs1KeyFormat;
import com.google.crypto.tink.proto.RsaSsaPkcs1Params;
import com.google.crypto.tink.proto.RsaSsaPkcs1PrivateKey;
import com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.subtle.EngineFactory;
import com.google.crypto.tink.subtle.RsaSsaPkcs1SignJce;
import com.google.crypto.tink.subtle.SelfKeyTestValidators;
import com.google.crypto.tink.subtle.Validators;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistryLite;
import com.google.protobuf.InvalidProtocolBufferException;
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

/**
 * This key manager generates new {@code RsaSsaPkcs1PrivateKey} keys and produces new instances of
 * {@code RsaSsaPkcs1SignJce}.
 */
public final class RsaSsaPkcs1SignKeyManager
    extends PrivateKeyTypeManager<RsaSsaPkcs1PrivateKey, RsaSsaPkcs1PublicKey> {
  RsaSsaPkcs1SignKeyManager() {
    super(
        RsaSsaPkcs1PrivateKey.class,
        RsaSsaPkcs1PublicKey.class,
        new KeyTypeManager.PrimitiveFactory<PublicKeySign, RsaSsaPkcs1PrivateKey>(
            PublicKeySign.class) {
          @Override
          public PublicKeySign getPrimitive(RsaSsaPkcs1PrivateKey keyProto)
              throws GeneralSecurityException {
            java.security.KeyFactory kf = EngineFactory.KEY_FACTORY.getInstance("RSA");
            RSAPrivateCrtKey privateKey =
                (RSAPrivateCrtKey)
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
            RsaSsaPkcs1Params params = keyProto.getPublicKey().getParams();
            RSAPublicKey publicKey =
                (RSAPublicKey)
                    kf.generatePublic(
                        new RSAPublicKeySpec(
                            new BigInteger(1, keyProto.getPublicKey().getN().toByteArray()),
                            new BigInteger(1, keyProto.getPublicKey().getE().toByteArray())));

            SelfKeyTestValidators.validateRsaSsaPkcs1(
                privateKey, publicKey, SigUtil.toHashType(params.getHashType()));
            return new RsaSsaPkcs1SignJce(privateKey, SigUtil.toHashType(params.getHashType()));
          }
        });
  }

  @Override
  public String getKeyType() {
    return "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";
  }

  @Override
  public int getVersion() {
    return 0;
  }

  @Override
  public RsaSsaPkcs1PublicKey getPublicKey(RsaSsaPkcs1PrivateKey privKeyProto)
      throws GeneralSecurityException {
    return privKeyProto.getPublicKey();
  }

  @Override
  public KeyMaterialType keyMaterialType() {
    return KeyMaterialType.ASYMMETRIC_PRIVATE;
  }

  @Override
  public RsaSsaPkcs1PrivateKey parseKey(ByteString byteString)
      throws InvalidProtocolBufferException {
    return RsaSsaPkcs1PrivateKey.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
  }

  @Override
  public void validateKey(RsaSsaPkcs1PrivateKey privKey) throws GeneralSecurityException {
    Validators.validateVersion(privKey.getVersion(), getVersion());
    Validators.validateRsaModulusSize(
        new BigInteger(1, privKey.getPublicKey().getN().toByteArray()).bitLength());
    Validators.validateRsaPublicExponent(
        new BigInteger(1, privKey.getPublicKey().getE().toByteArray()));
    SigUtil.validateRsaSsaPkcs1Params(privKey.getPublicKey().getParams());
  }

  @Override
  public KeyFactory<RsaSsaPkcs1KeyFormat, RsaSsaPkcs1PrivateKey> keyFactory() {
    return new KeyFactory<RsaSsaPkcs1KeyFormat, RsaSsaPkcs1PrivateKey>(RsaSsaPkcs1KeyFormat.class) {
      @Override
      public void validateKeyFormat(RsaSsaPkcs1KeyFormat keyFormat)
          throws GeneralSecurityException {
        SigUtil.validateRsaSsaPkcs1Params(keyFormat.getParams());
        Validators.validateRsaModulusSize(keyFormat.getModulusSizeInBits());
        Validators.validateRsaPublicExponent(
            new BigInteger(1, keyFormat.getPublicExponent().toByteArray()));
      }

      @Override
      public RsaSsaPkcs1KeyFormat parseKeyFormat(ByteString byteString)
          throws InvalidProtocolBufferException {
        return RsaSsaPkcs1KeyFormat.parseFrom(byteString, ExtensionRegistryLite.getEmptyRegistry());
      }

      @Override
      public RsaSsaPkcs1PrivateKey createKey(RsaSsaPkcs1KeyFormat format)
          throws GeneralSecurityException {
        RsaSsaPkcs1Params params = format.getParams();
        KeyPairGenerator keyGen = EngineFactory.KEY_PAIR_GENERATOR.getInstance("RSA");
        RSAKeyGenParameterSpec spec =
            new RSAKeyGenParameterSpec(
                format.getModulusSizeInBits(),
                new BigInteger(1, format.getPublicExponent().toByteArray()));
        keyGen.initialize(spec);
        KeyPair keyPair = keyGen.generateKeyPair();
        RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();

        // Creates RsaSsaPkcs1PublicKey.
        RsaSsaPkcs1PublicKey pkcs1PubKey =
            RsaSsaPkcs1PublicKey.newBuilder()
                .setVersion(getVersion())
                .setParams(params)
                .setE(ByteString.copyFrom(pubKey.getPublicExponent().toByteArray()))
                .setN(ByteString.copyFrom(pubKey.getModulus().toByteArray()))
                .build();

        // Creates RsaSsaPkcs1PrivateKey.
        return RsaSsaPkcs1PrivateKey.newBuilder()
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

      @Override
      public Map<String, KeyFactory.KeyFormat<RsaSsaPkcs1KeyFormat>> keyFormats()
          throws GeneralSecurityException {
        Map<String, KeyFactory.KeyFormat<RsaSsaPkcs1KeyFormat>> result = new HashMap<>();
        result.put(
            "RSA_SSA_PKCS1_3072_SHA256_F4",
            new KeyFormat<>(
                createKeyFormat(HashType.SHA256, 3072, RSAKeyGenParameterSpec.F4),
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "RSA_SSA_PKCS1_3072_SHA256_F4_RAW",
            new KeyFormat<>(
                createKeyFormat(HashType.SHA256, 3072, RSAKeyGenParameterSpec.F4),
                KeyTemplate.OutputPrefixType.RAW));
        // This is identical to RSA_SSA_PKCS1_3072_SHA256_F4_RAW. It is needed to maintain backward
        // compatibility with SignatureKeyTemplates.
        // TODO(b/185475349): remove this in Tink 2.0.0.
        result.put(
            "RSA_SSA_PKCS1_3072_SHA256_F4_WITHOUT_PREFIX",
            new KeyFormat<>(
                createKeyFormat(HashType.SHA256, 3072, RSAKeyGenParameterSpec.F4),
                KeyTemplate.OutputPrefixType.RAW));
        result.put(
            "RSA_SSA_PKCS1_4096_SHA512_F4",
            new KeyFormat<>(
                createKeyFormat(HashType.SHA512, 4096, RSAKeyGenParameterSpec.F4),
                KeyTemplate.OutputPrefixType.TINK));
        result.put(
            "RSA_SSA_PKCS1_4096_SHA512_F4_RAW",
            new KeyFormat<>(
                createKeyFormat(HashType.SHA512, 4096, RSAKeyGenParameterSpec.F4),
                KeyTemplate.OutputPrefixType.RAW));
        return Collections.unmodifiableMap(result);
      }
    };
  }

  /**
   * Registers the {@link RsaSsaPkcs1SignKeyManager} and the {@link RsaSsaPkcs1VerifyKeyManager}
   * with the registry, so that the the RsaSsaPkcs1-Keys can be used with Tink.
   */
  public static void registerPair(boolean newKeyAllowed) throws GeneralSecurityException {
    Registry.registerAsymmetricKeyManagers(
        new RsaSsaPkcs1SignKeyManager(), new RsaSsaPkcs1VerifyKeyManager(), newKeyAllowed);
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of RSA-SSA-PKCS1 key pairs with the
   *     following parameters:
   *     <ul>
   *       <li>Hash function: SHA256.
   *       <li>Modulus size: 3072 bit.
   *       <li>Public exponent: 65537 (aka F4).
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}.
   *     </ul>
   *
   * @deprecated use {@code KeyTemplates.get("RSA_SSA_PKCS1_3072_SHA256_F4")}
   */
  @Deprecated
  public static final KeyTemplate rsa3072SsaPkcs1Sha256F4Template() {
    return createKeyTemplate(
        HashType.SHA256,
        /*modulusSize=*/ 3072,
        RSAKeyGenParameterSpec.F4,
        KeyTemplate.OutputPrefixType.TINK);
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of RSA-SSA-PKCS1 key pairs with the
   *     following parameters:
   *     <ul>
   *       <li>Hash function: SHA256.
   *       <li>Modulus size: 3072 bit.
   *       <li>Public exponent: 65537 (aka F4).
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix).
   *     </ul>
   *
   * @deprecated use {@code KeyTemplates.get("RSA_SSA_PKCS1_3072_SHA256_F4_RAW")}
   */
  @Deprecated
  public static final KeyTemplate rawRsa3072SsaPkcs1Sha256F4Template() {
    return createKeyTemplate(
        HashType.SHA256,
        /*modulusSize=*/ 3072,
        RSAKeyGenParameterSpec.F4,
        KeyTemplate.OutputPrefixType.RAW);
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of RSA-SSA-PKCS1 key pairs with the
   *     following parameters:
   *     <ul>
   *       <li>Hash function: SHA512.
   *       <li>Modulus size: 4096 bit.
   *       <li>Public exponent: 65537 (aka F4).
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#TINK}.
   *     </ul>
   *
   * @deprecated use {@code KeyTemplates.get("RSA_SSA_PKCS1_4096_SHA512_F4")}
   */
  @Deprecated
  public static final KeyTemplate rsa4096SsaPkcs1Sha512F4Template() {
    return createKeyTemplate(
        HashType.SHA512,
        /*modulusSize=*/ 4096,
        RSAKeyGenParameterSpec.F4,
        KeyTemplate.OutputPrefixType.TINK);
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of RSA-SSA-PKCS1 key pairs with the
   *     following parameters:
   *     <ul>
   *       <li>Hash function: SHA512.
   *       <li>Modulus size: 4096 bit.
   *       <li>Public exponent: 65537 (aka F4).
   *       <li>Prefix type: {@link KeyTemplate.OutputPrefixType#RAW} (no prefix).
   *     </ul>
   *
   * @deprecated use {@code KeyTemplates.get("RSA_SSA_PKCS1_4096_SHA512_F4_RAW")}
   */
  @Deprecated
  public static final KeyTemplate rawRsa4096SsaPkcs1Sha512F4Template() {
    return createKeyTemplate(
        HashType.SHA512,
        /*modulusSize=*/ 4096,
        RSAKeyGenParameterSpec.F4,
        KeyTemplate.OutputPrefixType.RAW);
  }

  /**
   * @return a {@link KeyTemplate} containing a {@link RsaSsaPkcs1KeyFormat} with some specified
   *     parameters.
   */
  private static KeyTemplate createKeyTemplate(
      HashType hashType,
      int modulusSize,
      BigInteger publicExponent,
      KeyTemplate.OutputPrefixType prefixType) {
    RsaSsaPkcs1KeyFormat format = createKeyFormat(hashType, modulusSize, publicExponent);
    return KeyTemplate.create(
        new RsaSsaPkcs1SignKeyManager().getKeyType(), format.toByteArray(), prefixType);
  }

  private static RsaSsaPkcs1KeyFormat createKeyFormat(
      HashType hashType, int modulusSize, BigInteger publicExponent) {
    RsaSsaPkcs1Params params = RsaSsaPkcs1Params.newBuilder().setHashType(hashType).build();
    return RsaSsaPkcs1KeyFormat.newBuilder()
        .setParams(params)
        .setModulusSizeInBits(modulusSize)
        .setPublicExponent(ByteString.copyFrom(publicExponent.toByteArray()))
        .build();
  }
}
