// Copyright 2017 Google Inc.
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

import com.google.crypto.tink.KeysetReader;
import com.google.crypto.tink.PemKeyType;
import com.google.crypto.tink.proto.EcdsaParams;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.EncryptedKeyset;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.RsaSsaPkcs1Params;
import com.google.crypto.tink.proto.RsaSsaPkcs1PublicKey;
import com.google.crypto.tink.proto.RsaSsaPssParams;
import com.google.crypto.tink.proto.RsaSsaPssPublicKey;
import com.google.crypto.tink.signature.internal.SigUtil;
import com.google.crypto.tink.subtle.Random;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.Key;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * SignaturePemKeysetReader is a {@link KeysetReader} that can read digital signature keys in PEM
 * format (RFC 7468).
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * import com.google.crypto.tink.subtle.PemKeyType;
 *
 * String pem = ...;
 * PemKeyType type = ...;
 * KeysetReader reader = SignaturePemKeysetReader.newBuilder().addPem(pem, type).build();
 * }</pre>
 */
public final class SignaturePemKeysetReader implements KeysetReader {
  private List<PemKey> pemKeys;

  SignaturePemKeysetReader(List<PemKey> pemKeys) {
    this.pemKeys = pemKeys;
  }

  /** @return a {@link Builder} for {@link SignaturePemKeysetReader}. */
  public static Builder newBuilder() {
    return new Builder();
  }

  /** Builder for SignaturePemKeysetReader */
  public static final class Builder {
    private List<PemKey> pemKeys = new ArrayList<PemKey>();

    Builder() {}

    public KeysetReader build() {
      return new SignaturePemKeysetReader(pemKeys);
    }

    /**
     * Adds a PEM.
     *
     * <p>A single PEM can contain multiple keys, but all must have the same {@code keyType}.
     * Invalid or unparsable keys are ignored.
     *
     * <p>The first key in the first added PEM is the primary key.
     */
    public Builder addPem(String pem, PemKeyType keyType) {
      PemKey pemKey = new PemKey();
      pemKey.reader = new BufferedReader(new StringReader(pem));
      pemKey.type = keyType;
      pemKeys.add(pemKey);
      return this;
    }
  }

  private static final class PemKey {
    BufferedReader reader;
    PemKeyType type;
  }

  @Override
  public Keyset read() throws IOException {
    Keyset.Builder keyset = Keyset.newBuilder();
    for (PemKey pemKey : pemKeys) {
      for (Keyset.Key key = readKey(pemKey.reader, pemKey.type);
          key != null;
          key = readKey(pemKey.reader, pemKey.type)) {
        keyset.addKey(key);
      }
    }

    if (keyset.getKeyCount() == 0) {
      throw new IOException("cannot find any key");
    }
    // Use the first key as the primary key id.
    keyset.setPrimaryKeyId(keyset.getKey(0).getKeyId());
    return keyset.build();
  }

  @Override
  public EncryptedKeyset readEncrypted() throws IOException {
    throw new UnsupportedOperationException();
  }

  /** Reads a single PEM key from {@code reader}. Invalid or unparsable PEM would be ignored */
  private static Keyset.Key readKey(BufferedReader reader, PemKeyType pemKeyType)
      throws IOException {
    Key key = pemKeyType.readKey(reader);
    if (key == null) {
      return null;
    }

    KeyData keyData;
    if (key instanceof RSAPublicKey) {
      keyData = convertRsaPublicKey(pemKeyType, (RSAPublicKey) key);
    } else if (key instanceof ECPublicKey) {
      keyData = convertEcPublicKey(pemKeyType, (ECPublicKey) key);
    } else {
      // TODO(thaidn): support RSA and EC private keys.
      return null;
    }

    return Keyset.Key.newBuilder()
        .setKeyData(keyData)
        .setStatus(KeyStatusType.ENABLED)
        .setOutputPrefixType(OutputPrefixType.RAW) // PEM keys don't add any prefix to signatures
        .setKeyId(Random.randInt())
        .build();
  }

  private static KeyData convertRsaPublicKey(PemKeyType pemKeyType, RSAPublicKey key)
      throws IOException {
    if (pemKeyType.algorithm.equals("RSASSA-PKCS1-v1_5")) {
      RsaSsaPkcs1Params params =
          RsaSsaPkcs1Params.newBuilder().setHashType(getHashType(pemKeyType)).build();
      RsaSsaPkcs1PublicKey pkcs1PubKey =
          RsaSsaPkcs1PublicKey.newBuilder()
              .setVersion(new RsaSsaPkcs1VerifyKeyManager().getVersion())
              .setParams(params)
              .setE(SigUtil.toUnsignedIntByteString(key.getPublicExponent()))
              .setN(SigUtil.toUnsignedIntByteString(key.getModulus()))
              .build();
      return KeyData.newBuilder()
          .setTypeUrl(new RsaSsaPkcs1VerifyKeyManager().getKeyType())
          .setValue(pkcs1PubKey.toByteString())
          .setKeyMaterialType(KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC)
          .build();
    } else if (pemKeyType.algorithm.equals("RSASSA-PSS")) {
      RsaSsaPssParams params =
          RsaSsaPssParams.newBuilder()
              .setSigHash(getHashType(pemKeyType))
              .setMgf1Hash(getHashType(pemKeyType))
              .setSaltLength(getDigestSizeInBytes(pemKeyType))
              .build();
      RsaSsaPssPublicKey pssPubKey =
          RsaSsaPssPublicKey.newBuilder()
              .setVersion(new RsaSsaPssVerifyKeyManager().getVersion())
              .setParams(params)
              .setE(SigUtil.toUnsignedIntByteString(key.getPublicExponent()))
              .setN(SigUtil.toUnsignedIntByteString(key.getModulus()))
              .build();
      return KeyData.newBuilder()
          .setTypeUrl(new RsaSsaPssVerifyKeyManager().getKeyType())
          .setValue(pssPubKey.toByteString())
          .setKeyMaterialType(KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC)
          .build();
    }
    throw new IOException("unsupported RSA signature algorithm: " + pemKeyType.algorithm);
  }

  private static KeyData convertEcPublicKey(PemKeyType pemKeyType, ECPublicKey key)
      throws IOException {
    if (pemKeyType.algorithm.equals("ECDSA")) {
      EcdsaParams params =
          EcdsaParams.newBuilder()
              .setHashType(getHashType(pemKeyType))
              .setCurve(getCurveType(pemKeyType))
              .setEncoding(EcdsaSignatureEncoding.DER)
              .build();
      EcdsaPublicKey ecdsaPubKey =
          EcdsaPublicKey.newBuilder()
              .setVersion(new EcdsaVerifyKeyManager().getVersion())
              .setParams(params)
              .setX(SigUtil.toUnsignedIntByteString(key.getW().getAffineX()))
              .setY(SigUtil.toUnsignedIntByteString(key.getW().getAffineY()))
              .build();

      return KeyData.newBuilder()
          .setTypeUrl(new EcdsaVerifyKeyManager().getKeyType())
          .setValue(ecdsaPubKey.toByteString())
          .setKeyMaterialType(KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC)
          .build();
    }
    throw new IOException("unsupported EC signature algorithm: " + pemKeyType.algorithm);
  }

  private static HashType getHashType(PemKeyType pemKeyType) {
    switch (pemKeyType.hash) {
      case SHA256:
        return HashType.SHA256;
      case SHA384:
        return HashType.SHA384;
      case SHA512:
        return HashType.SHA512;
      default:
        break;
    }
    throw new IllegalArgumentException("unsupported hash type: " + pemKeyType.hash.name());
  }

  private static int getDigestSizeInBytes(PemKeyType pemKeyType) {
    switch (pemKeyType.hash) {
      case SHA256:
        return 32;
      case SHA384:
        return 48;
      case SHA512:
        return 64;
      default:
        break;
    }
    throw new IllegalArgumentException("unsupported hash type: " + pemKeyType.hash.name());
  }

  private static EllipticCurveType getCurveType(PemKeyType pemKeyType) {
    switch (pemKeyType.keySizeInBits) {
      case 256:
        return EllipticCurveType.NIST_P256;
      case 384:
        return EllipticCurveType.NIST_P384;
      case 521:
        return EllipticCurveType.NIST_P521;
      default:
        break;
    }
    throw new IllegalArgumentException(
        "unsupported curve for key size: " + pemKeyType.keySizeInBits);
  }
}
