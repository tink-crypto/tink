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

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.KeysetReader;
import com.google.crypto.tink.PemKeyType;
import com.google.crypto.tink.proto.EcdsaPublicKey;
import com.google.crypto.tink.proto.EcdsaSignatureEncoding;
import com.google.crypto.tink.proto.EllipticCurveType;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.KeyData;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.KeyStatusType;
import com.google.crypto.tink.proto.Keyset;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.proto.RsaSsaPssPublicKey;
import com.google.crypto.tink.signature.internal.SigUtil;
import com.google.crypto.tink.testing.TestUtil;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.BufferedReader;
import java.io.StringReader;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for SignaturePemKeysetReader */
@RunWith(JUnit4.class)
public final class SignaturePemKeysetReaderTest {

  @Before
  public void setUp() {}

  @Test
  public void read_oneRSAPublicKey_shouldWork() throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n"
            + "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n"
            + "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n"
            + "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n"
            + "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n"
            + "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n"
            + "wQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder().addPem(pem, PemKeyType.RSA_PSS_2048_SHA256).build();
    Keyset ks = keysetReader.read();
    Keyset.Key key = ks.getKey(0);
    KeyData keyData = key.getKeyData();
    RsaSsaPssPublicKey publicKeyProto =
        RsaSsaPssPublicKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    RSAPublicKey publicKey =
        (RSAPublicKey)
            PemKeyType.RSA_PSS_2048_SHA256.readKey(new BufferedReader(new StringReader(pem)));

    assertThat(ks.getKeyCount()).isEqualTo(1);
    assertThat(ks.getPrimaryKeyId()).isEqualTo(key.getKeyId());
    assertThat(key.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(key.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
    assertThat(keyData.getTypeUrl()).isEqualTo(new RsaSsaPssVerifyKeyManager().getKeyType());
    assertThat(keyData.getKeyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
    assertThat(publicKeyProto.getParams().getSigHash()).isEqualTo(HashType.SHA256);
    assertThat(publicKeyProto.getParams().getMgf1Hash()).isEqualTo(HashType.SHA256);
    assertThat(publicKeyProto.getParams().getSaltLength()).isEqualTo(32);
    assertThat(publicKeyProto.getN().toByteArray())
        .isEqualTo(SigUtil.toUnsignedIntByteString(publicKey.getModulus()).toByteArray());
    assertThat(publicKeyProto.getE().toByteArray())
        .isEqualTo(SigUtil.toUnsignedIntByteString(publicKey.getPublicExponent()).toByteArray());
  }

  @Test
  public void read_oneECPublicKey_shouldWork() throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";
    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder().addPem(pem, PemKeyType.ECDSA_P256_SHA256).build();
    Keyset ks = keysetReader.read();
    Keyset.Key key = ks.getKey(0);
    KeyData keyData = key.getKeyData();
    EcdsaPublicKey publicKeyProto =
        EcdsaPublicKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    ECPublicKey publicKey =
        (ECPublicKey)
            PemKeyType.ECDSA_P256_SHA256.readKey(new BufferedReader(new StringReader(pem)));

    assertThat(ks.getKeyCount()).isEqualTo(1);
    assertThat(ks.getPrimaryKeyId()).isEqualTo(key.getKeyId());
    assertThat(key.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(key.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
    assertThat(keyData.getTypeUrl()).isEqualTo(new EcdsaVerifyKeyManager().getKeyType());
    assertThat(keyData.getKeyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
    assertThat(publicKeyProto.getParams().getHashType()).isEqualTo(HashType.SHA256);
    assertThat(publicKeyProto.getParams().getCurve()).isEqualTo(EllipticCurveType.NIST_P256);
    assertThat(publicKeyProto.getParams().getEncoding()).isEqualTo(EcdsaSignatureEncoding.DER);
    assertThat(publicKeyProto.getX().toByteArray())
        .isEqualTo(SigUtil.toUnsignedIntByteString(publicKey.getW().getAffineX()).toByteArray());
    assertThat(publicKeyProto.getY().toByteArray())
        .isEqualTo(SigUtil.toUnsignedIntByteString(publicKey.getW().getAffineY()).toByteArray());
  }

  @Test
  public void read_ensureUnsignedIntRepresentation() throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1M5IlCiYLvNDGG65DmoErfQTZjWa\n"
            + "UI/nrGayg/BmQa4f9db4zQRCc5IwErn3JtlLDAxQ8fXUoy99klswBEMZ/A==\n"
            + "-----END PUBLIC KEY-----";

    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder().addPem(pem, PemKeyType.ECDSA_P256_SHA256).build();

    Keyset ks = keysetReader.read();
    Keyset.Key key = ks.getKey(0);
    KeyData keyData = key.getKeyData();
    EcdsaPublicKey publicKeyProto =
        EcdsaPublicKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(publicKeyProto.getX().toByteArray())
        .isEqualTo(
            TestUtil.hexDecode("D4CE489428982EF343186EB90E6A04ADF41366359A508FE7AC66B283F06641AE"));
  }

  @Test
  public void read_onePEM_twoRSAPublicKeys_shouldWork() throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n"
            + "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n"
            + "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n"
            + "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n"
            + "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n"
            + "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n"
            + "wQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n"
            + "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkHT+woDZHckRv316VyUw\n"
            + "WnQ8lR7C1rOj+KPuBnAPMQTW8htNG0gfjYEb01ZRvZM8ezOunDnpBqvYPeATKTGu\n"
            + "YD7/Tq1gkcFGf59aG2vgi8I/+0OkYNyWwuYLKm34t50TKMvQwiIBr0IZfaGnzF/5\n"
            + "43wqtE6rvcZTavlR0q3ftJQ6OEFXnOzShRctQf7nIn2Mi2mks3cLoWpqLJe0rSiM\n"
            + "TYqas+fiLd5K5p55H2woBpoRPBmNEBMd2r+P0caGNRd3XuO2OwOx/2XezZ0Lj9ms\n"
            + "u7BDXM/No6dxLmrgwzokuRg0N/mF+PUCnNakbT1nyn/1uMopialAMDhYUEtZdFjw\n"
            + "gwIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder().addPem(pem, PemKeyType.RSA_PSS_2048_SHA256).build();
    Keyset ks = keysetReader.read();
    Keyset.Key firstKey = ks.getKey(0);
    Keyset.Key secondKey = ks.getKey(1);
    assertThat(ks.getKeyCount()).isEqualTo(2);
    assertThat(ks.getPrimaryKeyId()).isEqualTo(firstKey.getKeyId());

    KeyData keyData = firstKey.getKeyData();
    RsaSsaPssPublicKey publicKeyProto =
        RsaSsaPssPublicKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    RSAPublicKey publicKey =
        (RSAPublicKey)
            PemKeyType.RSA_PSS_2048_SHA256.readKey(new BufferedReader(new StringReader(pem)));
    assertThat(firstKey.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(firstKey.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
    assertThat(keyData.getTypeUrl()).isEqualTo(new RsaSsaPssVerifyKeyManager().getKeyType());
    assertThat(keyData.getKeyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
    assertThat(publicKeyProto.getParams().getSigHash()).isEqualTo(HashType.SHA256);
    assertThat(publicKeyProto.getParams().getMgf1Hash()).isEqualTo(HashType.SHA256);
    assertThat(publicKeyProto.getParams().getSaltLength()).isEqualTo(32);
    assertThat(publicKeyProto.getN().toByteArray())
        .isEqualTo(SigUtil.toUnsignedIntByteString(publicKey.getModulus()).toByteArray());
    assertThat(publicKeyProto.getE().toByteArray())
        .isEqualTo(SigUtil.toUnsignedIntByteString(publicKey.getPublicExponent()).toByteArray());

    keyData = secondKey.getKeyData();
    publicKeyProto =
        RsaSsaPssPublicKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    assertThat(secondKey.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(secondKey.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
    assertThat(keyData.getTypeUrl()).isEqualTo(new RsaSsaPssVerifyKeyManager().getKeyType());
    assertThat(keyData.getKeyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
    assertThat(publicKeyProto.getParams().getSigHash()).isEqualTo(HashType.SHA256);
    assertThat(publicKeyProto.getParams().getMgf1Hash()).isEqualTo(HashType.SHA256);
    assertThat(publicKeyProto.getParams().getSaltLength()).isEqualTo(32);
  }

  @Test
  public void read_onePEM_oneRSAPublicKey_oneECPublicKey_ECPublicKeyShouldBeIgnored()
      throws Exception {
    String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n"
            + "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n"
            + "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n"
            + "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n"
            + "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n"
            + "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n"
            + "wQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n"
            + "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";
    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder().addPem(pem, PemKeyType.RSA_PSS_2048_SHA256).build();
    Keyset ks = keysetReader.read();
    Keyset.Key key = ks.getKey(0);
    KeyData keyData = key.getKeyData();
    RsaSsaPssPublicKey publicKeyProto =
        RsaSsaPssPublicKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    RSAPublicKey publicKey =
        (RSAPublicKey)
            PemKeyType.RSA_PSS_2048_SHA256.readKey(new BufferedReader(new StringReader(pem)));

    assertThat(ks.getKeyCount()).isEqualTo(1);
    assertThat(ks.getPrimaryKeyId()).isEqualTo(key.getKeyId());
    assertThat(key.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(key.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
    assertThat(keyData.getTypeUrl()).isEqualTo(new RsaSsaPssVerifyKeyManager().getKeyType());
    assertThat(keyData.getKeyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
    assertThat(publicKeyProto.getParams().getSigHash()).isEqualTo(HashType.SHA256);
    assertThat(publicKeyProto.getParams().getMgf1Hash()).isEqualTo(HashType.SHA256);
    assertThat(publicKeyProto.getParams().getSaltLength()).isEqualTo(32);
    assertThat(publicKeyProto.getN().toByteArray())
        .isEqualTo(SigUtil.toUnsignedIntByteString(publicKey.getModulus()).toByteArray());
    assertThat(publicKeyProto.getE().toByteArray())
        .isEqualTo(SigUtil.toUnsignedIntByteString(publicKey.getPublicExponent()).toByteArray());
  }

  @Test
  public void read_twoPEMs_oneRSAPublicKey_oneECPublicKey_shouldWork() throws Exception {
    String rsaPem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n"
            + "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n"
            + "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n"
            + "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n"
            + "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n"
            + "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n"
            + "wQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    String ecPem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";
    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder()
            .addPem(rsaPem, PemKeyType.RSA_PSS_2048_SHA256)
            .addPem(ecPem, PemKeyType.ECDSA_P256_SHA256)
            .build();

    Keyset ks = keysetReader.read();
    assertThat(ks.getKeyCount()).isEqualTo(2);

    Keyset.Key firstKey = ks.getKey(0);
    assertThat(ks.getPrimaryKeyId()).isEqualTo(firstKey.getKeyId());
    KeyData keyData = firstKey.getKeyData();
    RsaSsaPssPublicKey rsaPublicKeyProto =
        RsaSsaPssPublicKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    RSAPublicKey rsaPublicKey =
        (RSAPublicKey)
            PemKeyType.RSA_PSS_2048_SHA256.readKey(new BufferedReader(new StringReader(rsaPem)));
    assertThat(firstKey.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(firstKey.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
    assertThat(keyData.getTypeUrl()).isEqualTo(new RsaSsaPssVerifyKeyManager().getKeyType());
    assertThat(keyData.getKeyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
    assertThat(rsaPublicKeyProto.getParams().getSigHash()).isEqualTo(HashType.SHA256);
    assertThat(rsaPublicKeyProto.getParams().getMgf1Hash()).isEqualTo(HashType.SHA256);
    assertThat(rsaPublicKeyProto.getParams().getSaltLength()).isEqualTo(32);
    assertThat(rsaPublicKeyProto.getN().toByteArray())
        .isEqualTo(SigUtil.toUnsignedIntByteString(rsaPublicKey.getModulus()).toByteArray());
    assertThat(rsaPublicKeyProto.getE().toByteArray())
        .isEqualTo(SigUtil.toUnsignedIntByteString(rsaPublicKey.getPublicExponent()).toByteArray());

    Keyset.Key secondKey = ks.getKey(1);
    keyData = secondKey.getKeyData();
    EcdsaPublicKey ecPublicKeyProto =
        EcdsaPublicKey.parseFrom(keyData.getValue(), ExtensionRegistryLite.getEmptyRegistry());
    ECPublicKey ecPublicKey =
        (ECPublicKey)
            PemKeyType.ECDSA_P256_SHA256.readKey(new BufferedReader(new StringReader(ecPem)));
    assertThat(secondKey.getStatus()).isEqualTo(KeyStatusType.ENABLED);
    assertThat(secondKey.getOutputPrefixType()).isEqualTo(OutputPrefixType.RAW);
    assertThat(keyData.getTypeUrl()).isEqualTo(new EcdsaVerifyKeyManager().getKeyType());
    assertThat(keyData.getKeyMaterialType()).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
    assertThat(ecPublicKeyProto.getParams().getHashType()).isEqualTo(HashType.SHA256);
    assertThat(ecPublicKeyProto.getParams().getCurve()).isEqualTo(EllipticCurveType.NIST_P256);
    assertThat(ecPublicKeyProto.getParams().getEncoding()).isEqualTo(EcdsaSignatureEncoding.DER);
    assertThat(ecPublicKeyProto.getX().toByteArray())
        .isEqualTo(SigUtil.toUnsignedIntByteString(ecPublicKey.getW().getAffineX()).toByteArray());
    assertThat(ecPublicKeyProto.getY().toByteArray())
        .isEqualTo(SigUtil.toUnsignedIntByteString(ecPublicKey.getW().getAffineY()).toByteArray());
  }
}
