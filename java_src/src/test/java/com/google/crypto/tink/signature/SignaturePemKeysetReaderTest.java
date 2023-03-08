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
import static org.junit.Assert.assertThrows;

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
import com.google.crypto.tink.subtle.Hex;
import com.google.protobuf.ExtensionRegistryLite;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for SignaturePemKeysetReader */
@RunWith(JUnit4.class)
public final class SignaturePemKeysetReaderTest {

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
        .isEqualTo(Hex.decode("D4CE489428982EF343186EB90E6A04ADF41366359A508FE7AC66B283F06641AE"));
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
  public void read_onePEM_oneRSAPublicKey_oneECPublicKey_eCPublicKeyShouldBeIgnored()
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
    // The EC public key is ignored because it has the wrong type. It is not a RSA_PSS_2048_SHA256
    // key.
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

  @Test
  public void emptyReader_readThrowsIOException() throws Exception {
    KeysetReader keysetReader = SignaturePemKeysetReader.newBuilder().build();
    assertThrows(IOException.class, keysetReader::read);
  }

  @Test
  public void readerWithInvalidKeys_invalidKeysAreIgnored() throws Exception {
    String ecPublicKeyPem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";

    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder()
            .addPem("invalid", PemKeyType.ECDSA_P256_SHA256)
            .addPem(ecPublicKeyPem, PemKeyType.ECDSA_P256_SHA256)
            .addPem("invalid2", PemKeyType.ECDSA_P256_SHA256)
            .build();
    Keyset keyset = keysetReader.read();
    assertThat(keyset.getKeyCount()).isEqualTo(1);
  }

  @Test
  public void readerWithRsaPrivateKey_privateKeyIsIgnored() throws Exception {
    String rsaPublicKeyPem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv90Xf/NN1lRGBofJQzJf\n"
            + "lHvo6GAf25GGQGaMmD9T1ZP71CCbJ69lGIS/6akFBg6ECEHGM2EZ4WFLCdr5byUq\n"
            + "GCf4mY4WuOn+AcwzwAoDz9ASIFcQOoPclO7JYdfo2SOaumumdb5S/7FkKJ70TGYW\n"
            + "j9aTOYWsCcaojbjGDY/JEXz3BSRIngcgOvXBmV1JokcJ/LsrJD263WE9iUknZDhB\n"
            + "K7y4ChjHNqL8yJcw/D8xLNiJtIyuxiZ00p/lOVUInr8C/a2C1UGCgEGuXZAEGAdO\n"
            + "NVez52n5TLvQP3hRd4MTi7YvfhezRcA4aXyIDOv+TYi4p+OVTYQ+FMbkgoWBm5bq\n"
            + "wQIDAQAB\n"
            + "-----END PUBLIC KEY-----\n";
    String rsaPrivateKeyPem =
        "-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIIEpAIBAAKCAQEAsll1i7Arx1tosXYSyb9oxfoFlYozTGHhZ7wgvMdXV8Em6JIQ\n"
            + "ud85iQcs9iYOaIPHzUr00x3emRW2mzAfvvli3oxxvS217GJdollxL4ao3D0kHpaI\n"
            + "yCORt78evDWDEfVcJr6RC3b2H+pAjtaS8alXimIsgsD89vae82cOOL/JD2PaTzu7\n"
            + "0IjIrno8WlXmb2R01WLTLM57ft188BScoOlstlJegfu6gVqPEnSONOUTX1crLhe3\n"
            + "ukMAgVl+b7kDPABYhNWTURjGDXWwEPb+zn7NzBy31Y0TiWk9Qzd/Tz3pScseQQXn\n"
            + "krltfwSwzSYqwzz/xaiQ0mdCXmHBnpNjVQ8ihQIDAQABAoIBAHYrXf3bEXa6syh6\n"
            + "AkLYZzRdz5tggVLHu9C+zrYmIlILsZsBRMHTDM0lCv5hAsTvI9B7LLJBJT8rKt2y\n"
            + "SiaAGKk6RxZAljx0hHPQbXU+9N1QSYFW3nQ1VRR5NoUfs6OPfapSM8pz3OoSjQnX\n"
            + "VG94c39GQxWzhyifCXxeuQaS1EY0F8g9HKkSdRbvsNVF/2j+rdmWeur8swtYBDCN\n"
            + "nBymiDhEBj/Y1Ft3R6ywC14YM/af4aDWTbhQvZYPtITdoEtOWulGkqcx0j/NlMYU\n"
            + "SZcaG3M/6UuKXGzibtO4w9LlI00HPlBDi3fQGbezk6WyLNjcE4xj/MKFg7VosgN7\n"
            + "XDy68tUCgYEA6FovqDcya6JxivhyVZks98e22sPARwpowI3Nt+gsF5uPcqQMvbot\n"
            + "ACzKHjqxRJyGbioMUI8Ao20/f2PxzeI5wAtH2HPNaN6bCbBXvxlCTMCAokbHSWjW\n"
            + "stK2PXl2cqF/51ED7EPbgxABetGyfudsx22QowSR66Sq3I8UtZnQVUMCgYEAxIBC\n"
            + "EW2oLh9ZUKxEeMuFlMN1FJCCqIx3zeVjUtAC3Vm/VvodEL0KM7w9Y123BfeoWMnG\n"
            + "HaqNUEZRUO/bMvaiIXVykF19NTCxym4s6eKNBwGsdWvxroRm0k37uhflt9A7iVX6\n"
            + "HmDVPYgjLJbPmLc8+Ms5ML6Od7qXKajRFOPmSJcCgYEA28JY6s/x9013+InNkdpD\n"
            + "ZsNU1gpo9IgK1XwJQ1TrRxTRkwtIJbZN06mJLRg0C4HDv7QzW4o1f1zXvsQnsqOy\n"
            + "HUpOFJJKiFJq7roD8/GO/Irh3xn0aSEoV4/l37Te68KF96FvhWoU1xwvWhu1qEN4\n"
            + "ZhLhxt2OqgJfvCXz32LwYYMCgYBVEL0JNHJw/Qs6PEksDdcXLoI509FsS9r1XE9i\n"
            + "I0CKOHb3nTEF9QA8o0nkAUbhI3RSc477esDQNpCvPBalelV3rJNa4c35P8pHuuhg\n"
            + "m723gcb50i/+/7xPYIkP55Z/u3p6mqi7i+nkSFIJ1IOsNe8EOV3ZtzSPqkwUMcvJ\n"
            + "gltHowKBgQDkB76QzH3xb4jABKehkCxVxqyGLKxU7SOZpLpCc/5OHbo12u/CwlwG\n"
            + "uAeidKZk3SJEmj0F1+Aiir2KRv+RX543VvzCtEXNkVViVrirzvjZUGKPdkMWfbF8\n"
            + "OdD7qHPPNu5jSyaroeN6VqfbELpewhYzulMEipckEZlU4+Dxu2k1eQ==\n"
            + "-----END RSA PRIVATE KEY-----\n";
    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder()
            .addPem(rsaPublicKeyPem, PemKeyType.RSA_PSS_2048_SHA256)
            .addPem(rsaPrivateKeyPem, PemKeyType.RSA_PSS_2048_SHA256)
            .build();
    Keyset keyset = keysetReader.read();
    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getKey(0).getKeyData().getKeyMaterialType())
        .isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
  }

  @Test
  public void readerWithEcPrivateKey_privateKeyIsIgnored() throws Exception {
    String ecPublicKeyPem =
        "-----BEGIN PUBLIC KEY-----\n"
            + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7BiT5K5pivl4Qfrt9hRhRREMUzj/\n"
            + "8suEJ7GlMxZfvdcpbi/GhYPuJi8Gn2H1NaMJZcLZo5MLPKyyGT5u3u1VBQ==\n"
            + "-----END PUBLIC KEY-----\n";
    String ecPrivateKeyPem =
        "-----BEGIN EC PRIVATE KEY-----"
            + "MHcCAQEEIBZJ/P6e1I/nQiBnQxx9aYDPAjwUtbV9Nffuzfubyuw8oAoGCCqGSM49\n"
            + "AwEHoUQDQgAEKSPVJGELbULai+viQc3Zz95+x2NiFvjsDlqmh6rDNeiVuwiwdf5l\n"
            + "lyZ0gbLJ/vheUAwtcA2z0csWU60MfBup3Q==\n"
            + "-----END EC PRIVATE KEY-----\n";

    KeysetReader keysetReader =
        SignaturePemKeysetReader.newBuilder()
            .addPem(ecPublicKeyPem, PemKeyType.ECDSA_P256_SHA256)
            .addPem(ecPrivateKeyPem, PemKeyType.ECDSA_P256_SHA256)
            .build();
    Keyset keyset = keysetReader.read();
    assertThat(keyset.getKeyCount()).isEqualTo(1);
    assertThat(keyset.getKey(0).getKeyData().getKeyMaterialType())
        .isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC);
  }
}
