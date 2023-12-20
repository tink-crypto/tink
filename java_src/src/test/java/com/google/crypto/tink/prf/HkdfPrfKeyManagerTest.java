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

package com.google.crypto.tink.prf;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.internal.TinkBugException.exceptionIsBug;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.TinkProtoKeysetFormat;
import com.google.crypto.tink.internal.KeyManagerRegistry;
import com.google.crypto.tink.internal.KeyTypeManager;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.proto.HashType;
import com.google.crypto.tink.proto.HkdfPrfKey;
import com.google.crypto.tink.proto.HkdfPrfKeyFormat;
import com.google.crypto.tink.proto.HkdfPrfParams;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.subtle.Enums;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.subtle.Random;
import com.google.crypto.tink.subtle.prf.HkdfStreamingPrf;
import com.google.crypto.tink.subtle.prf.PrfImpl;
import com.google.crypto.tink.subtle.prf.StreamingPrf;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

/** Tests for HkdfPrfKeyManager. */
@RunWith(Theories.class)
public class HkdfPrfKeyManagerTest {
  private final HkdfPrfKeyManager manager = new HkdfPrfKeyManager();
  private final KeyTypeManager.KeyFactory<HkdfPrfKeyFormat, HkdfPrfKey> factory =
      manager.keyFactory();

  @Before
  public void register() throws Exception {
    PrfConfig.register();
  }

  @Test
  public void basics() throws Exception {
    assertThat(manager.getKeyType()).isEqualTo("type.googleapis.com/google.crypto.tink.HkdfPrfKey");
    assertThat(manager.getVersion()).isEqualTo(0);
    assertThat(manager.keyMaterialType()).isEqualTo(KeyMaterialType.SYMMETRIC);
  }

  @Test
  public void validateKey_empty_throws() throws Exception {
    HkdfPrfKey key = HkdfPrfKey.getDefaultInstance();
    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(key));
  }

  @Test
  public void validateKey_valid32ByteKey_works() throws Exception {
    manager.validateKey(
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build());
  }

  @Test
  public void validateKey_invalid31ByteKey_throws() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(31)))
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(key));
  }

  @Test
  public void validateKey_validSha512Key_works() throws Exception {
    manager.validateKey(
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA512))
            .build());
  }

  @Test
  public void validateKey_valid33ByteKey_works() throws Exception {
    manager.validateKey(
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(33)))
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build());
  }

  @Test
  public void validateKey_validKeyWithSalt_works() throws Exception {
    manager.validateKey(
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .setParams(
                HkdfPrfParams.newBuilder()
                    .setSalt(ByteString.copyFrom(Random.randBytes(5)))
                    .setHash(HashType.SHA256))
            .build());
  }

  @Test
  public void validateKey_invalidSha1Key_throws() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.newBuilder()
            .setVersion(0)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA1))
            .build();
    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(key));
  }

  @Test
  public void validateKey_invalidKeyVersion_throws() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.newBuilder()
            .setVersion(1)
            .setKeyValue(ByteString.copyFrom(Random.randBytes(32)))
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    assertThrows(GeneralSecurityException.class, () -> manager.validateKey(key));
  }

  @Test
  public void validateKeyFormat_empty_throws() throws Exception {
    HkdfPrfKeyFormat keyFormat = HkdfPrfKeyFormat.getDefaultInstance();
    assertThrows(GeneralSecurityException.class, () -> factory.validateKeyFormat(keyFormat));
  }

  @Test
  public void validateKeyFormat_valid32Byte() throws Exception {
    factory.validateKeyFormat(
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build());
  }

  @Test
  public void validateKeyFormat_invalid31Byte_throws() throws Exception {
    HkdfPrfKeyFormat keyFormat =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(31)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build();
    assertThrows(GeneralSecurityException.class, () -> factory.validateKeyFormat(keyFormat));
  }

  @Test
  public void validateKeyFormat_validSha512() throws Exception {
    factory.validateKeyFormat(
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA512))
            .build());
  }

  @Test
  public void validateKeyFormat_valid33Bytes() throws Exception {
    factory.validateKeyFormat(
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(33)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA256))
            .build());
  }

  @Test
  public void validateKeyFormat_validWithSalt() throws Exception {
    factory.validateKeyFormat(
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(
                HkdfPrfParams.newBuilder()
                    .setSalt(ByteString.copyFrom(Random.randBytes(5)))
                    .setHash(HashType.SHA256))
            .build());
  }

  @Test
  public void validateKeyFormat_invalidSha1_throws() throws Exception {
    HkdfPrfKeyFormat format =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(32)
            .setParams(HkdfPrfParams.newBuilder().setHash(HashType.SHA1))
            .build();
    assertThrows(GeneralSecurityException.class, () -> factory.validateKeyFormat(format));
  }

  @Test
  public void createKey_valuesAreOk() throws Exception {
    HkdfPrfKeyFormat format =
        HkdfPrfKeyFormat.newBuilder()
            .setKeySize(77)
            .setParams(
                HkdfPrfParams.newBuilder()
                    .setSalt(ByteString.copyFrom(Random.randBytes(5)))
                    .setHash(HashType.SHA256))
            .build();
    HkdfPrfKey key = factory.createKey(format);
    assertThat(key.getVersion()).isEqualTo(0);
    assertThat(key.getKeyValue()).hasSize(77);
    assertThat(key.getParams()).isEqualTo(format.getParams());
  }

  @Test
  public void createPrimitive_works() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.newBuilder()
            .setKeyValue(ByteString.copyFromUtf8("super secret key value"))
            .setParams(
                HkdfPrfParams.newBuilder()
                    .setSalt(ByteString.copyFromUtf8("some salt"))
                    .setHash(HashType.SHA256))
            .build();
    StreamingPrf managerPrf = manager.getPrimitive(key, StreamingPrf.class);
    InputStream managerInput = managerPrf.computePrf("my input".getBytes(UTF_8));
    byte[] managerOutput = new byte[10];
    assertThat(managerInput.read(managerOutput)).isEqualTo(10);

    HkdfStreamingPrf directPrf =
        new HkdfStreamingPrf(
            Enums.HashType.SHA256,
            "super secret key value".getBytes(UTF_8),
            "some salt".getBytes(UTF_8));
    InputStream directInput = directPrf.computePrf("my input".getBytes(UTF_8));

    byte[] directOutput = new byte[10];
    assertThat(directInput.read(directOutput)).isEqualTo(10);

    assertThat(directOutput).isEqualTo(managerOutput);
  }

  /** Smoke test getPrimitive for PrfSet via the HkdfPrfKeymanager. */
  @Test
  public void createPrfSetPrimitive_works() throws Exception {
    HkdfPrfKey key =
        HkdfPrfKey.newBuilder()
            .setKeyValue(ByteString.copyFromUtf8("super secret key value"))
            .setParams(
                HkdfPrfParams.newBuilder()
                    .setSalt(ByteString.copyFromUtf8("some salt"))
                    .setHash(HashType.SHA256))
            .build();
    Object unused = manager.getPrimitive(key, Prf.class);
  }

  @Test
  public void testHkdfSha256Template() throws Exception {
    KeyTemplate kt = HkdfPrfKeyManager.hkdfSha256Template();
    assertThat(kt.toParameters())
        .isEqualTo(
            HkdfPrfParameters.builder()
                .setKeySizeBytes(32)
                .setHashType(HkdfPrfParameters.HashType.SHA256)
                .setSalt(Bytes.copyFrom(new byte[] {}))
                .build());
  }

  @Test
  public void testKeyTemplateAndManagerCompatibility() throws Exception {
    Parameters p = HkdfPrfKeyManager.hkdfSha256Template().toParameters();
    assertThat(KeysetHandle.generateNew(p).getAt(0).getKey().getParameters()).isEqualTo(p);
  }

  @DataPoints("templateNames")
  public static final String[] KEY_TEMPLATES =
      new String[] {
        "HKDF_SHA256",
      };

  @Theory
  public void testTemplates(@FromDataPoints("templateNames") String templateName) throws Exception {
    KeysetHandle h = KeysetHandle.generateNew(KeyTemplates.get(templateName));
    assertThat(h.size()).isEqualTo(1);
    assertThat(h.getAt(0).getKey().getParameters())
        .isEqualTo(KeyTemplates.get(templateName).toParameters());
  }

  @Test
  public void register_registersPrfPrimitiveConstructor() throws Exception {
    HkdfPrfParameters hkdfPrfParameters =
        HkdfPrfParameters.builder()
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .setKeySizeBytes(32)
            .setSalt(Bytes.copyFrom(Random.randBytes(5)))
            .build();
    com.google.crypto.tink.prf.HkdfPrfKey hkdfPrfKey =
        com.google.crypto.tink.prf.HkdfPrfKey.builder()
            .setParameters(hkdfPrfParameters)
            .setKeyBytes(SecretBytes.copyFrom(Random.randBytes(32), InsecureSecretKeyAccess.get()))
            .build();

    Prf prf = MutablePrimitiveRegistry.globalInstance().getPrimitive(hkdfPrfKey, Prf.class);

    assertThat(prf).isNotNull();
  }

  @Test
  public void register_registersStreamingPrfPrimitiveConstructor() throws Exception {
    HkdfPrfParameters hkdfPrfParameters =
        HkdfPrfParameters.builder()
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .setKeySizeBytes(32)
            .setSalt(Bytes.copyFrom(Random.randBytes(5)))
            .build();
    com.google.crypto.tink.prf.HkdfPrfKey hkdfPrfKey =
        com.google.crypto.tink.prf.HkdfPrfKey.builder()
            .setParameters(hkdfPrfParameters)
            .setKeyBytes(SecretBytes.copyFrom(Random.randBytes(32), InsecureSecretKeyAccess.get()))
            .build();

    StreamingPrf streamingPrf =
        MutablePrimitiveRegistry.globalInstance().getPrimitive(hkdfPrfKey, StreamingPrf.class);

    assertThat(streamingPrf).isNotNull();
  }

  @Test
  public void testKeyManagerRegistered() throws Exception {
    assertThat(
            KeyManagerRegistry.globalInstance()
                .getKeyManager("type.googleapis.com/google.crypto.tink.HkdfPrfKey", Prf.class))
        .isNotNull();
  }

  @Test
  public void createKey_works() throws Exception {
    HkdfPrfParameters params =
        HkdfPrfParameters.builder()
            .setHashType(HkdfPrfParameters.HashType.SHA256)
            .setKeySizeBytes(32)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(params);
    assertThat(handle.size()).isEqualTo(1);
    com.google.crypto.tink.prf.HkdfPrfKey key =
        (com.google.crypto.tink.prf.HkdfPrfKey) handle.getAt(0).getKey();
    assertThat(key.getParameters()).isEqualTo(params);
  }

  @Test
  public void createKey_otherParams_works() throws Exception {
    HkdfPrfParameters params =
        HkdfPrfParameters.builder()
            .setHashType(HkdfPrfParameters.HashType.SHA512)
            .setKeySizeBytes(32)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(params);
    assertThat(handle.size()).isEqualTo(1);
    com.google.crypto.tink.prf.HkdfPrfKey key =
        (com.google.crypto.tink.prf.HkdfPrfKey) handle.getAt(0).getKey();
    assertThat(key.getParameters()).isEqualTo(params);
  }

  @Test
  public void createKey_differentKeyValues_alwaysDifferent() throws Exception {
    HkdfPrfParameters params =
        HkdfPrfParameters.builder()
            .setHashType(HkdfPrfParameters.HashType.SHA512)
            .setKeySizeBytes(32)
            .build();

    int numKeys = 100;
    Set<String> keys = new TreeSet<>();
    for (int i = 0; i < numKeys; i++) {
      KeysetHandle handle = KeysetHandle.generateNew(params);
      assertThat(handle.size()).isEqualTo(1);
      com.google.crypto.tink.prf.HkdfPrfKey key =
          (com.google.crypto.tink.prf.HkdfPrfKey) handle.getAt(0).getKey();
      keys.add(Hex.encode(key.getKeyBytes().toByteArray(InsecureSecretKeyAccess.get())));
    }
    assertThat(keys).hasSize(numKeys);
  }

  @Test
  public void createPrimitiveAndUseIt_works() throws Exception {
    HkdfPrfParameters params =
        HkdfPrfParameters.builder()
            .setHashType(HkdfPrfParameters.HashType.SHA512)
            .setKeySizeBytes(32)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(params);
    assertThat(handle.size()).isEqualTo(1);
    PrfSet prfSet = handle.getPrimitive(PrfSet.class);
    Prf directPrf =
        PrfImpl.wrap(
            HkdfStreamingPrf.create(
                (com.google.crypto.tink.prf.HkdfPrfKey) handle.getAt(0).getKey()));
    assertThat(prfSet.computePrimary(new byte[0], 16))
        .isEqualTo(directPrf.compute(new byte[0], 16));
  }

  @Test
  public void serializeAndDeserializeKeysets() throws Exception {
    HkdfPrfParameters params =
        HkdfPrfParameters.builder()
            .setHashType(HkdfPrfParameters.HashType.SHA512)
            .setKeySizeBytes(32)
            .build();
    KeysetHandle handle = KeysetHandle.generateNew(params);

    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    assertTrue(parsed.equalsKeyset(handle));
  }

  @Theory
  public void createKeyWithRejectedParameters_throws(
      @FromDataPoints("KeyManager rejected") HkdfPrfParameters params) throws Exception {
    assertThrows(GeneralSecurityException.class, () -> KeysetHandle.generateNew(params));
  }

  @Theory
  public void createPrimitiveWithRejectedParameters_throws(
      @FromDataPoints("KeyManager rejected") HkdfPrfParameters params) throws Exception {
    com.google.crypto.tink.prf.HkdfPrfKey key =
        com.google.crypto.tink.prf.HkdfPrfKey.builder()
            .setParameters(params)
            .setKeyBytes(SecretBytes.randomBytes(params.getKeySizeBytes()))
            .build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(1).makePrimary())
            .build();
    assertThrows(GeneralSecurityException.class, () -> handle.getPrimitive(PrfSet.class));
  }

  /** We allow serialization and deserialization with parameters which are otherwise rejected */
  @Theory
  public void serializeDeserializeKeysetsWithRejectedParams_works(
      @FromDataPoints("KeyManager rejected") HkdfPrfParameters params) throws Exception {
    com.google.crypto.tink.prf.HkdfPrfKey key =
        com.google.crypto.tink.prf.HkdfPrfKey.builder()
            .setParameters(params)
            .setKeyBytes(SecretBytes.randomBytes(params.getKeySizeBytes()))
            .build();
    KeysetHandle handle =
        KeysetHandle.newBuilder()
            .addEntry(KeysetHandle.importKey(key).withFixedId(1).makePrimary())
            .build();
    byte[] serializedKeyset =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get());
    KeysetHandle parsed =
        TinkProtoKeysetFormat.parseKeyset(serializedKeyset, InsecureSecretKeyAccess.get());
    assertTrue(parsed.equalsKeyset(handle));
  }

  private static HkdfPrfParameters[] createRejectedParameters() {
    return exceptionIsBug(
        () ->
            new HkdfPrfParameters[] {
              // Key Size 16 is rejected
              HkdfPrfParameters.builder()
                  .setHashType(HkdfPrfParameters.HashType.SHA512)
                  .setKeySizeBytes(16)
                  .build(),
              // Only SHA256 and SHA512 are accepted
              HkdfPrfParameters.builder()
                  .setHashType(HkdfPrfParameters.HashType.SHA1)
                  .setKeySizeBytes(32)
                  .build(),
              HkdfPrfParameters.builder()
                  .setHashType(HkdfPrfParameters.HashType.SHA224)
                  .setKeySizeBytes(32)
                  .build(),
              HkdfPrfParameters.builder()
                  .setHashType(HkdfPrfParameters.HashType.SHA384)
                  .setKeySizeBytes(32)
                  .build()
            });
  }

  @DataPoints("KeyManager rejected")
  public static final HkdfPrfParameters[] RECJECTED_PARAMETERS = createRejectedParameters();
}
