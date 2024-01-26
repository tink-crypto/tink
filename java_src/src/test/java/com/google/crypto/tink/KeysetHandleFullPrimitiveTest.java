// Copyright 2022 Google LLC
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

package com.google.crypto.tink;

import static com.google.common.truth.Truth.assertThat;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.PrimitiveSet.Entry;
import com.google.crypto.tink.internal.KeyParser;
import com.google.crypto.tink.internal.KeySerializer;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.PrimitiveConstructor;
import com.google.crypto.tink.internal.ProtoKeySerialization;
import com.google.crypto.tink.mac.AesCmacKey;
import com.google.crypto.tink.mac.AesCmacParameters;
import com.google.crypto.tink.mac.AesCmacParameters.Variant;
import com.google.crypto.tink.mac.MacConfig;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.crypto.tink.proto.OutputPrefixType;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import java.util.List;
import javax.annotation.Nullable;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Tests how {@link KeysetHandle} handles the situation when there is a {@link
 * PrimitiveSet#fullPrimitive} registered.
 */
@RunWith(JUnit4.class)
public class KeysetHandleFullPrimitiveTest {

  private static final PrimitiveConstructor<TestKey, SingleTestPrimitive>
      TEST_PRIMITIVE_CONSTRUCTOR =
          PrimitiveConstructor.create(
              KeysetHandleFullPrimitiveTest::createTestPrimitive,
              TestKey.class,
              SingleTestPrimitive.class);
  public static final KeySerializer<TestKey, ProtoKeySerialization> TEST_KEY_SERIALIZER =
      KeySerializer.create(
          KeysetHandleFullPrimitiveTest::serializeTestKey,
          TestKey.class,
          ProtoKeySerialization.class);
  public static final KeyParser<ProtoKeySerialization> TEST_KEY_PARSER =
      KeyParser.create(
          KeysetHandleFullPrimitiveTest::parseTestKey,
          Bytes.copyFrom("testKeyForFullPrimitiveUrl".getBytes(UTF_8)),
          ProtoKeySerialization.class);

  private static class SingleTestPrimitive {}

  /**
   * In combination with {@link KeysetHandleFullPrimitiveTest#TestWrapper}, this test primitive lets
   * us check some assumptions about the {@link PrimitiveSet} which was created by the {@link
   * KeysetHandle}.
   */
  private static class WrappedTestPrimitive {

    private final PrimitiveSet<SingleTestPrimitive> primitiveSet;

    WrappedTestPrimitive(PrimitiveSet<SingleTestPrimitive> primitiveSet) {
      this.primitiveSet = primitiveSet;
    }

    PrimitiveSet<SingleTestPrimitive> getPrimitiveSet() {
      return primitiveSet;
    }
  }

  private static class TestWrapper
      implements PrimitiveWrapper<SingleTestPrimitive, WrappedTestPrimitive> {

    private static final TestWrapper WRAPPER = new TestWrapper();

    @Override
    public WrappedTestPrimitive wrap(PrimitiveSet<SingleTestPrimitive> primitiveSet)
        throws GeneralSecurityException {
      return new WrappedTestPrimitive(primitiveSet);
    }

    @Override
    public Class<WrappedTestPrimitive> getPrimitiveClass() {
      return WrappedTestPrimitive.class;
    }

    @Override
    public Class<SingleTestPrimitive> getInputPrimitiveClass() {
      return SingleTestPrimitive.class;
    }

    public static void register() throws GeneralSecurityException {
      MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    }
  }

  private static final class TestKey extends Key {

    private final int id;

    TestKey(int id) {
      this.id = id;
    }

    @Override
    public Parameters getParameters() {
      throw new UnsupportedOperationException("Not needed in test");
    }

    @Override
    public Integer getIdRequirementOrNull() {
      return id;
    }

    @Override
    public boolean equalsKey(Key other) {
      throw new UnsupportedOperationException("Not needed in test");
    }

    public int getId() {
      return id;
    }
  }

  private static ProtoKeySerialization serializeTestKey(
      TestKey key, @Nullable SecretKeyAccess access) throws GeneralSecurityException {
    return ProtoKeySerialization.create(
        "testKeyForFullPrimitiveUrl",
        ByteString.EMPTY,
        KeyMaterialType.ASYMMETRIC_PUBLIC,
        OutputPrefixType.TINK,
        key.getId());
  }

  private static TestKey parseTestKey(
      ProtoKeySerialization serialization, @Nullable SecretKeyAccess access) {
    return new TestKey(serialization.getIdRequirementOrNull());
  }

  private static SingleTestPrimitive createTestPrimitive(TestKey key)
      throws GeneralSecurityException {
    return new SingleTestPrimitive();
  }

  /**
   * In combination with {@link KeysetHandleFullPrimitiveTest#MacTestWrapper}, this test primitive
   * lets us check some assumptions about the {@link PrimitiveSet} which was created by the {@link
   * KeysetHandle}.
   */
  private static class WrappedMacTestPrimitive {

    private final PrimitiveSet<Mac> primitiveSet;

    WrappedMacTestPrimitive(PrimitiveSet<Mac> primitiveSet) {
      this.primitiveSet = primitiveSet;
    }

    PrimitiveSet<Mac> getPrimitiveSet() {
      return primitiveSet;
    }
  }

  private static class MacTestWrapper implements PrimitiveWrapper<Mac, WrappedMacTestPrimitive> {

    private static final MacTestWrapper WRAPPER = new MacTestWrapper();

    @Override
    public WrappedMacTestPrimitive wrap(PrimitiveSet<Mac> primitiveSet)
        throws GeneralSecurityException {
      return new WrappedMacTestPrimitive(primitiveSet);
    }

    @Override
    public Class<WrappedMacTestPrimitive> getPrimitiveClass() {
      return WrappedMacTestPrimitive.class;
    }

    @Override
    public Class<Mac> getInputPrimitiveClass() {
      return Mac.class;
    }

    public static void register() throws GeneralSecurityException {
      MutablePrimitiveRegistry.globalInstance().registerPrimitiveWrapper(WRAPPER);
    }
  }

  @Test
  public void getPrimitive_fullPrimitiveWithoutPrimitive_worksCorrectly() throws Exception {
    Registry.reset();
    MutableSerializationRegistry.globalInstance().registerKeySerializer(TEST_KEY_SERIALIZER);
    MutableSerializationRegistry.globalInstance().registerKeyParser(TEST_KEY_PARSER);
    MutablePrimitiveRegistry.globalInstance()
        .registerPrimitiveConstructor(TEST_PRIMITIVE_CONSTRUCTOR);
    TestWrapper.register();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(new TestKey(1234))
                    .setStatus(KeyStatus.ENABLED)
                    .withFixedId(1234)
                    .makePrimary())
            .addEntry(
                KeysetHandle.importKey(new TestKey(1235))
                    .setStatus(KeyStatus.ENABLED)
                    .withFixedId(1235))
            .addEntry(
                KeysetHandle.importKey(new TestKey(1236))
                    .setStatus(KeyStatus.ENABLED)
                    .withFixedId(1236))
            .addEntry(
                KeysetHandle.importKey(new TestKey(1237))
                    .setStatus(KeyStatus.ENABLED)
                    .withFixedId(1237))
            .build();

    WrappedTestPrimitive primitive = keysetHandle.getPrimitive(WrappedTestPrimitive.class);

    for (List<Entry<SingleTestPrimitive>> list : primitive.getPrimitiveSet().getAll()) {
      for (PrimitiveSet.Entry<SingleTestPrimitive> entry : list) {
        assertThat(entry.getFullPrimitive()).isNotNull();
        assertThat(entry.getPrimitive()).isNull();
      }
    }
  }

  @Test
  public void getPrimitive_noFullPrimitiveNoPrimitive_throws() throws Exception {
    Registry.reset();
    MutableSerializationRegistry.globalInstance().registerKeySerializer(TEST_KEY_SERIALIZER);
    MutableSerializationRegistry.globalInstance().registerKeyParser(TEST_KEY_PARSER);
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(new TestKey(1234))
                    .setStatus(KeyStatus.ENABLED)
                    .withFixedId(1234)
                    .makePrimary())
            .addEntry(
                KeysetHandle.importKey(new TestKey(1235))
                    .setStatus(KeyStatus.ENABLED)
                    .withFixedId(1235))
            .addEntry(
                KeysetHandle.importKey(new TestKey(1236))
                    .setStatus(KeyStatus.ENABLED)
                    .withFixedId(1236))
            .addEntry(
                KeysetHandle.importKey(new TestKey(1237))
                    .setStatus(KeyStatus.ENABLED)
                    .withFixedId(1237))
            .build();

    assertThrows(
        GeneralSecurityException.class,
        () -> keysetHandle.getPrimitive(WrappedTestPrimitive.class));
  }

  @Test
  public void getPrimitive_fullPrimitiveWithPrimitive_worksCorrectly() throws Exception {
    Registry.reset();
    MacTestWrapper.register();
    MacConfig.register();
    AesCmacParameters parameters =
        AesCmacParameters.builder()
            .setKeySizeBytes(32)
            .setTagSizeBytes(10)
            .setVariant(Variant.TINK)
            .build();
    KeysetHandle keysetHandle =
        KeysetHandle.newBuilder()
            .addEntry(
                KeysetHandle.importKey(
                        AesCmacKey.builder()
                            .setParameters(parameters)
                            .setAesKeyBytes(SecretBytes.randomBytes(32))
                            .setIdRequirement(1234)
                            .build())
                    .setStatus(KeyStatus.ENABLED)
                    .withFixedId(1234)
                    .makePrimary())
            .addEntry(
                KeysetHandle.importKey(
                        AesCmacKey.builder()
                            .setParameters(parameters)
                            .setAesKeyBytes(SecretBytes.randomBytes(32))
                            .setIdRequirement(1235)
                            .build())
                    .setStatus(KeyStatus.ENABLED)
                    .withFixedId(1235))
            .addEntry(
                KeysetHandle.importKey(
                        AesCmacKey.builder()
                            .setParameters(parameters)
                            .setAesKeyBytes(SecretBytes.randomBytes(32))
                            .setIdRequirement(1236)
                            .build())
                    .setStatus(KeyStatus.ENABLED)
                    .withFixedId(1236))
            .addEntry(
                KeysetHandle.importKey(
                        AesCmacKey.builder()
                            .setParameters(parameters)
                            .setAesKeyBytes(SecretBytes.randomBytes(32))
                            .setIdRequirement(1237)
                            .build())
                    .setStatus(KeyStatus.ENABLED)
                    .withFixedId(1237))
            .build();

    WrappedMacTestPrimitive primitive = keysetHandle.getPrimitive(WrappedMacTestPrimitive.class);

    for (List<Entry<Mac>> list : primitive.getPrimitiveSet().getAll()) {
      for (PrimitiveSet.Entry<Mac> entry : list) {
        assertThat(entry.getFullPrimitive()).isNotNull();
        assertThat(entry.getPrimitive()).isNotNull();
      }
    }
  }
}
