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

package com.google.crypto.tink.internal;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyManager;
import com.google.crypto.tink.config.internal.TinkFipsUtil;
import com.google.crypto.tink.proto.KeyData;
import com.google.protobuf.ByteString;
import java.security.GeneralSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for {@link KeyManagerRegistry}. */
@RunWith(JUnit4.class)
public final class KeyManagerRegistryTest {
  private static class Primitive1 {}

  private static class TestKeyManager implements KeyManager<Primitive1> {
    public TestKeyManager(String typeUrl) {
      this.typeUrl = typeUrl;
    }

    private final String typeUrl;

    @Override
    public Primitive1 getPrimitive(ByteString serializedKey) throws GeneralSecurityException {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public KeyData newKeyData(ByteString serializedKeyFormat) throws GeneralSecurityException {
      throw new UnsupportedOperationException("Not needed for test");
    }

    @Override
    public String getKeyType() {
      return this.typeUrl;
    }

    @Override
    public Class<Primitive1> getPrimitiveClass() {
      return Primitive1.class;
    }
  }

  @Test
  public void testEmptyRegistry() throws Exception {
    KeyManagerRegistry registry = new KeyManagerRegistry();
    assertThrows(
        GeneralSecurityException.class, () -> registry.getKeyManager("customTypeUrl", Aead.class));
    assertThrows(
        GeneralSecurityException.class, () -> registry.getUntypedKeyManager("customTypeUrl"));
    assertThat(registry.typeUrlExists("customTypeUrl")).isFalse();
  }

  @Test
  public void testRegisterKeyManager_works() throws Exception {
    assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestKeyManager manager = new TestKeyManager("customTypeUrl");
    registry.registerKeyManager(manager, true);

    assertThat(registry.getKeyManager("customTypeUrl", Primitive1.class)).isSameInstanceAs(manager);
    assertThat(registry.typeUrlExists("customTypeUrl")).isTrue();
  }

  @Test
  public void testRegisterKeyManager_twice_works() throws Exception {
    assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestKeyManager manager1 = new TestKeyManager("customTypeUrl");
    TestKeyManager manager2 = new TestKeyManager("customTypeUrl");
    registry.registerKeyManager(manager1, true);
    registry.registerKeyManager(manager2, true);

    assertThat(registry.getKeyManager("customTypeUrl", Primitive1.class))
        .isAnyOf(manager1, manager2);
  }

  @Test
  public void testRegisterKeyManager_differentManagersSameKeyType_fails() throws Exception {
    assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    registry.registerKeyManager(new TestKeyManager("customTypeUrl"), true);
    // Adding {} at the end makes this an anonymous subclass, hence a different class, so this
    // throws.
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.registerKeyManager(new TestKeyManager("customTypeUrl") {}, true));
  }

  @Test
  public void testRegisterKeyManager_twoKeyTypes_works() throws Exception {
    assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestKeyManager manager1 = new TestKeyManager("customTypeUrl1");
    TestKeyManager manager2 = new TestKeyManager("customTypeUrl2");
    registry.registerKeyManager(manager1, true);
    registry.registerKeyManager(manager2, true);
    assertThat(registry.getKeyManager("customTypeUrl1", Primitive1.class))
        .isSameInstanceAs(manager1);
    assertThat(registry.getKeyManager("customTypeUrl2", Primitive1.class))
        .isSameInstanceAs(manager2);
  }

  @Test
  public void testFipsCompatibleKeyManager_works() throws Exception {
    if (TinkFipsUtil.useOnlyFips()) {
      assumeTrue(
          "If FIPS is required, we can only register managers if the fips module is available",
          TinkFipsUtil.fipsModuleAvailable());
    }

    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestKeyManager manager = new TestKeyManager("customTypeUrl1");
    assertThrows(
        GeneralSecurityException.class, () -> registry.getUntypedKeyManager("customTypeUrl1"));
    registry.registerKeyManagerWithFipsCompatibility(
        manager, TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO, true);
    assertThat(registry.getUntypedKeyManager("customTypeUrl1")).isNotNull();
  }

  @Test
  public void testFipsCompatibleKeyManager_noFipsAvailable_fails() throws Exception {
    assumeTrue(TinkFipsUtil.useOnlyFips());
    assumeFalse(TinkFipsUtil.fipsModuleAvailable());

    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestKeyManager manager = new TestKeyManager("customTypeUrl1");
    assertThrows(
        GeneralSecurityException.class,
        () ->
            registry.registerKeyManagerWithFipsCompatibility(
                manager,
                TinkFipsUtil.AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO,
                true));
  }

  @Test
  public void testTypeUrlExists() throws Exception {
    assumeFalse("Unable to test with KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestKeyManager manager1 = new TestKeyManager("customTypeUrl1");
    TestKeyManager manager2 = new TestKeyManager("customTypeUrl2");
    registry.registerKeyManager(manager1, true);
    registry.registerKeyManager(manager2, true);
    assertThat(registry.typeUrlExists("customTypeUrl1")).isTrue();
    assertThat(registry.typeUrlExists("customTypeUrl2")).isTrue();
    assertThat(registry.typeUrlExists("unknownTypeUrl")).isFalse();
  }

  @Test
  public void testGetKeyManager_works() throws Exception {
    assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    KeyManager<?> registered = new TestKeyManager("typeUrl");
    registry.registerKeyManager(registered, true);
    KeyManager<Primitive1> aeadManager1 = registry.getKeyManager("typeUrl", Primitive1.class);
    KeyManager<?> manager = registry.getUntypedKeyManager("typeUrl");
    assertThat(aeadManager1).isSameInstanceAs(registered);
    assertThat(manager).isSameInstanceAs(registered);
  }

  @Test
  public void testIsNewKeyAllowed_works() throws Exception {
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestKeyManager manager1 = new TestKeyManager("customTypeUrlAllow");
    registry.registerKeyManager(manager1, true);
    TestKeyManager manager2 = new TestKeyManager("customTypeUrlDisallow");
    registry.registerKeyManager(manager2, false);
    assertThat(registry.isNewKeyAllowed("customTypeUrlAllow")).isTrue();
    assertThat(registry.isNewKeyAllowed("customTypeUrlDisallow")).isFalse();
  }

  @Test
  public void testRegisterKeyManager_sameNewKeyAllowed_shouldWork() throws Exception {
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestKeyManager manager = new TestKeyManager("customTypeUrl");
    registry.registerKeyManager(manager, false);
    registry.registerKeyManager(manager, false);
  }

  @Test
  public void testRegisterKeyManager_moreRestrictedNewKeyAllowed_shouldWork() throws Exception {
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestKeyManager manager = new TestKeyManager("customTypeUrl");
    registry.registerKeyManager(manager, true);
    registry.registerKeyManager(manager, false);
  }

  @Test
  public void testRegisterKeyManager_lessRestrictedNewKeyAllowed_shouldThrowException()
      throws Exception {
    // Skip test if in FIPS mode, as registerKeyManager() is not allowed in FipsMode.
    assumeFalse("Unable to test KeyManagers in Fips mode", TinkFipsUtil.useOnlyFips());
    KeyManagerRegistry registry = new KeyManagerRegistry();
    TestKeyManager manager = new TestKeyManager("customTypeUrl");
    registry.registerKeyManager(manager, false);
    assertThrows(GeneralSecurityException.class, () -> registry.registerKeyManager(manager, true));
  }
}
