/*
 * Copyright 2014 Google. Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.k2crypto.keyversions;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.k2crypto.K2Context;
import com.google.k2crypto.K2Exception;
import com.google.k2crypto.exceptions.KeyVersionException;
import com.google.k2crypto.exceptions.UnregisteredKeyVersionException;
import com.google.k2crypto.keyversions.AesKeyVersionProto.AesKeyVersionCore;
import com.google.k2crypto.keyversions.HmacKeyVersionProto.HmacKeyVersionCore;
import com.google.k2crypto.keyversions.KeyVersionProto.Type;
import com.google.k2crypto.keyversions.MockKeyVersionProto.MockKeyVersionCore;
import com.google.protobuf.Descriptors.FieldDescriptor;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.List;

/**
 * Unit tests for the KeyVersionRegistry.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@RunWith(JUnit4.class)
public class KeyVersionRegistryTest {
  
  private K2Context context = null;
 
  /**
   * Creates a context for the tests.
   */
  @Before public final void setUp() {
    context = new K2Context();
  }

  /**
   * Tests registering a bad key version.
   */
  @Test public final void testRegisterBadKeyVersion() {
    KeyVersionRegistry registry = new KeyVersionRegistry(context);
    try {
      registry.register(BadKeyVersion.class);
      fail("Key version should not be installable.");
    } catch (KeyVersionException expected) {
      assertEquals(BadKeyVersion.class, expected.getKeyVersionClass());
    }
    assertEquals(0, registry.getRegisteredKeyVersions().size());
    assertNull(registry.getRegistration(Type.TEST));
  }
  
  // Test "data" for the above
  public static abstract class BadKeyVersion extends MockKeyVersion {
    private BadKeyVersion() {
      super(null);
    }
  }
  
  /**
   * Checks that the specified type is NOT currently registered.
   * 
   * @param registry Registry to query.
   * @param type Type to check.
   * @param fd Field descriptor of the proto-extension associated with the type.
   */
  private void checkNotRegistered(
      KeyVersionRegistry registry, 
      Type type, 
      FieldDescriptor fd) {
    assertNull(registry.getRegistration(type));
    assertFalse(registry.isRegistered(type));
    assertNull(
        registry.getProtoExtensions().findExtensionByName(fd.getFullName()));
    try {
      registry.newBuilder(type);
      fail("Expected unregistered exception.");
    } catch (UnregisteredKeyVersionException expected) {
      assertEquals(type, expected.getType());
    }
    assertFalse(registry.unregister(type));
  }
  
  /**
   * Checks that the specified type is currently registered.
   * 
   * @param registry Registry to query.
   * @param rkv The object returned as a result of registering the key version.
   * @param fd Field descriptor of the proto-extension associated with the type.
   */
  private void checkRegistered(
      KeyVersionRegistry registry, 
      RegisteredKeyVersion rkv,
      FieldDescriptor fd) throws K2Exception {
    Type type = rkv.getType();
    assertEquals(rkv, registry.getRegistration(type));
    assertTrue(registry.isRegistered(type));
    assertEquals(fd, registry
        .getProtoExtensions().findExtensionByName(fd.getFullName()).descriptor);
    assertEquals(
        rkv.getKeyVersionClass(), registry.newBuilder(type).build().getClass());
  }

  /**
   * Tests all relevant methods when registering and unregistering a single key
   * version.
   */
  @Test public final void testOneKeyVersion() throws K2Exception {
    KeyVersionRegistry registry = new KeyVersionRegistry(context);
    final Type type = Type.TEST;
    final FieldDescriptor fd = MockKeyVersionCore.extension.getDescriptor();

    // Check initial state (should be empty)
    assertEquals(0, registry.getRegisteredKeyVersions().size());
    checkNotRegistered(registry, type, fd);
    
    // Register the KV and check it exists
    RegisteredKeyVersion rkv = registry.register(OneKeyVersion.class);
    assertNotNull(rkv);
    assertEquals(OneKeyVersion.class, rkv.getKeyVersionClass());
    checkRegistered(registry, rkv, fd);
    
    List<RegisteredKeyVersion> list = registry.getRegisteredKeyVersions();
    assertEquals(1, list.size());
    assertEquals(rkv, list.get(0));

    // Repeated registration should fail and have no effect
    assertNull(registry.register(OneKeyVersion.class));
    assertEquals(1, registry.getRegisteredKeyVersions().size());

    // Registering another KV with the same type should
    // also fail and have no effect
    assertNull(registry.register(MockKeyVersion.class));
    list = registry.getRegisteredKeyVersions();
    assertEquals(1, list.size());
    assertEquals(rkv, list.get(0));
    checkRegistered(registry, rkv, fd);
    
    // Unregister and check state
    assertTrue(registry.unregister(type));
    assertEquals(0, registry.getRegisteredKeyVersions().size());
    checkNotRegistered(registry, type, fd);

    // The list object should be a copy and be unchanged
    assertEquals(1, list.size());
  }
  
  // Test "data" for the above
  public static class OneKeyVersion extends MockKeyVersion {
    private OneKeyVersion(Builder builder) {
      super(builder);
    }
    public static class Builder extends MockKeyVersion.Builder {
      @Override
      public OneKeyVersion build() {
        return new OneKeyVersion(this);
      }
    }
  }
  
  /**
   * Tests all relevant methods when registering and unregistering several key
   * versions.
   */
  @Test public final void testSeveralKeyVersions() throws K2Exception {

    // Register three different KVs
    KeyVersionRegistry registry = new KeyVersionRegistry(context);
    final FieldDescriptor aesFd = AesKeyVersionCore.extension.getDescriptor(); 
    RegisteredKeyVersion aesRkv = registry.register(TestAesKeyVersion.class);
    assertEquals(TestAesKeyVersion.class, aesRkv.getKeyVersionClass());

    final FieldDescriptor mockFd = MockKeyVersionCore.extension.getDescriptor(); 
    RegisteredKeyVersion mockRkv = registry.register(MockKeyVersion.class); 
    assertEquals(MockKeyVersion.class, mockRkv.getKeyVersionClass());

    final FieldDescriptor hmacFd = HmacKeyVersionCore.extension.getDescriptor(); 
    RegisteredKeyVersion hmacRkv = registry.register(TestHmacKeyVersion.class); 
    assertEquals(TestHmacKeyVersion.class, hmacRkv.getKeyVersionClass());

    // Make sure they exist and are in the right order
    checkRegistered(registry, aesRkv, aesFd);
    checkRegistered(registry, mockRkv, mockFd);
    checkRegistered(registry, hmacRkv, hmacFd);
    List<RegisteredKeyVersion> list = registry.getRegisteredKeyVersions();
    assertEquals(3, list.size());
    assertEquals(TestAesKeyVersion.class, list.get(0).getKeyVersionClass());
    assertEquals(MockKeyVersion.class, list.get(1).getKeyVersionClass());
    assertEquals(TestHmacKeyVersion.class, list.get(2).getKeyVersionClass());
    
    // Remove the middle one and check again
    assertTrue(registry.unregister(Type.TEST));
    
    checkRegistered(registry, aesRkv, aesFd);
    checkNotRegistered(registry, Type.TEST, mockFd);
    checkRegistered(registry, hmacRkv, hmacFd);
    list = registry.getRegisteredKeyVersions();
    assertEquals(2, list.size());
    assertEquals(TestAesKeyVersion.class, list.get(0).getKeyVersionClass());
    assertEquals(TestHmacKeyVersion.class, list.get(1).getKeyVersionClass());

    // Re-register the middle one (should be at the end now)
    mockRkv = registry.register(MockKeyVersion.class);
    assertNotNull(mockRkv);
    
    checkRegistered(registry, mockRkv, mockFd);
    list = registry.getRegisteredKeyVersions();
    assertEquals(3, list.size());
    assertEquals(TestAesKeyVersion.class, list.get(0).getKeyVersionClass());
    assertEquals(TestHmacKeyVersion.class, list.get(1).getKeyVersionClass());
    assertEquals(MockKeyVersion.class, list.get(2).getKeyVersionClass());
    
    // Unregister all KVs
    assertTrue(registry.unregister(Type.AES));
    assertTrue(registry.unregister(Type.HMAC));
    assertTrue(registry.unregister(Type.TEST));
    
    // Verify empty state
    checkNotRegistered(registry, Type.AES, aesFd);
    checkNotRegistered(registry, Type.TEST, mockFd);
    checkNotRegistered(registry, Type.HMAC, hmacFd);    
    assertEquals(0, registry.getRegisteredKeyVersions().size());
    
    // Again, the previously obtained list should be a copy and be unchanged
    assertEquals(3, list.size());
  }

  // Test "data" for the above
  @KeyVersionInfo(
      type = Type.AES, proto = AesKeyVersionProto.class)
  public static class TestAesKeyVersion extends KeyVersion {
    private TestAesKeyVersion(Builder builder) {
      super(builder);
    }
    public static class Builder extends KeyVersion.Builder {
      @Override
      public TestAesKeyVersion build() {
        return new TestAesKeyVersion(this);
      }
    }
  }

  // Test "data" for the above
  @KeyVersionInfo(
      type = Type.HMAC, proto = HmacKeyVersionProto.class)
  public static class TestHmacKeyVersion extends KeyVersion {
    private TestHmacKeyVersion(Builder builder) {
      super(builder);
    }
    public static class Builder extends KeyVersion.Builder {
      @Override
      public TestHmacKeyVersion build() {
        return new TestHmacKeyVersion(this);
      }
    }
  }

  /**
   * Tests that all methods throw up on a null argument. 
   */
  @Test public final void testNullArguments() throws K2Exception {
    KeyVersionRegistry registry = new KeyVersionRegistry(context);
    try {
      registry.register(null);
      fail();
    } catch (NullPointerException expected) {
      assertEquals("kvClass", expected.getMessage());
    }
    try {
      registry.unregister(null);
      fail();
    } catch (NullPointerException expected) {
      assertEquals("type", expected.getMessage());
    }
    try {
      registry.getRegistration(null);
      fail();
    } catch (NullPointerException expected) {
      assertEquals("type", expected.getMessage());
    }
    try {
      registry.isRegistered(null);
      fail();
    } catch (NullPointerException expected) {
      assertEquals("type", expected.getMessage());
    }
    try {
      registry.newBuilder(null);
      fail();
    } catch (NullPointerException expected) {
      assertEquals("type", expected.getMessage());
    }
  }
}
