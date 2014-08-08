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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.google.k2crypto.K2Context;
import com.google.k2crypto.K2Exception;
import com.google.k2crypto.exceptions.KeyVersionException;
import com.google.protobuf.Descriptors.FieldDescriptor;
import com.google.protobuf.ExtensionRegistry;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for a RegisteredKeyVersion.
 * 
 * <p>We want to make sure that the class rejects all badly-implemented
 * KeyVersion sub-classes, while also accepting oddly-implemented but legal
 * sub-classes.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@RunWith(JUnit4.class)
public class RegisteredKeyVersionTest {
  
  private K2Context context = null;
 
  /**
   * Creates a context for the tests.
   */
  @Before public final void setUp() {
    context = new K2Context();
  }

  /**
   * Tests rejection when the context to the constructor is null. 
   */
  @Test public final void testRejectNullContext() throws K2Exception {
    Class<? extends KeyVersion> kvClass = MockKeyVersion.class; 
    try {
      new RegisteredKeyVersion(null, kvClass);
      fail("Expected NullPointerException of context.");
    } catch (NullPointerException expected) {
      assertEquals("context", expected.getMessage());
    }
  }
  
  /**
   * Tests rejection when the key version class to the constructor is null. 
   */
  @Test public final void testRejectNullKeyVersionClass() throws K2Exception {
    try {
      new RegisteredKeyVersion(context, null);
      fail("Expected NullPointerException of kvClass.");
    } catch (NullPointerException expected) {
      assertEquals("kvClass", expected.getMessage());
    }
  }

  /**
   * Utility to verify that a key version implemented is accepted. 
   * 
   * @param kvClass Class of the key version.
   * @param kvBuilderClass Builder of the key version.
   * 
   * @return the RegisteredKeyVersion that accepted the implementation,
   *         for further checking.
   * 
   * @throws KeyVersionException if the key version is rejected.
   */
  private RegisteredKeyVersion checkAcceptRegistration(
      Class<? extends KeyVersion> kvClass,
      Class<? extends KeyVersion.Builder> kvBuilderClass)
          throws KeyVersionException {
    assertTrue(kvClass.equals(kvBuilderClass.getEnclosingClass()));
    RegisteredKeyVersion rkv = new RegisteredKeyVersion(context, kvClass);
    assertEquals(kvClass, rkv.getKeyVersionClass());
    assertEquals(kvBuilderClass, rkv.getBuilderClass());
    assertEquals(kvBuilderClass, rkv.newBuilder().getClass());
    return rkv;
  }

  /**
   * Utility to verify that a key version implementation is rejected for the
   * specified reason.
   * 
   * @param kvClass Key version class to check.
   * @param reason Reason for the rejection.
   * @param failMessage Assertion message used if the key version is
   *                    NOT rejected.
   */
  private void checkRejectRegistration(
      Class<? extends KeyVersion> kvClass,
      KeyVersionException.Reason reason,
      String failMessage) {
    try {
      new RegisteredKeyVersion(context, kvClass);
      fail(failMessage);
    } catch (KeyVersionException expected) {
      assertEquals(kvClass, expected.getKeyVersionClass());
      assertEquals(reason, expected.getReason());
    }
  }
  
  /**
   * Tests successful verification of a valid implementation and basic
   * functionality.
   */
  @Test public final void testAcceptValid()
      throws K2Exception, ReflectiveOperationException {
    
    // Verify basic acceptance
    RegisteredKeyVersion rkv = checkAcceptRegistration(
        MockKeyVersion.class, MockKeyVersion.Builder.class);
    
    // Verify return values of various access methods  
    assertEquals(context, rkv.getContext());
    assertEquals(KeyVersionProto.Type.TEST, rkv.getType());
    assertEquals(MockKeyVersionProto.class, rkv.getProtoClass());
    assertEquals(MockKeyVersion.class.hashCode(), rkv.hashCode());
    
    // Make sure protobuf extensions get registered
    ExtensionRegistry registry = ExtensionRegistry.newInstance();
    rkv.registerProtoExtensions(registry);
    FieldDescriptor fd;
    fd = MockKeyVersionProto.MockKeyVersionCore.extension.getDescriptor();
    assertEquals(fd, registry.findExtensionByName(fd.getFullName()).descriptor);
    fd = MockKeyVersionProto.MockKeyVersionData.extension.getDescriptor();
    assertEquals(fd, registry.findExtensionByName(fd.getFullName()).descriptor);
  }

  /**
   * Tests rejection of a key version without a builder inner-class.
   */
  @Test public final void testRejectMissingBuilder() {
    checkRejectRegistration(
        KVWithoutBuilder.class, 
        KeyVersionException.Reason.NO_BUILDER, 
        "Key versions without a Builder inner-class should be rejected.");
  }

  // Test "data" for the above
  public static class KVWithoutBuilder extends MockKeyVersion {
    public KVWithoutBuilder(Builder builder) {
      super(builder);
    }
  }
  
  /**
   * Tests rejection of a key version builder without a
   * zero-argument constructor.
   */
  @Test public final void testRejectMissingBuilderConstructor() {
    checkRejectRegistration(
        KVWithMissingBuilderConstructor.class, 
        KeyVersionException.Reason.NO_CONSTRUCTOR, 
        "Key version builders without a zero-argument constructor "
            + "should be rejected.");
  }

  // Test "data" for the above
  public static class KVWithMissingBuilderConstructor extends MockKeyVersion {
    public KVWithMissingBuilderConstructor(Builder builder) {
      super(builder);
    }
    public static class Builder extends MockKeyVersion.Builder {
      public Builder(@SuppressWarnings("unused") Object obj) {}
      @Override public KVWithMissingBuilderConstructor build() {
        return null;
      }
    }
  }

  /**
   * Tests rejection of a key version builder NOT extending KeyVersion.Builder.
   */
  @Test public final void testRejectWrongBuilderParent() {
    checkRejectRegistration(
        KVWithWrongBuilderParent.class, 
        KeyVersionException.Reason.BAD_PARENT, 
        "Key version builders not extending KeyVersion.Builder "
            + "should be rejected.");
  }

  // Test "data" for the above
  public static class KVWithWrongBuilderParent extends MockKeyVersion {
    public KVWithWrongBuilderParent(MockKeyVersion.Builder builder) {
      super(builder);
    }
    public static class Builder {
      public KVWithWrongBuilderParent build() {
        return null;
      }
    }
  }

  /**
   * Tests rejection of a key version builder that does not build() a key
   * version of the enclosing class type. 
   */
  @Test public final void testRejectBadBuildMethod() {
    checkRejectRegistration(
        KVWithBadBuildMethod.class, 
        KeyVersionException.Reason.BAD_BUILD, 
        "Key version builders that don't build the specified key version "
            + "should be rejected.");
  }

  // Test "data" for the above
  public static class KVWithBadBuildMethod extends MockKeyVersion {
    public KVWithBadBuildMethod(Builder builder) {
      super(builder);
    }
    public static class Builder extends MockKeyVersion.Builder {
      @Override public MockKeyVersion build() {
        return null;
      }
    }
  }
  
  /**
   * Tests acceptance of an abstract key version (only the Builder need not
   * be abstract). 
   */
  @Test public final void testAcceptAbstract() throws K2Exception {
    checkAcceptRegistration(
        AbstractKeyVersion.class, 
        AbstractKeyVersion.Builder.class);
  }

  // Test "data" for the above
  public static abstract class AbstractKeyVersion extends MockKeyVersion {
    private AbstractKeyVersion(Builder builder) {
      super(builder);
    }
    public static class Builder extends MockKeyVersion.Builder {
      @Override public AbstractKeyVersion build() {
        return new AbstractKeyVersion(this) {};
      }
    }
  }
  
  /**
   * Tests rejection of an abstract key version builder.
   */
  @Test public final void testRejectAbstractBuilder() {
    checkRejectRegistration(
        KVWithAbstractBuilder.class,
        KeyVersionException.Reason.INSTANTIATE_FAIL,
        "Key version with abstract builders should be rejected.");
  }

  // Test "data" for the above
  public static class KVWithAbstractBuilder extends MockKeyVersion {
    private KVWithAbstractBuilder(Builder builder) {
      super(builder);
    }
    public static abstract class Builder extends MockKeyVersion.Builder {
      @Override public KVWithAbstractBuilder build() {
        return null;
      }
    }
  }
  
  /**
   * Tests acceptance of a private key version builder with a package-protected
   * constructor. (Yes, this works.) 
   */
  @Test public final void testAcceptPrivateBuilder() throws K2Exception {
    checkAcceptRegistration(
        KVWithPrivateBuilder.class, 
        KVWithPrivateBuilder.Builder.class);
  }

  // Test "data" for the above
  public static class KVWithPrivateBuilder extends MockKeyVersion {
    private KVWithPrivateBuilder(Builder builder) {
      super(builder);
    }
    private static class Builder extends MockKeyVersion.Builder {
      @SuppressWarnings("unused") Builder() {}
      @Override public KVWithPrivateBuilder build() {
        return new KVWithPrivateBuilder(this);
      }
    }
  }

  /**
   * Tests rejection of a key version builder with a private constructor.
   */
  @Test public final void testRejectPrivateConstructorBuilder() {
    checkRejectRegistration(
        KVWithPrivateConstructorBuilder.class,
        KeyVersionException.Reason.INSTANTIATE_FAIL,
        "Key version builders with private constructors should be rejected.");
  }
  
  // Test "data" for the above
  public static class KVWithPrivateConstructorBuilder extends MockKeyVersion {
    private KVWithPrivateConstructorBuilder(Builder builder) {
      super(builder);
    }
    public static class Builder extends MockKeyVersion.Builder {
      private Builder() {}
      @Override public KVWithPrivateConstructorBuilder build() {
        return null;
      }
    }
  }

  /**
   * Tests rejection of a key version builder with a constructor that throws
   * illegal throwables.
   */
  @Test public final void testRejectConstructorWithBadThrowables() {
    checkRejectRegistration(
        KVWithBadThrowablesBuilder.class,
        KeyVersionException.Reason.ILLEGAL_THROWS,
        "Key version builders with constructors throwing throwables other "
            + "than Error and RuntimeException should be rejected.");
  }
  
  // Test "data" for the above
  public static class KVWithBadThrowablesBuilder extends MockKeyVersion {
    private KVWithBadThrowablesBuilder(Builder builder) {
      super(builder);
    }
    public static class Builder extends MockKeyVersion.Builder {
      public Builder() throws Exception, Throwable {}
      @Override public KVWithBadThrowablesBuilder build() {
        return null;
      }
    }
  }
  
  /**
   * Test acceptance of a key version builder with a constructor that throws
   * entirely legal throwables.
   */
  @Test public final void testAcceptConstructorWithLegalThrowables()
      throws K2Exception {
    checkAcceptRegistration(
        KVWithLegalThrowablesBuilder.class,
        KVWithLegalThrowablesBuilder.Builder.class);
  }

  // Test "data" for the above
  public static class KVWithLegalThrowablesBuilder extends MockKeyVersion {
    private KVWithLegalThrowablesBuilder(Builder builder) {
      super(builder);
    }
    public static class Builder extends MockKeyVersion.Builder {
      public Builder() throws Error, RuntimeException {}
      @Override public KVWithLegalThrowablesBuilder build() {
        return new KVWithLegalThrowablesBuilder(this);
      }
    }
  }
  
  /**
   * Tests rejection of a key version without the meta-data annotation.
   */
  @Test public final void testRejectMissingAnnotation() {
    checkRejectRegistration(
        KVWithoutAnnotation.class,
        KeyVersionException.Reason.NO_METADATA,
        "Key version builders without the KeyVersionInfo annotation "
            + "should be rejected.");
  }
  
  // Test "data" for the above
  public static class KVWithoutAnnotation extends KeyVersion {
    private KVWithoutAnnotation(Builder builder) {
      super(builder);
    }
    public static class Builder extends KeyVersion.Builder {
      @Override public KVWithoutAnnotation build() {
        return null;
      }
    }
  }
  
  /**
   * Tests rejection of a key version that specifies an invalid protobuf class.
   */
  @Test public final void testRejectBadProto() {
    checkRejectRegistration(
        KVWithObjectProto.class,
        KeyVersionException.Reason.BAD_PROTO,
        "Key versions not specifying a valid proto should be rejected.");
    checkRejectRegistration(
        KVWithSelfProto.class,
        KeyVersionException.Reason.BAD_PROTO,
        "Key versions specifying a proto with a non-static register"
            + "extensions method should be rejected.");
  }

  // Test "data" for the above
  @KeyVersionInfo(
      type = KeyVersionProto.Type.TEST, proto = Object.class)
  public static class KVWithObjectProto extends KeyVersion {
    private KVWithObjectProto(Builder builder) {
      super(builder);
    }
    public static class Builder extends KeyVersion.Builder {
      @Override public KVWithObjectProto build() {
        return null;
      }
    }
  }

  // Test "data" for the above
  @KeyVersionInfo(
      type = KeyVersionProto.Type.TEST, proto = KVWithSelfProto.class)
  public static class KVWithSelfProto extends KeyVersion {
    private KVWithSelfProto(Builder builder) {
      super(builder);
    }
    public void registerAllExtensions(
        @SuppressWarnings("unused") ExtensionRegistry registry) {}
    public static class Builder extends KeyVersion.Builder {
      @Override public KVWithSelfProto build() {
        return null;
      }
    }
  }
}
