// Copyright 2019 Google LLC
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

import com.google.crypto.tink.annotations.Alpha;
import com.google.crypto.tink.proto.KeyData.KeyMaterialType;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * An object which collects all the operations which one can do on for a single key type, identified
 * by a single KeyProto.
 *
 * <p>A KeyTypeManager manages all the operations one can do on a given KeyProto. This includes
 * generating primitives, generating keys (if applicable), parsing and validating keys and key
 * formats. This object is meant to be implemented, i.e., one should use it via the {@link
 * Registry}, and not directly.
 *
 * <p>In order to implement a new key manager, one should subclass this class, setting the type
 * parameter to the proto of the corresponding key (e.g., subclass {@code
 * KeyTypeManager<AesGcmKey>}).
 *
 * <p>For each primitive the key manager should implement, one needs to add an argument to the
 * constructor. The type of it should be a {@code PrimitiveFactory<PrimitiveT, KeyT>}, an object
 * which knows how to produce primitives.
 *
 * <p>If the key manager can create new keys, one also needs to implement the method {@code
 * #keyFactory}. In this case it needs to return an object of type {@code KeyFactory<KeyFormatProto,
 * KeyProtoT>}, where one has to specify a proto for the key format as well.
 */
@Alpha
public abstract class KeyTypeManager<KeyProtoT extends MessageLite> {
  /** A PrimitiveFactory knows how to create primitives from a given key. */
  protected abstract static class PrimitiveFactory<PrimitiveT, KeyT> {
    private final Class<PrimitiveT> clazz;

    public PrimitiveFactory(Class<PrimitiveT> clazz) {
      this.clazz = clazz;
    }

    /**
     * Returns the class object corresponding to the generic parameter {@code PrimitiveT}.
     */
    final Class<PrimitiveT> getPrimitiveClass() {
      return clazz;
    }

    /** Creates a new instance of {@code PrimitiveT}. */
    public abstract PrimitiveT getPrimitive(KeyT key) throws GeneralSecurityException;
  }

  private final Class<KeyProtoT> clazz;

  private final Map<Class<?>, PrimitiveFactory<?, KeyProtoT>> factories;
  private final Class<?> firstPrimitiveClass;

  /**
   * Constructs a new KeyTypeManager.
   *
   * <p>Takes an arbitrary number of {@link PrimitiveFactory} objects as input. These will be used
   * and provided via {@link #getPrimitive} to the user.
   *
   * @throws IllegalArgumentException if two of the passed in factories produce primitives of the
   *     same class.
   */
  @SafeVarargs // Safe because we do not reference the array (see Effective Java ed. 3, Item 32).
  protected KeyTypeManager(Class<KeyProtoT> clazz, PrimitiveFactory<?, KeyProtoT>... factories) {
    this.clazz = clazz;
    Map<Class<?>, PrimitiveFactory<?, KeyProtoT>> factoriesMap = new HashMap<>();
    for (PrimitiveFactory<?, KeyProtoT> factory : factories) {
      if (factoriesMap.containsKey(factory.getPrimitiveClass())) {
        throw new IllegalArgumentException(
            "KeyTypeManager constructed with duplicate factories for primitive "
                + factory.getPrimitiveClass().getCanonicalName());
      }
      factoriesMap.put(factory.getPrimitiveClass(), factory);
    }
    if (factories.length > 0) {
      this.firstPrimitiveClass = factories[0].getPrimitiveClass();
    } else {
      this.firstPrimitiveClass = Void.class;
    }
    this.factories = Collections.unmodifiableMap(factoriesMap);
  }

  /** Returns the class corresponding to the key protobuffer. */
  public final Class<KeyProtoT> getKeyClass() {
    return clazz;
  }

  /** Returns the type URL that identifies the key type of keys managed by this KeyManager. */
  public abstract String getKeyType();

  /** Returns the version number of this KeyManager. */
  public abstract int getVersion();

  /** Returns the {@link KeyMaterialType} for this proto. */
  public abstract KeyMaterialType keyMaterialType();

  /**
   * Parses a serialized key proto.
   *
   * <p>Implement as {@code return KeyProtoT.parseFrom(byteString);}.
   */
  public abstract KeyProtoT parseKey(ByteString byteString) throws InvalidProtocolBufferException;

  /**
   * Checks if the given {@code keyProto} is a valid key.
   *
   * @throws GeneralSecurityException if the passed {@code keyProto} is not valid in any way.
   */
  public abstract void validateKey(KeyProtoT keyProto) throws GeneralSecurityException;

  /**
   * Creates the requested primitive.
   *
   * @throws java.lang.IllegalArgumentException if the given {@code primitiveClass} is not supported
   *     (i.e., not returned by {@link #supportedPrimitives}.
   * @throws GeneralSecurityException if the underlying factory throws a GeneralSecurityException
   *     creating the primitive.
   */
  public final <P> P getPrimitive(KeyProtoT key, Class<P> primitiveClass)
      throws GeneralSecurityException {
    @SuppressWarnings("unchecked") //  factories maps Class<P> to PrimitiveFactory<P, KeyProtoT>.
    PrimitiveFactory<P, KeyProtoT> factory =
        (PrimitiveFactory<P, KeyProtoT>) factories.get(primitiveClass);
    if (factory == null) {
      throw new IllegalArgumentException(
          "Requested primitive class " + primitiveClass.getCanonicalName() + " not supported.");
    }
    return factory.getPrimitive(key);
  }

  /**
   * Returns a set containing the supported primitives.
   */
  public final Set<Class<?>> supportedPrimitives() {
    return factories.keySet();
  }

  /**
   * Returns the first class object of the first supported primitive, or {@code Class<Void>} if the
   * key manager supports no primitive at all.
   */
  final Class<?> firstSupportedPrimitiveClass() {
    return firstPrimitiveClass;
  }

  /**
   * A {@code KeyFactory} creates new keys from a given KeyFormat.
   *
   * <p>A KeyFactory implements all the methods which are required if a KeyTypeManager should also
   * be able to generate keys. In particular, in this case it needs to have some KeyFormat protocol
   * buffer which can be validated, parsed, and from which a key can be generated.
   */
  public abstract static class KeyFactory<KeyFormatProtoT extends MessageLite, KeyT> {
    private final Class<KeyFormatProtoT> clazz;
    public KeyFactory(Class<KeyFormatProtoT> clazz) {
      this.clazz = clazz;
    }

    /**
     * A container that contains key format and other information that form key templates supported
     * by this factory.
     */
    public static final class KeyFormat<KeyFormatProtoT> {
      public KeyFormatProtoT keyFormat;
      public KeyTemplate.OutputPrefixType outputPrefixType;

      public KeyFormat(KeyFormatProtoT keyFormat, KeyTemplate.OutputPrefixType outputPrefixType) {
        this.keyFormat = keyFormat;
        this.outputPrefixType = outputPrefixType;
      }
    }

    /**
     * Returns the class corresponding to the key format protobuffer.
     */
    public final Class<KeyFormatProtoT> getKeyFormatClass() {
      return clazz;
    }

    /**
     * Checks if the given {@code keyFormatProto} is a valid key.
     *
     * @throws GeneralSecurityException if the passed {@code keyFormatProto} is not valid in any
     *     way.
     */
    public abstract void validateKeyFormat(KeyFormatProtoT keyFormatProto)
        throws GeneralSecurityException;

    /**
     * Parses a serialized key proto.
     *
     * <p>Implement as {@code return KeyFormatProtoT.parseFrom(byteString);}.
     */
    public abstract KeyFormatProtoT parseKeyFormat(ByteString byteString)
        throws InvalidProtocolBufferException;

    /** Creates a new key from a given format. */
    public abstract KeyT createKey(KeyFormatProtoT keyFormat) throws GeneralSecurityException;

    /**
     * Derives a new key from a given format, using the given {@code pseudoRandomness}.
     *
     * <p>Implementations need to note that the given paramter {@code pseudoRandomness} may only
     * produce a finite amount of randomness. Hence, proper implementations will first obtain all
     * the pseudorandom bytes needed; and only after produce the key.
     *
     * <p>While {@link validateKeyFormat} is called before this method will be called,
     * implementations must check the version of the given {@code keyFormat}, as {@link
     * validateKeyFormat} is also called from {@link createKey}.
     *
     * <p>Not every KeyTypeManager needs to implement this; if not implemented a {@link
     * GeneralSecurityException} will be thrown.
     */
    public KeyT deriveKey(KeyFormatProtoT keyFormat, InputStream pseudoRandomness)
        throws GeneralSecurityException {
      throw new GeneralSecurityException("deriveKey not implemented for key of type " + clazz);
    }

    /** Returns supported key formats and their names. */
    public Map<String, KeyFormat<KeyFormatProtoT>> keyFormats() {
      return Collections.emptyMap();
    }
  }

  /**
   * Returns the {@link KeyFactory} for this key type.
   *
   * <p>By default, this throws an UnsupportedOperationException. Hence, if an implementation does
   * not support creating primitives, no implementation is required.
   *
   * @throws UnsupportedOperationException if the manager does not support creating primitives.
   */
  public KeyFactory<?, KeyProtoT> keyFactory() {
    throw new UnsupportedOperationException("Creating keys is not supported.");
  }
}
