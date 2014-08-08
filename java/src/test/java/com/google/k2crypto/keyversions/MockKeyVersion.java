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

import com.google.k2crypto.keyversions.KeyVersionProto.KeyVersionCore;
import com.google.k2crypto.keyversions.KeyVersionProto.KeyVersionData;
import com.google.k2crypto.keyversions.MockKeyVersionProto.MockKeyVersionCore;
import com.google.k2crypto.keyversions.MockKeyVersionProto.MockKeyVersionData;
import com.google.protobuf.ByteString;
import com.google.protobuf.ExtensionRegistry;
import com.google.protobuf.InvalidProtocolBufferException;

import java.util.Random;

/**
 * Mock implementation of a KeyVersion.
 * 
 * <p>This mock generates key "material" and supports adding arbitrary comments
 * to the key version. It does not support any cryptographic function.
 * 
 * @author darylseah@gmail.com (Daryl Seah)
 */
@KeyVersionInfo(
    type = KeyVersionProto.Type.TEST,
    proto = MockKeyVersionProto.class)
public class MockKeyVersion extends KeyVersion {
  
  /**
   * Default size in bytes of the generated material.
   */
  public static final int DEFAULT_MATERIAL_SIZE = 64;
  
  // Key version "material"
  final ByteString material;
  
  // User comments
  final String comments;
  
  // Call counts for inspection
  int buildDataCalls = 0; 
  int buildCoreCalls = 0; 
  
  /**
   * Constructs a MockKeyVersion.
   * 
   * @param builder Builder with the initialization parameters.
   */
  protected MockKeyVersion(Builder builder) {
    super(builder);
    if (builder.material == null) {
      // Generate material
      Random random = new Random(); // mock need not be secure
      byte[] bytes = new byte[builder.materialSize];
      for (int i = bytes.length; --i >= 0; ) {
        bytes[i] = (byte)random.nextInt(256);
      }
      material = ByteString.copyFrom(bytes);
    } else {
      // Copy material
      material = builder.material;
    }
    comments = builder.comments;
  }

  /**
   * Returns the key version material.
   */
  public ByteString getMaterial() {
    return material;
  }

  /**
   * Returns the comments assigned at build time, or null if none.
   */
  public String getComments() {
    return comments;
  }
  
  /**
   * @see KeyVersion#buildCore()
   */
  @Override
  protected KeyVersionCore.Builder buildCore() {
    ++buildCoreCalls;
    MockKeyVersionCore.Builder coreBuilder = MockKeyVersionCore.newBuilder();
    coreBuilder.setMaterial(material);
    KeyVersionCore.Builder builder = super.buildCore();
    builder.setExtension(MockKeyVersionCore.extension, coreBuilder.build());
    return builder;
  }
  
  /**
   * @see KeyVersion#buildData()
   */
  @Override
  public KeyVersionData.Builder buildData() {
    ++buildDataCalls;
    MockKeyVersionData.Builder dataBuilder = MockKeyVersionData.newBuilder();
    if (comments != null) {
      dataBuilder.setComments(comments);
    }
    KeyVersionData.Builder builder = super.buildData();
    builder.setExtension(MockKeyVersionData.extension, dataBuilder.build());
    return builder;
  }
  
  /**
   * Tests the mock for equality with an object.
   * 
   * @param obj Object to compare to.
   * 
   * @return {@code true} if, and only if, the object is of the same class and
   *         has the same material and comments as this one. 
   */
  @Override
  public boolean equals(Object obj) {
    if (super.equals(obj)) {
      MockKeyVersion other = (MockKeyVersion)obj;
      return material.equals(other.material) && (comments == null
          ? other.comments == null : comments.equals(other.comments));
    }
    return false;
  }
  
  /**
   * Builder for the mock key version.
   */
  public static class Builder extends KeyVersion.Builder {
    
    private int materialSize = DEFAULT_MATERIAL_SIZE;
    
    private ByteString material = null;
    
    private String comments = null;
    
    /**
     * Specifies that material of the given size should be generated. 
     *
     * @param bytes Size in bytes.
     * 
     * @return a reference to this builder.
     */
    public Builder materialSize(int bytes) {
      if (bytes < 0) {
        throw new IllegalArgumentException("Negative " + bytes);
      }
      material = null;
      materialSize = bytes;
      return this;
    }
    
    /**
     * Sets the material to use. 
     *
     * @param material Bytes for the material.
     * 
     * @return a reference to this builder.
     */
    public Builder material(ByteString material) {
      materialSize = material.size();
      this.material = material;
      return this;
    }
    
    /**
     * Sets the comments.
     * 
     * @param comments Comments string.
     * 
     * @return a reference to this builder.
     */
    public Builder comments(String comments) {
      this.comments =
          (comments == null || comments.length() == 0) ? null : comments;
      return this;
    }
    
    /**
     * @see KeyVersion.Builder#withData(KeyVersionData, ExtensionRegistry)
     */
    @Override
    public Builder withData(KeyVersionData kvData, ExtensionRegistry registry)
        throws InvalidProtocolBufferException {
      super.withData(kvData, registry);
      MockKeyVersionData data =
          kvData.getExtension(MockKeyVersionData.extension);
      this.comments(data.hasComments() ? data.getComments() : null);
      return this;
    }

    /**
     * @see KeyVersion.Builder#withCore(KeyVersionCore)
     */
    @Override
    protected Builder withCore(KeyVersionCore kvCore) 
        throws InvalidProtocolBufferException {
      super.withCore(kvCore);
      MockKeyVersionCore core =
          kvCore.getExtension(MockKeyVersionCore.extension);
      if (!core.hasMaterial()) {
        // Material is required
        throw new InvalidProtocolBufferException("Core material missing.");
      }
      this.material(core.getMaterial());
      return this;
    }

    /**
     * @see KeyVersion.Builder#build()
     */
    @Override
    public MockKeyVersion build() {
      return new MockKeyVersion(this);
    }
  }
}
