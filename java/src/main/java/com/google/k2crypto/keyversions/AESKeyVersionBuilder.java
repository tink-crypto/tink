/*
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */


package com.google.k2crypto.keyversions;

import com.google.k2crypto.KeyVersionBuilder;

/**
 * This class represents a key version builder for AES key versions.
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public class AESKeyVersionBuilder extends KeyVersionBuilder {
  /**
   * key size can be 16, 24 or 32
   */
  private int keyVersionLength = 16;
  /**
   * Supported modes: CBC, ECB, OFB, CFB, CTR Unsupported modes: XTS, OCB
   */
  private String mode;

  /**
   * TODO: Supported paddings depends on Java implementation. Upgrade java implementation to support
   * more paddings
   */
  /**
   * Supported padding: PKCS5PADDING Unsupported padding: PKCS7Padding, ISO10126d2Padding,
   * X932Padding, ISO7816d4Padding, ZeroBytePadding
   */
  private String padding = "PKCS5PADDING";

  // key matter, init vector

  public AESKeyVersionBuilder() {}

  /**
   * Set the key version length
   *
   * @param keyVersionLength Integer representing key version length in BYTES, can be 16, 24, 32
   * @return This object with keyVersionLength updated
   */
  public AESKeyVersionBuilder keyVersionLength(int keyVersionLength) {
    this.keyVersionLength = keyVersionLength;
    return this;
  }

  /**
   * Set the encryption mode
   *
   * @param mode String representing the encryption mode. Supported modes: CBC, ECB, OFB, CFB, CTR
   * @return This object with mode updated
   */
  public AESKeyVersionBuilder mode(String mode) {
    this.mode = mode;
    return this;
  }


  /**
   * Set the padding
   *
   * @param mode String representing the padding mode. Supported padding: PKCS5PADDING
   * @return This object with padding updated
   */
  public AESKeyVersionBuilder padding(String padding) {
    this.padding = padding;
    return this;
  }

}
