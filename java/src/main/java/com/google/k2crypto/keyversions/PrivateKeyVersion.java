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

/**
 * Class representing PrivateKeyVersions. Extended by specific implementations such as
 * DSAPrivateKeyVersion
 *
 * @author John Maheswaran (maheswaran@google.com)
 */
public abstract class PrivateKeyVersion extends AsymmetricKeyVersion {

  /**
   * Constructor for PrivateKeyVersion
   *
   * @param builder The Builder object used to build this PrivateKeyVersion
   */
  protected PrivateKeyVersion(Builder builder) {
    super(builder);
  }

}
