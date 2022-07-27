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

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotates methods and classes which access parts of keys.
 *
 * <p>In Tink, a key is a representation of a mathematical function (e.g. the function {@code
 * Encrypt}, or the function {@code Sign}). These functions typically require all fields in the
 * corresponding objects to be specified. A common mistake is to extract only parts of such a
 * description. This can lead to incompatibilities.
 *
 * <p>For example, suppose a user want to export an RSASSA-PSS key public key from Tink for use with
 * a different library. These keys consist of the modulus {@code n}, the public exponent {@code e},
 * as well as the specification of two hash functions, and the length of salt used internally in the
 * algorithm. When exporting such a key, often users ignore the hash functions and the salt length.
 * However, this would be a mistake: even if it works at the moment, if later Tink is configured to
 * use a different hash function, and the resulting key is exported using such a method, the
 * signatures will not be compatible.
 *
 * <p>Hence, when users access a function which requires this annotation, they should ensure that
 * they will not get compatibility bugs in the future. In most cases, they probably should call the
 * other methods on the corresponding class too.
 *
 * <p>In order to use a function which calls such a method, the function using it has to be
 * annotated with {@code AccessesPartialKey}:
 *
 * <pre>
 *   class KeyExporter {
 *      ...
 *      {@literal @}AccessesPartialKey
 *      public static SecretBytes exportHmacKey(HmacKey key) {
 *        // The caller of this method can only handle keys without prefix, SHA256, 20 byte tags,
 *        // and 32 byte keys.
 *        if (key.getParameters().getVariant() != HmacParameters.Variant.NO_PREFIX ||
 *            key.getParameters().getHashType() != HMacParameters.Hash.SHA_256 ||
 *            key.getParameters().getTagSizeBytes() != 20 ||
 *            key.getParameters().getKeySizeBytes() != 32) {
 *          throw new IllegalArgumentException("Parameters not supported by receiver.");
 *        }
 *        return key.getKeyBytes();
 *      }
 *   }
 * </pre>
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.CLASS)
public @interface AccessesPartialKey {}
