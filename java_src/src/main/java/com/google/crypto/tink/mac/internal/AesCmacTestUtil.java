// Copyright 2023 Google LLC
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

package com.google.crypto.tink.mac.internal;

import com.google.crypto.tink.AccessesPartialKey;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.internal.TinkBugException;
import com.google.crypto.tink.mac.AesCmacKey;
import com.google.crypto.tink.mac.AesCmacParameters;
import com.google.crypto.tink.mac.AesCmacParameters.Variant;
import com.google.crypto.tink.subtle.Hex;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;
import javax.annotation.Nullable;

/**
 * Test vector class, reusable test vectors, and convenience functions for testing AesCmac
 * implementations.
 */
@AccessesPartialKey
public final class AesCmacTestUtil {

  public static final AesCmacTestVector RFC_TEST_VECTOR_0 =
      new AesCmacTestVector(
          createAesCmacKey(
              "2b7e151628aed2a6abf7158809cf4f3c",
              createAesCmacParameters(16, 16, Variant.NO_PREFIX),
              null),
          "",
          "bb1d6929e95937287fa37d129b756746");
  public static final AesCmacTestVector RFC_TEST_VECTOR_1 =
      new AesCmacTestVector(
          createAesCmacKey(
              "2b7e151628aed2a6abf7158809cf4f3c",
              createAesCmacParameters(16, 16, Variant.NO_PREFIX),
              null),
          "6bc1bee22e409f96e93d7e117393172a"
              + "ae2d8a571e03ac9c9eb76fac45af8e51"
              + "30c81c46a35ce411",
          "dfa66747de9ae63030ca32611497c827");
  public static final AesCmacTestVector RFC_TEST_VECTOR_2 =
      new AesCmacTestVector(
          createAesCmacKey(
              "2b7e151628aed2a6abf7158809cf4f3c",
              createAesCmacParameters(16, 16, Variant.NO_PREFIX),
              null),
          "6bc1bee22e409f96e93d7e117393172a"
              + "ae2d8a571e03ac9c9eb76fac45af8e51"
              + "30c81c46a35ce411e5fbc1191a0a52ef"
              + "f69f2445df4f9b17ad2b417be66c3710",
          "51f0bebf7e3b9d92fc49741779363cfe");

  public static final AesCmacTestVector NOT_OVERFLOWING_INTERNAL_STATE =
      new AesCmacTestVector(
          createAesCmacKey(
              "00112233445566778899aabbccddeeff",
              createAesCmacParameters(16, 16, Variant.NO_PREFIX),
              null),
          "aaaaaa",
          "97268151a23fcd035a2dd0573d84e6ba");
  public static final AesCmacTestVector FILL_UP_EXACTLY_INTERNAL_STATE =
      new AesCmacTestVector(
          // fill up exactly the internal state once
          createAesCmacKey(
              "00112233445566778899aabbccddeeff",
              createAesCmacParameters(16, 16, Variant.NO_PREFIX),
              null),
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "70e4648706483f8c5e8e2fab7b190c08");
  public static final AesCmacTestVector FILL_UP_EXACTLY_INTERNAL_STATE_TWICE =
      new AesCmacTestVector(
          createAesCmacKey(
              "00112233445566778899aabbccddeeff",
              createAesCmacParameters(16, 16, Variant.NO_PREFIX),
              null),
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "219db2ebac5416dc2b0d8afcb666fb7a");
  public static final AesCmacTestVector OVERFLOW_INTERNAL_STATE_ONCE =
      new AesCmacTestVector(
          createAesCmacKey(
              "00112233445566778899aabbccddeeff",
              createAesCmacParameters(16, 16, Variant.NO_PREFIX),
              null),
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
              + "bbbbbb",
          "0336c9c4bf8f1bc219b017292af24358");
  public static final AesCmacTestVector OVERFLOW_INTERNAL_STATE_TWICE =
      new AesCmacTestVector(
          // overflow the internal state twice
          createAesCmacKey(
              "00112233445566778899aabbccddeeff",
              createAesCmacParameters(16, 16, Variant.NO_PREFIX),
              null),
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
              + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
              + "bbbbbb",
          "611a1ededd3dfff548ed80b7fd10c0ba");
  public static final AesCmacTestVector SHORTER_TAG =
      new AesCmacTestVector(
          createAesCmacKey(
              "00112233445566778899aabbccddeeff",
              createAesCmacParameters(16, 15, Variant.NO_PREFIX),
              null),
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
              + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
              + "bbbbbb",
          "611a1ededd3dfff548ed80b7fd10c0");
  public static final AesCmacTestVector TAG_WITH_KEY_PREFIX_TYPE_LEGACY =
      new AesCmacTestVector(
          createAesCmacKey(
              "00112233445566778899aabbccddeeff",
              createAesCmacParameters(16, 16, Variant.LEGACY),
              1877),
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
              + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
              + "bbbbbb",
          "00000007554816512e20d15db74f1de942d86a2f7b");
  public static final AesCmacTestVector TAG_WITH_KEY_PREFIX_TYPE_TINK =
      new AesCmacTestVector(
          createAesCmacKey(
              "00112233445566778899aabbccddeeff",
              createAesCmacParameters(16, 16, Variant.TINK),
              1877),
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
              + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
              + "bbbbbb",
          "0100000755611a1ededd3dfff548ed80b7fd10c0ba");
  public static final AesCmacTestVector LONG_KEY_TEST_VECTOR =
      new AesCmacTestVector(
          createAesCmacKey(
              "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
              createAesCmacParameters(32, 16, Variant.NO_PREFIX),
              null),
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
              + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
              + "bbbbbb",
          "139fce15a6f4a281ad22458d3d3cac26");

  public static final AesCmacTestVector WRONG_PREFIX_TAG_LEGACY =
      new AesCmacTestVector(
          createAesCmacKey(
              "00112233445566778899aabbccddeeff",
              createAesCmacParameters(16, 16, Variant.LEGACY),
              1877),
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
              + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
              + "bbbbbb",
          "0000611a1ededd3dfff548ed80b7fd10c0ba");
  public static final AesCmacTestVector WRONG_PREFIX_TAG_TINK =
      new AesCmacTestVector(
          createAesCmacKey(
              "00112233445566778899aabbccddeeff",
              createAesCmacParameters(16, 16, Variant.TINK),
              1877),
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
              + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
              + "bbbbbb",
          "0100000745611a1ededd3dfff548ed80b7fd10c0ba");
  public static final AesCmacTestVector TAG_TOO_SHORT =
      new AesCmacTestVector(
          createAesCmacKey(
              "00112233445566778899aabbccddeeff",
              createAesCmacParameters(16, 16, Variant.TINK),
              1877),
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
              + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
              + "bbbbbb",
          "c0ba");

  /**
   * Creates an {@link AesCmacKey} from the provided {@code keyMaterial}, {@code parameters}, and
   * {@code idRequirement}. This is a convenience method that makes the tests code more concise and
   * readable.
   */
  public static AesCmacKey createAesCmacKey(
      String keyMaterial, AesCmacParameters parameters, @Nullable Integer idRequirement) {
    try {
      return AesCmacKey.builder()
          .setAesKeyBytes(
              SecretBytes.copyFrom(Hex.decode(keyMaterial), InsecureSecretKeyAccess.get()))
          .setParameters(parameters)
          .setIdRequirement(idRequirement)
          .build();
    } catch (GeneralSecurityException ex) {
      throw new TinkBugException(ex);
    }
  }

  /**
   * Creates an {@link AesCmacParameters} object from the provided {@code keySizeBytes},
   * {@code tagSizeBytes}, and {@code variant}. This is a convenience method that makes the tests
   * code more concise and readable.
   */
  public static AesCmacParameters createAesCmacParameters(
      int keySizeBytes, int tagSizeBytes, Variant variant) {
    try {
      return AesCmacParameters.builder()
          .setKeySizeBytes(keySizeBytes)
          .setVariant(variant)
          .setTagSizeBytes(tagSizeBytes)
          .build();
    } catch (GeneralSecurityException ex) {
      throw new TinkBugException(ex);
    }
  }

  /**
   * Represents a single AesCmac test vector.
   */
  public static final class AesCmacTestVector {
    public final AesCmacKey key;
    public final byte[] message;
    public final byte[] tag;

    public AesCmacTestVector(AesCmacKey key, String message, String tag) {
      this.key = key;
      this.message = Hex.decode(message);
      this.tag = Hex.decode(tag);
    }
  }

  private AesCmacTestUtil() {}
}
