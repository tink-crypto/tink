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

import static com.google.common.truth.Truth.assertWithMessage;

import com.google.crypto.tink.Key;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Helps check correctness of implementations of "equalsKey".
 *
 * <p>This is similar to the Guava class {@code EqualsTester}, but uses {@code equalsKey} instead of
 * {@code equals}, and tests additional properties which are useful for keys only.
 *
 * <p>Usage example:
 *
 * <pre>
 * new KeyTester()
 *     .addEqualityGroup("128 bit AES Gcm Key", fixed128bitAesGcmKey(), fixed128bitAesGcmKey())
 *     .addEqualityGroup("256 bit AES Gcm Key", fixed256bitAesGcmKey(), fixed256bitAesGcmKey())
 *     .doTests();
 * </pre>
 *
 * <p>Compared to the Guava {@code EqualsTester}, the user has to specify a name for each group
 * because keys cannot have a useful {@code toString} method.
 *
 * <p>This API is currently internal. If needed, we can consider adding it to the public API after
 * we have some experience with it.
 */
public final class KeyTester {
  private final Map<String, List<Key>> equivalenceGroups = new HashMap<>();

  public KeyTester addEqualityGroup(String name, Key... keys) {
    if (equivalenceGroups.containsKey(name)) {
      throw new AssertionError("Group with name " + name + " already present");
    }
    equivalenceGroups.put(name, Arrays.asList(keys));
    return this;
  }

  private static void testSingleKey(String keyIdentifier, Key key) {
    if (key.getKeyFormat().hasIdRequirement()) {
      assertWithMessage(
              keyIdentifier
                  + " has a format with IdRequirement, but getIdRequirementOrNull returns null")
          .that(key.getIdRequirementOrNull())
          .isNotNull();
    } else {
      assertWithMessage(
              keyIdentifier
                  + " has a format without IdRequirement, but getIdRequirementOrNull returns a"
                  + " non-null value")
          .that(key.getIdRequirementOrNull())
          .isNull();
    }
  }

  private static void testSameGroupKeys(String keysIdentifier, Key key1, Key key2) {
    assertWithMessage(keysIdentifier + " are not equal: ").that(key1.equalsKey(key2)).isTrue();
    assertWithMessage(keysIdentifier + " have different ID requirements: ")
        .that(key1.getIdRequirementOrNull())
        .isEqualTo(key2.getIdRequirementOrNull());
    assertWithMessage(keysIdentifier + " have different key format: ")
        .that(key1.getKeyFormat()).isEqualTo(key2.getKeyFormat());
    assertWithMessage(keysIdentifier + " have key formats with different hashCode values: ")
        .that(key1.getKeyFormat().hashCode()).isEqualTo(key2.getKeyFormat().hashCode());
  }

  private static void testDifferentGroupKeys(
      String keyIdentifier1, String keyIdentifier2, Key key1, Key key2) {
    assertWithMessage(
            keyIdentifier1
                + "and"
                + keyIdentifier2
                + " are from different equality groups, but equalsKey returns true")
        .that(key1.equalsKey(key2))
        .isFalse();
  }

  /**
   * Runs tests on the given equality groups.
   *
   * <p>This tests the following properties on the previously configured equality groups:
   *
   * <ul>
   *   <li>For each individual key {@code k}, we check consistency of {@code getIdRequirementOrNull}
   *       and {@code k.getKeyFormat().hasIdRequirement()}.
   *   <li>For each pair {@code k1, k2} of keys in the same group, we check that {@code
   *       k1.equalsKey(k2)}, that {@code k1.getKeyFormat().equals(k2.getKeyFormat())}, that {@code
   *       k1.getKeyFormat().hashCode() == k2.getKeyFormat().hashCode()}, and that {@code
   *       Object.equals(k1.getIdRequirementOrNull(), k2.getIdRequirementOrNull())}.
   *   <li>For each pair {@code k1, k2} of keys in different groups, we check that {@code
   *       k1.equalsKey(k2)} is false.
   * </ul>
   */
  public void doTests() {
    for (Map.Entry<String, List<Key>> group : equivalenceGroups.entrySet()) {
      for (int i = 0; i < group.getValue().size(); ++i) {
        testSingleKey("Key #" + i + " from group " + group.getKey(), group.getValue().get(i));
      }
    }

    for (Map.Entry<String, List<Key>> group1 : equivalenceGroups.entrySet()) {
      for (Map.Entry<String, List<Key>> group2 : equivalenceGroups.entrySet()) {
        for (int i1 = 0; i1 < group1.getValue().size(); ++i1) {
          for (int i2 = 0; i2 < group2.getValue().size(); ++i2) {
            String group1Name = group1.getKey();
            String group2Name = group2.getKey();
            Key key1 = group1.getValue().get(i1);
            Key key2 = group2.getValue().get(i2);
            if (group1Name.equals(group2Name)) {
              String keysIdentifier =
                  "Keys #" + i1 + " and #" + i2 + " from group '" + group1Name + "'";
              testSameGroupKeys(keysIdentifier, key1, key2);
            } else {
              String keysIdentifier1 = "Key #" + i1 + " from group '" + group1.getKey() + "'";
              String keysIdentifier2 = "Key #" + i2 + " from group '" + group2.getKey() + "'";
              testDifferentGroupKeys(keysIdentifier1, keysIdentifier2, key1, key2);
            }
          }
        }
      }
    }
  }
}
