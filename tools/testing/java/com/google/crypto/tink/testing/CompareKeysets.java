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

package com.google.crypto.tink.testing;

import com.google.crypto.tink.PrivilegedRegistry;
import com.google.crypto.tink.proto.Keyset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Provides a function {@link compareKeysets} which can compare two keysets.
 */
final class CompareKeysets {
  // Compares two keys of a keyset. We parse the KeyData in each keyset in order to ensure we do not
  // depend strongly on the serialization order of the tags; note that keysets may be serialized
  // in different languages, and assuming that the fields are ordered in the same way when generated
  // in each language seems relatively strong.
  private static boolean equalKeys(Keyset.Key key1, Keyset.Key key2) throws Exception {
    if (!key1.getStatus().equals(key2.getStatus())) {
      return false;
    }
    if (key1.getKeyId() != key2.getKeyId()) {
      return false;
    }
    if (!key1.getOutputPrefixType().equals(key2.getOutputPrefixType())) {
      return false;
    }
    if (!key1.getKeyData().getKeyMaterialType().equals(key2.getKeyData().getKeyMaterialType())) {
      return false;
    }
    if (!PrivilegedRegistry.parseKeyData(key1.getKeyData())
        .equals(PrivilegedRegistry.parseKeyData(key2.getKeyData()))) {
      return false;
    }
    return true;
  }

  /**
   * Finds a key in {@code keyList} for which {@link equalKeys} returns true, removes it, and
   * returns true. If no such key exists, returns false.
   */
  private static boolean findAndRemove(Keyset.Key key, List<Keyset.Key> keyList) throws Exception {
    for (Keyset.Key key2 : keyList) {
      if (equalKeys(key, key2)) {
        keyList.remove(key2);
        return true;
      }
    }
    return false;
  }

  private static void compareKeysetLists(List<Keyset.Key> keyList1, List<Keyset.Key> keyList2)
      throws Exception {
    for (Keyset.Key key1 : keyList1) {
      if (!findAndRemove(key1, keyList2)) {
        throw new IllegalArgumentException("Key " + key1 + " not found in second keyset.");
      }
    }
  }

  /**
   * Collects all keys with a fixed key id in a {@link List}, returning the result in a map from
   * the key-id to this list.
   */
  private static Map<Integer, List<Keyset.Key>> getKeyDataMap(Keyset keyset) {
    Map<Integer, List<Keyset.Key>> result = new HashMap<>();
    for (int i = 0; i < keyset.getKeyCount(); ++i) {
      Keyset.Key key = keyset.getKey(i);
      if (!result.containsKey(key.getKeyId())) {
        result.put(key.getKeyId(), new ArrayList<Keyset.Key>());
      }
      result.get(key.getKeyId()).add(key);
    }
    return result;
  }

  /**
   * Compares two keysets, throws some exception if the keyset are different.
   *
   * <p>If the keysets are different, this is guaranteed to throw an exception. If they are the same
   * there are several possibilities why this will still throw an exception:
   *
   * <ul>
   *   <li>There is no key manager registered for one of the Keys used in the keyset
   *   <li>
   * </ul>
   */
  public static void compareKeysets(Keyset keyset1, Keyset keyset2) throws Exception {
    if (keyset1.getPrimaryKeyId() != keyset2.getPrimaryKeyId()) {
      throw new IllegalArgumentException(
          "Given keysets contain different key ids. \n\nKeyset 1: "
              + keyset1
              + "\n\nKeyset2: "
              + keyset2);
    }
    if (keyset1.getKeyCount() != keyset2.getKeyCount()) {
      throw new IllegalArgumentException(
          "Given keysets contain different number of keys. \n\nKeyset 1: "
              + keyset1
              + "\n\nKeyset2: "
              + keyset2);
    }

    // The order of the keys in the keyset is considered irrelevant.
    Map<Integer, List<Keyset.Key>> keyset1Map = getKeyDataMap(keyset1);
    Map<Integer, List<Keyset.Key>> keyset2Map = getKeyDataMap(keyset2);
    for (Map.Entry<Integer, List<Keyset.Key>> idToList : keyset1Map.entrySet()) {
      if (!keyset2Map.containsKey(idToList.getKey())) {
        throw new IllegalArgumentException(
            "Keysets differ; the second one contains no key with id "
                + idToList.getKey()
                + ", but the first one does. \n\nKeyset 1: "
                + keyset1
                + "\n\nKeyset 2:"
                + keyset2);
      }
      compareKeysetLists(keyset2Map.get(idToList.getKey()), idToList.getValue());
    }
  }

  private CompareKeysets() {
  }
}
