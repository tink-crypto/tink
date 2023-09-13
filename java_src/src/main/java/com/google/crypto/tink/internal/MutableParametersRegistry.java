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

package com.google.crypto.tink.internal;

import com.google.crypto.tink.Parameters;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A container for the global parameters values.
 *
 * <p>Thread safe.
 */
public final class MutableParametersRegistry {
  private final Map<String, Parameters> parametersMap = new HashMap<>();

  MutableParametersRegistry() {}

  private static final MutableParametersRegistry globalInstance = new MutableParametersRegistry();

  public static MutableParametersRegistry globalInstance() {
    return globalInstance;
  }

  public synchronized void put(String name, Parameters value) throws GeneralSecurityException {
    if (parametersMap.containsKey(name)) {
      if (parametersMap.get(name).equals(value)) {
        return;
      }
      throw new GeneralSecurityException(
          "Parameters object with name "
              + name
              + " already exists ("
              + parametersMap.get(name)
              + "), cannot insert "
              + value);
    }
    parametersMap.put(name, value);
  }

  public synchronized Parameters get(String name) throws GeneralSecurityException {
    if (parametersMap.containsKey(name)) {
      return parametersMap.get(name);
    }
    throw new GeneralSecurityException("Name " + name + " does not exist");
  }

  public synchronized void putAll(Map<String, Parameters> values) throws GeneralSecurityException {
    for (Map.Entry<String, Parameters> entry : values.entrySet()) {
      put(entry.getKey(), entry.getValue());
    }
  }

  public synchronized List<String> getNames() throws GeneralSecurityException {
    List<String> results = new ArrayList<>();
    results.addAll(parametersMap.keySet());

    return Collections.unmodifiableList(results);
  }
}
