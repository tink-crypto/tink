// Copyright 2021 Google LLC
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

import static com.google.common.truth.Truth.assertThat;

import com.google.crypto.tink.internal.MutableParametersRegistry;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for KeyTemplates * */
@RunWith(JUnit4.class)
public final class KeyTemplatesTest {
  private static Map<String, Parameters> namedParameters() throws GeneralSecurityException {
    Map<String, Parameters> formats = new HashMap<>();
    formats.put(
        "TINK",
        new Parameters() {
          @Override
          public boolean hasIdRequirement() {
            return true;
          }
        });
    formats.put(
        "RAW",
        new Parameters() {
          @Override
          public boolean hasIdRequirement() {
            return false;
          }
        });
    return Collections.unmodifiableMap(formats);
  }

  @Test
  public void get() throws Exception {
    MutableParametersRegistry.globalInstance().putAll(namedParameters());

    KeyTemplate template1 = KeyTemplates.get("TINK");
    assertThat(template1.toParameters().hasIdRequirement()).isEqualTo(true);

    KeyTemplate template2 = KeyTemplates.get("RAW");
    assertThat(template2.toParameters().hasIdRequirement()).isEqualTo(false);
  }
}
