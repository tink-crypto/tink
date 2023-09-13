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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.crypto.tink.Parameters;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class MutableParametersRegistryTest {
  @Test
  public void putAndGet_works() throws Exception {
    MutableParametersRegistry registry = new MutableParametersRegistry();
    registry.put("AES_128GCM", PredefinedAeadParameters.AES128_GCM);
    assertThat(registry.get("AES_128GCM")).isEqualTo(PredefinedAeadParameters.AES128_GCM);
  }

  @Test
  public void putAndGet_multipleElements_works() throws Exception {
    MutableParametersRegistry registry = new MutableParametersRegistry();
    registry.put("AES_128GCM", PredefinedAeadParameters.AES128_GCM);
    registry.put("AES_256GCM", PredefinedAeadParameters.AES256_GCM);
    assertThat(registry.get("AES_128GCM")).isEqualTo(PredefinedAeadParameters.AES128_GCM);
    assertThat(registry.get("AES_256GCM")).isEqualTo(PredefinedAeadParameters.AES256_GCM);
  }

  @Test
  public void putAndGet_multipleElementsWithPutAll_works() throws Exception {
    HashMap<String, Parameters> multipleParameters = new HashMap<>();
    multipleParameters.put("AES_128GCM", PredefinedAeadParameters.AES128_GCM);
    multipleParameters.put("AES_256GCM", PredefinedAeadParameters.AES256_GCM);
    MutableParametersRegistry registry = new MutableParametersRegistry();
    registry.putAll(multipleParameters);
    assertThat(registry.get("AES_128GCM")).isEqualTo(PredefinedAeadParameters.AES128_GCM);
    assertThat(registry.get("AES_256GCM")).isEqualTo(PredefinedAeadParameters.AES256_GCM);
  }

  @Test
  public void putAndGet_sameElementMultipleTimes_works() throws Exception {
    MutableParametersRegistry registry = new MutableParametersRegistry();
    registry.put("AES_128GCM", PredefinedAeadParameters.AES128_GCM);
    registry.put("AES_256GCM", PredefinedAeadParameters.AES256_GCM);
    registry.put("AES_128GCM", PredefinedAeadParameters.AES128_GCM);
    registry.put("AES_256GCM", PredefinedAeadParameters.AES256_GCM);
    registry.put("AES_128GCM", PredefinedAeadParameters.AES128_GCM);
    registry.put("AES_256GCM", PredefinedAeadParameters.AES256_GCM);
    assertThat(registry.get("AES_128GCM")).isEqualTo(PredefinedAeadParameters.AES128_GCM);
    assertThat(registry.get("AES_256GCM")).isEqualTo(PredefinedAeadParameters.AES256_GCM);
  }

  @Test
  public void putAndGet_multipleElementsWithPutAll_multipleTimes_works() throws Exception {
    Map<String, Parameters> multipleParameters = new HashMap<>();
    multipleParameters.put("AES_128GCM", PredefinedAeadParameters.AES128_GCM);
    multipleParameters.put("AES_256GCM", PredefinedAeadParameters.AES256_GCM);
    MutableParametersRegistry registry = new MutableParametersRegistry();
    registry.put("AES_128GCM", PredefinedAeadParameters.AES128_GCM);
    registry.put("AES_256GCM", PredefinedAeadParameters.AES256_GCM);
    registry.putAll(multipleParameters);
    assertThat(registry.get("AES_128GCM")).isEqualTo(PredefinedAeadParameters.AES128_GCM);
    assertThat(registry.get("AES_256GCM")).isEqualTo(PredefinedAeadParameters.AES256_GCM);
  }

  @Test
  public void getNonexistentKey_throws() throws Exception {
    MutableParametersRegistry registry = new MutableParametersRegistry();
    registry.put("AES_128GCM", PredefinedAeadParameters.AES128_GCM);
    assertThrows(GeneralSecurityException.class, () -> registry.get("AES_256GCM"));
  }

  @Test
  public void putAndGet_sameKeyDifferentValue_throws() throws Exception {
    MutableParametersRegistry registry = new MutableParametersRegistry();
    registry.put("AES_128GCM", PredefinedAeadParameters.AES128_GCM);
    assertThrows(
        GeneralSecurityException.class,
        () -> registry.put("AES_128GCM", PredefinedAeadParameters.AES256_GCM));
  }

  @Test
  public void putAndGet_putAllSameKeyDifferentValue_throws() throws Exception {
    Map<String, Parameters> multipleParameters = new HashMap<>();
    multipleParameters.put("AES_128GCM", PredefinedAeadParameters.AES128_GCM);
    multipleParameters.put("AES_256GCM", PredefinedAeadParameters.AES256_GCM);
    MutableParametersRegistry registry = new MutableParametersRegistry();
    registry.put("AES_128GCM", PredefinedAeadParameters.AES128_GCM);
    registry.put("AES_256GCM", PredefinedAeadParameters.AES128_GCM);

    assertThrows(GeneralSecurityException.class, () -> registry.putAll(multipleParameters));
  }

  @Test
  public void getNamesTest_works() throws Exception {
    MutableParametersRegistry registry = new MutableParametersRegistry();
    registry.put("AES_128GCM", PredefinedAeadParameters.AES128_GCM);
    registry.put("AES_256GCM", PredefinedAeadParameters.AES256_GCM);
    assertThat(registry.getNames()).containsExactly("AES_128GCM", "AES_256GCM");
  }
}
