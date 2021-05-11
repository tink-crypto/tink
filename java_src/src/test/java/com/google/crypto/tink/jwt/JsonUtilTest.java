// Copyright 2020 Google LLC
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

package com.google.crypto.tink.jwt;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Unit tests for JsonUtil */
@RunWith(JUnit4.class)
public final class JsonUtilTest {

  @Test
  public void validateValidString_success() throws Exception {
    assertThat(JsonUtil.isValidString("")).isTrue();
    assertThat(JsonUtil.isValidString("foo")).isTrue();
    assertThat(JsonUtil.isValidString("*\uD834\uDD1E*")).isTrue();
    assertThat(JsonUtil.isValidString("\uD834\uDD1E*")).isTrue();
    assertThat(JsonUtil.isValidString("*\uD834\uDD1E")).isTrue();
    assertThat(JsonUtil.isValidString("\uD834\uDD1E")).isTrue();
  }

  @Test
  public void validateInvalidString_throws() throws Exception {
    assertThat(JsonUtil.isValidString("*\uD834")).isFalse();
    assertThat(JsonUtil.isValidString("\uD834*")).isFalse();
    assertThat(JsonUtil.isValidString("\uD834")).isFalse();
    assertThat(JsonUtil.isValidString("*\uD834*")).isFalse();
    assertThat(JsonUtil.isValidString("\uDD1E")).isFalse();
    assertThat(JsonUtil.isValidString("*\uDD1E")).isFalse();
    assertThat(JsonUtil.isValidString("\uDD1E*")).isFalse();
    assertThat(JsonUtil.isValidString("*\uDD1E*")).isFalse();
  }
  ;

  @Test
  public void parseJson_success() throws Exception {
    JsonObject header = JsonUtil.parseJson("{\"bool\":false}");
    assertThat(header.get("bool").getAsBoolean()).isFalse();
  }

  @Test
  public void parseJsonArray_success() throws Exception {
    JsonArray array = JsonUtil.parseJsonArray("[1, \"foo\"]");
    assertThat(array.get(0).getAsInt()).isEqualTo(1);
    assertThat(array.get(1).getAsString()).isEqualTo("foo");
  }

  @Test
  public void parseRecursiveJsonString_success() throws Exception {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < 10000; i++) {
      sb.append("{\"a\":");
    }
    sb.append("1");
    for (int i = 0; i < 10000; i++) {
      sb.append("}");
    }
    try {
      JsonUtil.parseJson(sb.toString());
    } catch (JwtInvalidException ex) {
      // JwtInvalidException is fine, no exception as well.
    }
  }

  @Test
  public void parseJsonWithoutQuotes_fail() throws Exception {
    assertThrows(JwtInvalidException.class, () -> JsonUtil.parseJson("{bool:false}"));
  }

  @Test
  public void parseJsonArrayWithoutComments_fail() throws Exception {
    assertThrows(JwtInvalidException.class, () -> JsonUtil.parseJson("[1, \"foo\" /* comment */]"));
  }

  @Test
  public void parseJsonWithoutComments_fail() throws Exception {
    assertThrows(
        JwtInvalidException.class, () -> JsonUtil.parseJson("{\"bool\":false /* comment */}"));
  }
}
