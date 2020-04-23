// Copyright 2018 Google Inc.
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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for Version. */
@RunWith(JUnit4.class)
public class VersionTest {
  @Test
  public void testVersionFormat() throws Exception {
    // The regex represents Semantic Versioning syntax (www.semver.org),
    // i.e. three dot-separated numbers, with an optional suffix
    // that starts with a hyphen, to cover alpha/beta releases and
    // release candiates, for example:
    //   1.2.3
    //   1.2.3-beta
    //   1.2.3-RC1
    String versionRegex = "[0-9]+[.][0-9]+[.][0-9]+(-[A-Za-z0-9]+)?";
    assertThat(Version.TINK_VERSION).matches(versionRegex);
  }
}
