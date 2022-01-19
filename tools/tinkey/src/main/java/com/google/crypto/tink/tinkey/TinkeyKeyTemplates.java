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

package com.google.crypto.tink.tinkey;

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
// place-holder for PrfBasedDeriverKeyManager. DO NOT EDIT
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * This class contains key templates that cannot stay in Tink, such as those that break Tink's
 * modularity because they depend on other key templates.
 */
final class TinkeyKeyTemplates {

  public static final Map<String, KeyTemplate> get() throws GeneralSecurityException {
    Map<String, KeyTemplate> result = new HashMap<>();
    // Keep synchronized with copybara/java.bara.sky
    // place-holder for PRF-based key templates. DO NOT EDIT
    return Collections.unmodifiableMap(result);
  }

  private TinkeyKeyTemplates() {}
}
