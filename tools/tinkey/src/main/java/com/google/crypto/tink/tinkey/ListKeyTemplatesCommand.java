// Copyright 2017 Google Inc.
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

import com.google.crypto.tink.Registry;

/** Creates a new {@link com.google.crypto.tink.proto.KeyTemplate}. */
public class ListKeyTemplatesCommand implements Command {

  @Override
  public void run() throws Exception {
    System.out.println("The following key templates are supported:");
    for (String name : Registry.keyTemplates()) {
      System.out.println(name);
    }
  }
}
