// Copyright 2014 Google. Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.k2crypto;

import com.google.k2crypto.Placeholdermessage.PlaceholderMessage;
import com.google.protobuf.ByteString;

import java.io.UnsupportedEncodingException;

/** A placeholder class to make sure the build scipt works */
class Placeholder {

  Placeholder() {
  }

  PlaceholderMessage getSomething()
      throws UnsupportedEncodingException {
    return PlaceholderMessage.newBuilder()
        .setVersion(1)
        .setPayload(ByteString.copyFrom("something", "UTF-8"))
        .build();
  }

  void doSomething() {
    try {
      System.err.println("Did it, and got " + getSomething().toString());
    } catch (UnsupportedEncodingException e) {
      e.printStackTrace();
    }
  }

  public static void main(String [] args) {
    Placeholder p = new Placeholder();
    p.doSomething();
  }
}
