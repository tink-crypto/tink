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

package com.google.crypto.tink;

import static org.junit.Assert.assertEquals;

import com.google.crypto.tink.proto.EcdsaPublicKey;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * A simple integration test to see whether Ecdsa protobuf is built correctly.
 * TODO(quannguyen): Add extensive tests.
 */
@RunWith(JUnit4.class)
public class EcdsaProtoTest {

  @Test
  public void testKeysetBasic() throws Exception {
    EcdsaPublicKey publicKey = EcdsaPublicKey.newBuilder().setVersion(1).build();
    assertEquals(1, publicKey.getVersion());
  }
}
