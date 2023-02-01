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

package com.google.crypto.tink.tinkey;

/** Outputs a help message. */
public class HelpCommand implements Command {
  @Override
  public void run() throws Exception {
    System.out.println("Tinkey supports the following commands:");
    System.out.println("  help:                 Prints this help message.");
    System.out.println("  add-key:              Generates and adds a new key to a keyset.");
    System.out.println("  convert-keyset:       Changes format, encrypts, decrypts a keyset.");
    System.out.println("  create-keyset:        Creates a new keyset.");
    System.out.println("  create-public-keyset: Creates a public keyset from a private keyset.");
    System.out.println("  list-key-templates:   Lists all supported key templates.");
    System.out.println("  delete-key:           Deletes a specified key in a keyset.");
    System.out.println(
        "  destroy-key:          Destroys the key material of a specified key in a keyset.");
    System.out.println("  disable-key:          Disables a specified key in a keyset.");
    System.out.println("  enable-key:           Enables a specified key in a keyset.");
    System.out.println("  list-keyset:          Lists keys in a keyset.");
    System.out.println("  promote-key:          Promotes a specified key to primary.");
    System.out.println(
        "  rotate-keyset:        Deprecated. Rotate keysets in two steps using the commands"
            + " 'add-key' and later 'promote-key'.");
  }
}
