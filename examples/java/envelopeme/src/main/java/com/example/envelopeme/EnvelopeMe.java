/*
 * Copyright (c) 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.example.envelopeme;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.NoSecretKeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadFactory;
import com.google.crypto.tink.mac.MacConfig;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;

/**
 * Implements the commands specified in {@code EnvelopeMeCommands}.
 */
public class EnvelopeMe {

  /**
   * Encrypts the given bytes, using the key config file and the credential file.
   */
  public static byte[] encrypt(byte[] config, byte[] plaintext)
      throws Exception {
    KeysetHandle handle = NoSecretKeysetHandle.parseFrom(config);
    Aead aead = AeadFactory.getPrimitive(handle);
    return aead.encrypt(plaintext, /* additionalData= */null);
  }

  /**
   * Decrypts the given encrypted bytes, using the key config file and the credential file.
   */
  public static byte[] decrypt(byte[] config, byte[] ciphertext)
      throws Exception {
    KeysetHandle handle = NoSecretKeysetHandle.parseFrom(config);
    Aead aead = AeadFactory.getPrimitive(handle);
    return aead.decrypt(ciphertext, /* additionalData= */null);
  }

  public static void main(String[] args) throws Exception {
    AeadConfig.registerStandardKeyTypes();
    MacConfig.registerStandardKeyTypes();

    EnvelopeMeCommands commands = new EnvelopeMeCommands();
    CmdLineParser parser = new CmdLineParser(commands);

    try {
      parser.parseArgument(args);
    } catch (CmdLineException e) {
      System.out.println(e);
      System.out.println();
      e.getParser().printUsage(System.out);
      System.exit(1);
    }
    commands.command.run();
  }
}
