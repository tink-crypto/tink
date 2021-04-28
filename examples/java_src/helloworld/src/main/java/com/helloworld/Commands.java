/*
 * Copyright 2017 Google LLC
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

package com.helloworld;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.KeysetHandle;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.Option;
import org.kohsuke.args4j.spi.SubCommand;
import org.kohsuke.args4j.spi.SubCommandHandler;
import org.kohsuke.args4j.spi.SubCommands;

/** Defines the different sub-commands and their parameters, for command-line invocation. */
public final class Commands {
  /** An interface for a command-line sub-command. */
  interface Command {
    public void run() throws Exception;
  }

  static class Options {
    @Option(
      name = "--keyset",
      required = true,
      usage = "The path to the keyset, generate new if does not exist"
    )
    File keyset;

    @Option(name = "--in", required = true, usage = "The input filename")
    File inFile;

    @Option(name = "--out", required = true, usage = "The output filename")
    File outFile;
  }

  /** Loads a KeysetHandle from {@code keyset} or generate a new one if it doesn't exist. */
  private static KeysetHandle getKeysetHandle(File keyset)
      throws GeneralSecurityException, IOException {
    if (keyset.exists()) {
      // Read the cleartext keyset from disk.
      // WARNING: reading cleartext keysets is a bad practice. Tink supports reading/writing
      // encrypted keysets, see
      // https://github.com/google/tink/blob/master/docs/JAVA-HOWTO.md#loading-existing-keysets.
      return CleartextKeysetHandle.read(JsonKeysetReader.withFile(keyset));
    }
    KeysetHandle handle = KeysetHandle.generateNew(KeyTemplates.get("AES128_GCM"));
    CleartextKeysetHandle.write(handle, JsonKeysetWriter.withFile(keyset));
    return handle;
  }

  /**
   * Encrypts a file.
   */
  public static class EncryptCommand extends Options implements Command {
    @Override
    public void run() throws Exception {
      // 1. Obtain a keyset handle.
      KeysetHandle handle = getKeysetHandle(keyset);
      // 2. Get a primitive.
      Aead aead = handle.getPrimitive(Aead.class);
      // 3. Do crypto. It's that simple!
      byte[] plaintext = Files.readAllBytes(inFile.toPath());
      byte[] ciphertext = aead.encrypt(plaintext, new byte[0] /* additionalData */);
      FileOutputStream stream = new FileOutputStream(outFile);
      try {
        stream.write(ciphertext);
      } finally {
        stream.close();
      }
    }
  }

  /**
   * Decrypts a file.
   */
  public static class DecryptCommand extends Options implements Command {
    @Override
    public void run() throws Exception {
      KeysetHandle handle = getKeysetHandle(keyset);
      Aead aead = handle.getPrimitive(Aead.class);
      byte[] ciphertext = Files.readAllBytes(inFile.toPath());
      byte[] plaintext = aead.decrypt(ciphertext, new byte[0] /* additionalData */);
      FileOutputStream stream = new FileOutputStream(outFile);
      try {
        stream.write(plaintext);
      } finally {
        stream.close();
      }
    }
  }

  @Argument(
    metaVar = "command",
    required = true,
    handler = SubCommandHandler.class,
    usage = "The subcommand to run"
  )
  @SubCommands({
    @SubCommand(name = "encrypt", impl = EncryptCommand.class),
    @SubCommand(name = "decrypt", impl = DecryptCommand.class)
  })
  Command command;
}
