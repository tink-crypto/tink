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

import com.google.cloud.crypto.tink.Registry;
import com.google.cloud.crypto.tink.aead.GcpKmsAeadKeyManager;
import com.google.cloud.crypto.tink.subtle.ServiceAccountGcpCredentialFactory;
import com.google.cloud.crypto.tink.subtle.SubtleUtil;
import com.google.common.base.Optional;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.Option;
import org.kohsuke.args4j.spi.SubCommand;
import org.kohsuke.args4j.spi.SubCommandHandler;
import org.kohsuke.args4j.spi.SubCommands;

/**
 * Defines the different sub-commands and their parameters, for command-line invocation.
 */
class EnvelopeMeCommands {
  /**
   * An interface for a command-line sub-command.
   */
  interface Command {
    public void run() throws Exception;
  }

  // Most of the commands take some subset of the same arguments, so specify groups of arguments
  // as classes for greater code reuse.
  static class Args {
    @Option(name = "--config", required = true, usage = "The key config file")
    File configFile;
    @Option(name = "--credential", required = true, usage = "The credential file")
    File credentialFile;
    @Argument(metaVar = "inFile", required = true, index = 0, usage = "The source file")
    File inFile;
    @Argument(metaVar = "outFile", required = true, index = 1, usage = "The destination file")
    File outFile;

    void validate() {
      try {
        SubtleUtil.validateNotExist(outFile);
        SubtleUtil.validateExists(configFile);
        SubtleUtil.validateExists(credentialFile);
        SubtleUtil.validateExists(inFile);
      } catch (Exception e) {
        SubtleUtil.die(e.toString());
      }
    }
  }

  public static class EncryptCommand extends Args implements Command {
    @Override
    public void run() throws Exception {
      Registry.INSTANCE.registerKeyManager(
        "type.googleapis.com/google.cloud.crypto.tink.GcpKmsAeadKey",
        new GcpKmsAeadKeyManager(
            new ServiceAccountGcpCredentialFactory(Optional.of(credentialFile))));

      byte[] encrypted = EnvelopeMe.encrypt(
          Files.readAllBytes(configFile.toPath()),
          Files.readAllBytes(inFile.toPath()));

      FileOutputStream stream = new FileOutputStream(outFile);
      try {
        stream.write(encrypted);
      } finally {
        stream.close();
      }
    }
  }

  public static class DecryptCommand extends Args implements Command {
    @Override
    public void run() throws Exception {
      Registry.INSTANCE.registerKeyManager(
        "type.googleapis.com/google.cloud.crypto.tink.GcpKmsAeadKey",
        new GcpKmsAeadKeyManager(
            new ServiceAccountGcpCredentialFactory(Optional.of(credentialFile))));

      byte[] decrypted = EnvelopeMe.decrypt(
          Files.readAllBytes(configFile.toPath()),
          Files.readAllBytes(inFile.toPath()));

      FileOutputStream stream = new FileOutputStream(outFile);
      try {
        stream.write(decrypted);
      } finally {
        stream.close();
      }
    }
  }

  @Argument(metaVar = "command", required = true, handler = SubCommandHandler.class,
      usage = "The subcommand to run")
  @SubCommands({
      @SubCommand(name = "encrypt", impl = EncryptCommand.class),
      @SubCommand(name = "decrypt", impl = DecryptCommand.class)
      })
  Command command;
}
