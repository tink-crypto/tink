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
import com.google.cloud.crypto.tink.aead.GoogleCloudKmsAeadKeyManager;

import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.Option;
import org.kohsuke.args4j.spi.SubCommand;
import org.kohsuke.args4j.spi.SubCommandHandler;
import org.kohsuke.args4j.spi.SubCommands;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

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
    String configFilename;
    @Option(name = "--credential", required = true, usage = "The credential file")
    String credentialFilename;
    @Argument(metaVar = "inFile", required = true, index = 0, usage = "The source file")
    String inFilename;
    @Argument(metaVar = "outFile", required = true, index = 1, usage = "The destination file")
    String outFilename;
  }

  public static class EncryptCommand extends Args implements Command {
    @Override
    public void run() throws Exception {
      Registry.INSTANCE.registerKeyManager(
        "type.googleapis.com/google.cloud.crypto.tink.GoogleCloudKmsAeadKey",
        new GoogleCloudKmsAeadKeyManager(
            new EnvelopeMeGoogleCredentialFactory(
                Files.readAllBytes(Paths.get(credentialFilename)))));

      byte[] encrypted = EnvelopeMe.encrypt(
          Files.readAllBytes(Paths.get(configFilename)),
          Files.readAllBytes(Paths.get(inFilename)));

      FileOutputStream stream = new FileOutputStream(outFilename);
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
        "type.googleapis.com/google.cloud.crypto.tink.GoogleCloudKmsAeadKey",
        new GoogleCloudKmsAeadKeyManager(
            new EnvelopeMeGoogleCredentialFactory(
                Files.readAllBytes(Paths.get(credentialFilename)))));

      byte[] decrypted = EnvelopeMe.decrypt(
          Files.readAllBytes(Paths.get(configFilename)),
          Files.readAllBytes(Paths.get(inFilename)));

      FileOutputStream stream = new FileOutputStream(outFilename);
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
