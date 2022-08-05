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

import com.google.crypto.tink.aead.AeadConfig;
import java.security.GeneralSecurityException;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;

/**
 * A command-line tool that can encrypt and decrypt small files with AES128-GCM.
 *
 * <p>This application uses the <a href="https://github.com/google/tink">Tink<a/> crypto library.
 */
public final class HelloWorld {
  public static void main(String[] args) throws Exception {
    // Register all AEAD key types with the Tink runtime.
    AeadConfig.register();

    Commands commands = new Commands();
    CmdLineParser parser = new CmdLineParser(commands);
    try {
      parser.parseArgument(args);
    } catch (CmdLineException e) {
      System.out.println(e);
      e.getParser().printUsage(System.out);
      System.exit(1);
    }
    try {
      commands.command.run();
    } catch (GeneralSecurityException e) {
      System.out.println("Cannot encrypt or decrypt, got error: " + e.toString());
      System.exit(1);
    }
  }

  private HelloWorld() {}
}
