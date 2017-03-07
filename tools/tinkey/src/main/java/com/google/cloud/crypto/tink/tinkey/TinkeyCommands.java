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

package com.google.cloud.crypto.tink.tinkey;

import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.spi.SubCommand;
import org.kohsuke.args4j.spi.SubCommandHandler;
import org.kohsuke.args4j.spi.SubCommands;

/**
 * Defines the different sub-commands and their parameters, for command-line invocation.
 */
class TinkeyCommands {
  @Argument(metaVar = "command", required = true, handler = SubCommandHandler.class,
      usage = "Command to run")
  @SubCommands({
      @SubCommand(name = "add", impl = AddCommand.class),
      @SubCommand(name = "change-master-key", impl = ChangeMasterKeyCommand.class),
      @SubCommand(name = "create", impl = CreateCommand.class),
      @SubCommand(name = "create-public-keyset", impl = CreatePublicKeysetCommand.class),
      @SubCommand(name = "create-key-template", impl = CreateKeyTemplateCommand.class),
      @SubCommand(name = "destroy", impl = DestroyCommand.class),
      @SubCommand(name = "disable", impl = DisableCommand.class),
      @SubCommand(name = "enable", impl = EnableCommand.class),
      @SubCommand(name = "list", impl = ListCommand.class),
      @SubCommand(name = "rotate", impl = RotateCommand.class),
  })
  Command command;
}
