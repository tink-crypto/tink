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

import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.spi.SubCommand;
import org.kohsuke.args4j.spi.SubCommandHandler;
import org.kohsuke.args4j.spi.SubCommands;

/**
 * Defines the different sub-commands and their parameters, for command-line invocation.
 */
public final class TinkeyCommands {
  @Argument(
      metaVar = "command",
      required = true,
      handler = SubCommandHandler.class,
      usage = "Command to run")
  @SubCommands({
    @SubCommand(name = "help", impl = HelpCommand.class),
    @SubCommand(name = "add-key", impl = AddKeyCommand.class),
    @SubCommand(name = "convert-keyset", impl = ConvertKeysetCommand.class),
    @SubCommand(name = "create-keyset", impl = CreateKeysetCommand.class),
    @SubCommand(name = "create-public-keyset", impl = CreatePublicKeysetCommand.class),
    @SubCommand(name = "delete-key", impl = DeleteKeyCommand.class),
    @SubCommand(name = "destroy-key", impl = DestroyKeyCommand.class),
    @SubCommand(name = "disable-key", impl = DisableKeyCommand.class),
    @SubCommand(name = "enable-key", impl = EnableKeyCommand.class),
    @SubCommand(name = "list-keyset", impl = ListKeysetCommand.class),
    @SubCommand(name = "list-key-templates", impl = ListKeyTemplatesCommand.class),
    @SubCommand(name = "rotate-keyset", impl = RotateKeysetCommand.class),
    @SubCommand(name = "promote-key", impl = PromoteKeyCommand.class),
  })
  Command command;
}
