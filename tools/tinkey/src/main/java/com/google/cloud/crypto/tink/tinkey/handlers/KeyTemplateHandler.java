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

import com.google.cloud.crypto.tink.TinkProto.KeyTemplate;
import com.google.cloud.crypto.tink.subtle.SubtleUtil;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.OptionDef;
import org.kohsuke.args4j.spi.OptionHandler;
import org.kohsuke.args4j.spi.Parameters;
import org.kohsuke.args4j.spi.Setter;

/**
 * A {@code OptionHandle} that can handle {@code KeyTemplate} in text format.
 */
public class KeyTemplateHandler extends OptionHandler<KeyTemplate> {
  public KeyTemplateHandler(
      final CmdLineParser parser,
      final OptionDef option,
      final Setter<KeyTemplate> setter) {
    super(parser, option, setter);
  }

  @Override
  public final int parseArguments(final Parameters params) throws CmdLineException {
    final String token = params.getParameter(0);
    Path keyTemplatePath = Paths.get(token);
    try {
      SubtleUtil.validateExists(keyTemplatePath.toFile());
      setter.addValue(TinkeyUtil.readKeyTemplateFromTextFile(keyTemplatePath));
    } catch (IOException e) {
      throw new CmdLineException(owner, e.getMessage(), e);
    }
    return 1;
  }

  @Override
  public String getDefaultMetaVariable() {
    return "aes-128-gcm.proto";
  }
}
