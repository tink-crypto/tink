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

import com.google.crypto.tink.KeyTemplate;
import com.google.crypto.tink.KeyTemplates;
import java.security.GeneralSecurityException;
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
    String templateName = params.getParameter(0);

    try {
      setter.addValue(KeyTemplates.get(templateName));
      return 1;
    } catch (GeneralSecurityException ex) {
      throw new CmdLineException(owner, ex.getMessage(), ex);

    }
  }

  @Override
  public String getDefaultMetaVariable() {
    return "AES128_GCM";
  }
}
