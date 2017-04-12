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

import com.google.cloud.crypto.tink.subtle.SubtleUtil;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Paths;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.OptionDef;
import org.kohsuke.args4j.spi.OptionHandler;
import org.kohsuke.args4j.spi.Parameters;
import org.kohsuke.args4j.spi.Setter;

/**
 * A {@code OptionHandle} that can handle input stream option.
 */
public class InputStreamHandler extends OptionHandler<InputStream> {
  public InputStreamHandler(
      final CmdLineParser parser,
      final OptionDef option,
      final Setter<InputStream> setter) {
    super(parser, option, setter);
  }

  @Override
  public final int parseArguments(final Parameters params) throws CmdLineException {
    final String token = params.getParameter(0);
    try {
      File inFile = Paths.get(token).toFile();
      SubtleUtil.validateNotExist(inFile);
      setter.addValue(new FileInputStream(inFile));
    } catch (IOException e) {
      throw new CmdLineException(owner, e.getMessage(), e);
    }
    return 1;
  }

  @Override
  public String getDefaultMetaVariable() {
    return "";
  }
}
