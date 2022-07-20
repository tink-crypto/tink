// Copyright 2022 Google LLC
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

package com.google.crypto.tink.monitoring;

import com.google.crypto.tink.annotations.Alpha;

/**
 * Interface for a monitoring client which can be registered with Tink.
 *
 * <p>A MonitoringClient is informed by Tink about certain events happening during cryptographic
 * operations. It can be registered in the Registry.
 *
 * <p>When a new primitive is created, the monitoring client will be called to create logger
 * objects. These loggers are then called on each operation of the primitive.
 *
 * <p>DO NOT USE. This API is not yet ready and may change or be removed.
 */
@Alpha
public interface MonitoringClient {

  /** Interface that logs specific API calls of a specific primitive.*/
  public interface Logger {
    public void log(int keyId, long numBytesAsInput);

    public void logFailure();
  }

  /** Function that creates Logger objects. It is called when a primitive is created. */
  public Logger createLogger(MonitoringKeysetInfo keysetInfo, String primitive, String api);
}
