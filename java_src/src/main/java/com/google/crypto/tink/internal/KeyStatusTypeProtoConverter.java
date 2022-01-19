// Copyright 2021 Google LLC
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
package com.google.crypto.tink.internal;

import com.google.crypto.tink.tinkkey.KeyHandle.KeyStatusType;

/**
 * Util functions to facilitate conversion between the {@link KeyHandle.KeyStatusType} enum and
 * {@link KeyStatusType} proto.
 */
public final class KeyStatusTypeProtoConverter {

  /** Converts a {@link KeyStatusType} proto enum into a {@link KeyHandle.KeyStatusType} enum */
  public static KeyStatusType fromProto(
      com.google.crypto.tink.proto.KeyStatusType keyStatusTypeProto) {
    switch (keyStatusTypeProto) {
      case ENABLED:
        return KeyStatusType.ENABLED;
      case DISABLED:
        return KeyStatusType.DISABLED;
      case DESTROYED:
        return KeyStatusType.DESTROYED;
      default:
        throw new IllegalArgumentException("Unknown key status type.");
    }
  }

  /** Converts a {@link KeyHandle.KeyStatusType} enum into a {@link KeyStatusType} proto enum */
  public static com.google.crypto.tink.proto.KeyStatusType toProto(KeyStatusType status) {
    switch (status) {
      case ENABLED:
        return com.google.crypto.tink.proto.KeyStatusType.ENABLED;
      case DISABLED:
        return com.google.crypto.tink.proto.KeyStatusType.DISABLED;
      case DESTROYED:
        return com.google.crypto.tink.proto.KeyStatusType.DESTROYED;
    }
    throw new IllegalArgumentException("Unknown key status type.");
  }

  private KeyStatusTypeProtoConverter() {}
}
