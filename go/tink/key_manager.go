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
package tink

import (
  "github.com/golang/protobuf/proto"
  tinkpb "github.com/google/tink/proto/tink_go_proto"
)

/**
 * KeyManager "understands" keys of a specific key types: it can
 * generate keys of a supported type and create primitives for
 * supported keys.  A key type is identified by the global name of the
 * protocol buffer that holds the corresponding key material, and is
 * given by type_url-field of KeyData-protocol buffer.
 */
type KeyManager interface {
  /**
   * Constructs a primitive instance for the key given in {@code serializedKey},
   * which must be a serialized key protocol buffer handled by this manager.
   *
   * @return the new constructed primitive instance.
   */
  GetPrimitiveFromSerializedKey(serializedKey []byte) (interface{}, error)

  /**
   * Constructs a primitive instance for the key given in {@code key}.
   *
   * @return the new constructed primitive instance.
   */
  GetPrimitiveFromKey(key proto.Message) (interface{}, error)

  /**
   * Generates a new key according to specification in {@code serializedKeyFormat},
   * which must be a serialized key format protocol buffer handled by this manager.
   *
   * @return the new generated key.
   */
  NewKeyFromSerializedKeyFormat(serializedKeyFormat []byte) (proto.Message, error)

  /**
   * Generates a new key according to specification in {@code keyFormat}.
   *
   * @return the new generated key.
   */
  NewKeyFromKeyFormat(keyFormat proto.Message) (proto.Message, error)

  /**
   * @return true iff this KeyManager supports key type identified by {@code typeUrl}.
   */
  DoesSupport(typeUrl string) bool

  /**
   * @return the type URL that identifes the key type of keys managed by this KeyManager.
   */
  GetKeyType() string

  // APIs for Key Management

  /**
   * Generates a new {@code KeyData} according to specification in {@code serializedkeyFormat}.
   * This should be used solely by the key management API.
   *
   * @return the new generated key.
   */
  NewKeyData(serializedKeyFormat []byte) (*tinkpb.KeyData, error)
}