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
import {Aead} from '../aead/internal/aead';
import {InvalidArgumentsException} from '../exception/invalid_arguments_exception';
import {SecurityException} from '../exception/security_exception';
import * as Random from '../subtle/random';

import * as KeyManager from './key_manager';
import {KeysetReader} from './keyset_reader';
import {KeysetWriter} from './keyset_writer';
import * as PrimitiveSet from './primitive_set';
import {PbKeyMaterialType, PbKeyset, PbKeyStatusType, PbKeyTemplate} from './proto';
import * as Registry from './registry';
import * as Util from './util';

/**
 * Keyset handle provide abstracted access to Keysets, to limit the exposure of
 * actual protocol buffers that hold sensitive key material.
 *
 * @final
 */
export class KeysetHandle {
  private readonly keyset_: PbKeyset;

  constructor(keyset: PbKeyset) {
    Util.validateKeyset(keyset);
    this.keyset_ = keyset;
  }

  /**
   * Returns a primitive that uses key material from this keyset handle. If
   * opt_customKeyManager is defined then the provided key manager is used to
   * instantiate primitives. Otherwise key manager from Registry is used.
   */
  async getPrimitive<P>(
      primitiveType: Util.Constructor<P>,
      opt_customKeyManager?: KeyManager.KeyManager<P>|null): Promise<P> {
    if (!primitiveType) {
      throw new InvalidArgumentsException('primitive type must be non-null');
    }
    const primitiveSet =
        await this.getPrimitiveSet(primitiveType, opt_customKeyManager);
    return Registry.wrap(primitiveSet);
  }

  /**
   * Creates a set of primitives corresponding to the keys with status Enabled
   * in the given keysetHandle, assuming all the correspoding key managers are
   * present (keys with status different from Enabled are skipped). If provided
   * uses customKeyManager instead of registered key managers for keys supported
   * by the customKeyManager.
   *
   * Visible for testing.
   */
  async getPrimitiveSet<P>(
      primitiveType: Util.Constructor<P>,
      opt_customKeyManager?: KeyManager.KeyManager<P>|
      null): Promise<PrimitiveSet.PrimitiveSet<P>> {
    const primitiveSet = new PrimitiveSet.PrimitiveSet<P>(primitiveType);
    const keys = this.keyset_.getKeyList();
    const keysLength = keys.length;
    for (let i = 0; i < keysLength; i++) {
      const key = keys[i];
      if (key.getStatus() === PbKeyStatusType.ENABLED) {
        const keyData = key.getKeyData();
        if (!keyData) {
          throw new SecurityException('Key data has to be non null.');
        }
        let primitive;
        if (opt_customKeyManager &&
            opt_customKeyManager.getKeyType() === keyData.getTypeUrl()) {
          primitive =
              await opt_customKeyManager.getPrimitive(primitiveType, keyData);
        } else {
          primitive = await Registry.getPrimitive<P>(primitiveType, keyData);
        }
        const entry = primitiveSet.addPrimitive(primitive, key);
        if (key.getKeyId() === this.keyset_.getPrimaryKeyId()) {
          primitiveSet.setPrimary(entry);
        }
      }
    }
    return primitiveSet;
  }

  /**
   * Encrypts the underlying keyset with the provided masterKeyAead wnd writes
   * the resulting encryptedKeyset to the given writer which must be non-null.
   *
   *
   */
  async write(writer: KeysetWriter, masterKeyAead: Aead) {
    // TODO implement
    throw new SecurityException('KeysetHandle -- write: Not implemented yet.');
  }

  /**
   * Returns the keyset held by this KeysetHandle.
   *
   */
  getKeyset(): PbKeyset {
    return this.keyset_;
  }
}

/**
 * Creates a KeysetHandle from an encrypted keyset obtained via reader, using
 * masterKeyAead to decrypt the keyset.
 *
 *
 */
export async function read(
    reader: KeysetReader, masterKeyAead: Aead): Promise<KeysetHandle> {
  // TODO implement
  throw new SecurityException('KeysetHandle -- read: Not implemented yet.');
}

/**
 * Returns a new KeysetHandle that contains a single new key generated
 * according to keyTemplate.
 *
 *
 */
export async function generateNew(keyTemplate: PbKeyTemplate):
    Promise<KeysetHandle> {
  // TODO(thaidn): move this to a key manager.
  const keyset = await generateNewKeyset_(keyTemplate);
  return new KeysetHandle(keyset);
}

/**
 * Generates a new Keyset that contains a single new key generated
 * according to keyTemplate.
 *
 */
async function generateNewKeyset_(keyTemplate: PbKeyTemplate):
    Promise<PbKeyset> {
  const key = (new PbKeyset.Key())
                  .setStatus(PbKeyStatusType.ENABLED)
                  .setOutputPrefixType(keyTemplate.getOutputPrefixType());
  const keyId = generateNewKeyId_();
  key.setKeyId(keyId);
  const keyData = await Registry.newKeyData(keyTemplate);
  key.setKeyData(keyData);
  const keyset = new PbKeyset();
  keyset.addKey(key);
  keyset.setPrimaryKeyId(keyId);
  return keyset;
}

/**
 * Generates a new random key ID.
 *
 * @return The key ID.
 */
function generateNewKeyId_(): number {
  const bytes = Random.randBytes(4);
  let value = 0;
  for (let i = 0; i < bytes.length; i++) {
    value += (bytes[i] & 255) << i * 8;
  }

  // Make sure the key ID is a positive integer smaller than 2^32.
  return Math.abs(value) % 2 ** 32;
}

/**
 * Creates a KeysetHandle from a keyset, obtained via reader, which
 * must contain no secret key material.
 *
 * This can be used to load public keysets or envelope encryption keysets.
 * Users that need to load cleartext keysets can use CleartextKeysetHandle.
 *
 */
export function readNoSecret(reader: KeysetReader): KeysetHandle {
  if (reader === null) {
    throw new SecurityException('Reader has to be non-null.');
  }
  const keyset = reader.read();
  const keyList = keyset.getKeyList();
  for (const key of keyList) {
    const keyData = key.getKeyData();
    if (keyData) {
      switch (keyData.getKeyMaterialType()) {
        case PbKeyMaterialType.ASYMMETRIC_PUBLIC:

        // fall through
        case PbKeyMaterialType.REMOTE:
          continue;
      }
    }
    throw new SecurityException('Keyset contains secret key material.');
  }
  return new KeysetHandle(keyset);
}
