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

goog.module('tink.ConfigTest');
goog.setTestOnly('tink.ConfigTest');

const AeadCatalogue = goog.require('tink.aead.AeadCatalogue');
const AeadKeyTemplates = goog.require('tink.aead.AeadKeyTemplates');
const Config = goog.require('tink.Config');
const PbKeyTypeEntry = goog.require('proto.google.crypto.tink.KeyTypeEntry');
const PbRegistryConfig = goog.require('proto.google.crypto.tink.RegistryConfig');
const Registry = goog.require('tink.Registry');

const testSuite = goog.require('goog.testing.testSuite');

////////////////////////////////////////////////////////////////////////////////
// tests
////////////////////////////////////////////////////////////////////////////////

testSuite({
  async tearDown() {
    Registry.reset();
  },

  testGetTinkKeyTypeEntry() {
    const catalogueName = 'some_catalogue_name';
    const primitiveName = 'some_primitive_name';
    const typeUrlPrefix = 'type.googleapis.com/google.crypto.tink.';
    const keyProtoName = 'some_key_proto_name';
    const keyManagerVersion = 0;
    const newKeyAllowed = true;

    const entry = Config.getTinkKeyTypeEntry(
        catalogueName, primitiveName, keyProtoName, keyManagerVersion,
        newKeyAllowed);

    assertEquals(catalogueName, entry.getCatalogueName());
    assertEquals(primitiveName, entry.getPrimitiveName());
    assertEquals(typeUrlPrefix + keyProtoName, entry.getTypeUrl());
    assertEquals(keyManagerVersion, entry.getKeyManagerVersion());
    assertEquals(newKeyAllowed, entry.getNewKeyAllowed());
  },

  testRegister_NoCatalogue() {
    const catalogueName = 'some_nonregistered_catalogue_name';
    const primitiveName = 'some_primitive_name';
    const keyProtoName = 'some_key_proto_name';
    const keyManagerVersion = 0;
    const newKeyAllowed = true;

    const entry = Config.getTinkKeyTypeEntry(
        catalogueName, primitiveName, keyProtoName, keyManagerVersion,
        newKeyAllowed);
    try {
      Config.register(entry);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(
          ExceptionText.nonRegisteredCatalogue(catalogueName), e.toString());
    }
  },

  testRegister_missingEntry() {
    try {
      Config.register();
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.undefinedEntry(), e.toString());
    }

    try {
      Config.register(null);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.undefinedEntry(), e.toString());
    }
  },

  testRegister_entryMissingPrimitiveName() {
    const entry = new PbKeyTypeEntry()
                      .setCatalogueName('some_catalogue_name')
                      .setTypeUrl('some_type_url')
                      .setKeyManagerVersion(0)
                      .setNewKeyAllowed(true);

    try {
      Config.register(entry);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.primitiveNameMissing(), e.toString());
    }
  },

  testRegister_entryMissingCatalogueName() {
    const entry = new PbKeyTypeEntry()
                      .setPrimitiveName('some_primitive_name')
                      .setTypeUrl('some_type_url')
                      .setKeyManagerVersion(0)
                      .setNewKeyAllowed(true);

    try {
      Config.register(entry);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.catalogueNameMissing(), e.toString());
    }
  },

  testRegister_entryMissingTypeUrl() {
    const entry = new PbKeyTypeEntry()
                      .setPrimitiveName('some_primitive_name')
                      .setCatalogueName('some_catalgoue_name')
                      .setKeyManagerVersion(0)
                      .setNewKeyAllowed(true);

    try {
      Config.register(entry);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.typeUrlMissing(), e.toString());
    }
  },

  async testRegister_withKeyTypeEntryAndNewKeysAllowed() {
    const catalogueName = 'TinkAead';
    const primitiveName = 'Aead';
    const keyProtoName = 'AesCtrHmacAeadKey';
    const typeUrl = 'type.googleapis.com/google.crypto.tink.' + keyProtoName;
    const keyManagerVersion = 0;
    const newKeyAllowed = true;

    const entry = Config.getTinkKeyTypeEntry(
        catalogueName, primitiveName, keyProtoName, keyManagerVersion,
        newKeyAllowed);

    Registry.addCatalogue(catalogueName, new AeadCatalogue());

    // Register the AesCtrHmacAead key manager.
    Config.register(entry);

    // Test the existence of key manager in registry.
    const manager = Registry.getKeyManager(typeUrl);
    assertTrue(manager != null);

    // Test that new keys are allowed for this key manager.
    const template = AeadKeyTemplates.aes256CtrHmacSha256();
    const key = await Registry.newKeyData(template);
    assertTrue(key != null);
  },

  async testRegister_withKeyTypeEntryAndNewKeysDisallowed() {
    const catalogueName = 'TinkAead';
    const primitiveName = 'Aead';
    const keyProtoName = 'AesCtrHmacAeadKey';
    const typeUrl = 'type.googleapis.com/google.crypto.tink.' + keyProtoName;
    const keyManagerVersion = 0;
    const newKeyAllowed = false;

    const entry = Config.getTinkKeyTypeEntry(
        catalogueName, primitiveName, keyProtoName, keyManagerVersion,
        newKeyAllowed);

    Registry.addCatalogue(catalogueName, new AeadCatalogue());

    // Register the AesCtrHmacAead key manager.
    Config.register(entry);

    // Test the existence of key manager in registry.
    const manager = Registry.getKeyManager(typeUrl);
    assertTrue(manager != null);

    // Test that new keys are not allowed for this key manager.
    const template = AeadKeyTemplates.aes256CtrHmacSha256();
    try {
      await Registry.newKeyData(template);
      fail('An exception should be thrown.');
    } catch (e) {
      assertEquals(ExceptionText.newKeyForbidden(typeUrl), e.toString());
    }
  },

  testRegister_withRegistryConfig() {
    const catalogueName = 'TinkAead';
    const primitiveName = 'Aead';
    const keyProtoName = 'AesCtrHmacAeadKey';
    const typeUrl = 'type.googleapis.com/google.crypto.tink.' + keyProtoName;
    const keyManagerVersion = 0;
    const newKeyAllowed = true;

    const entry = Config.getTinkKeyTypeEntry(
        catalogueName, primitiveName, keyProtoName, keyManagerVersion,
        newKeyAllowed);
    const registryConfig =
        new PbRegistryConfig().setConfigName('Test_aead_config');
    registryConfig.addEntry(entry);

    Registry.addCatalogue(catalogueName, new AeadCatalogue());

    // Register the AesCtrHmacAead key manager.
    Config.register(registryConfig);

    // Test the existence of key manager in registry.
    const manager = Registry.getKeyManager(typeUrl);
    assertTrue(manager != null);
  },
});

////////////////////////////////////////////////////////////////////////////////
// helper functions and classes for tests
////////////////////////////////////////////////////////////////////////////////

/**
 * Class which holds texts for each type of exception.
 * @final
 */
class ExceptionText {
  /** @return {string} */
  static undefinedEntry() {
    return 'CustomError: A non-null KeyTypeEntry or RegistryConfig proto ' +
        'has to be provided.';
  }

  /** @return {string} */
  static primitiveNameMissing() {
    return 'CustomError: Invalid KeyTypeEntry proto: missing primitive name.';
  }

  /** @return {string} */
  static catalogueNameMissing() {
    return 'CustomError: Invalid KeyTypeEntry proto: missing catalogue name.';
  }

  /** @return {string} */
  static typeUrlMissing() {
    return 'CustomError: Invalid KeyTypeEntry proto: missing type url.';
  }

  /**
   * @param {string} catalogueName
   *
   * @return {string}
   */
  static nonRegisteredCatalogue(catalogueName) {
    return 'CustomError: Catalogue with name ' + catalogueName +
        ' has not been added.';
  }

  /**
   * @param {string} keyType
   *
   * @return {string}
   */
  static newKeyForbidden(keyType) {
    return 'CustomError: New key operation is forbidden for key type: ' +
        keyType + '.';
  }
}
