import EcdsaPrivateKeyManager from 'goog:tink.signature.EcdsaPrivateKeyManager'; // from //third_party/tink/javascript/signature:ecdsa_key_managers
import SignatureKeyTemplates from 'goog:tink.signature.SignatureKeyTemplates'; // from //third_party/tink/javascript/signature:key_templates

import * as Registry from '../internal/registry';

export function register() {
  Registry.registerKeyManager(new EcdsaPrivateKeyManager());
}

export const ecdsaP256KeyTemplate = SignatureKeyTemplates.ecdsaP256;
export const ecdsaP384KeyTemplate = SignatureKeyTemplates.ecdsaP384;
export const ecdsaP521KeyTemplate = SignatureKeyTemplates.ecdsaP521;
export const ecdsaP256IeeeEncodingKeyTemplate =
    SignatureKeyTemplates.ecdsaP256IeeeEncoding;
export const ecdsaP384IeeeEncodingKeyTemplate =
    SignatureKeyTemplates.ecdsaP384IeeeEncoding;
export const ecdsaP521IeeeEncodingKeyTemplate =
    SignatureKeyTemplates.ecdsaP521IeeeEncoding;
