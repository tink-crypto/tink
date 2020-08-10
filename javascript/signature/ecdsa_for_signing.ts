/**
 * @license
 * Copyright 2020 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as Registry from '../internal/registry';
import {EcdsaPrivateKeyManager} from './ecdsa_private_key_manager';
import {SignatureKeyTemplates} from './signature_key_templates';

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
