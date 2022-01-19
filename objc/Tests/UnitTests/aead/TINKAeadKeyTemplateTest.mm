/**
 * Copyright 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 **************************************************************************
 */

#import "objc/TINKAeadKeyTemplate.h"

#import <XCTest/XCTest.h>

#include "tink/aead/xchacha20_poly1305_key_manager.h"

#import "objc/TINKKeyTemplate.h"
#import "objc/core/TINKKeyTemplate_Internal.h"

using google::crypto::tink::XChaCha20Poly1305KeyFormat;

@interface TINKAeadKeyTemplatesTest : XCTestCase
@end

@implementation TINKAeadKeyTemplatesTest

- (void)testAesGcmKeyTemplates {
  static std::string const kTypeURL = "type.googleapis.com/google.crypto.tink.AesGcmKey";

  NSError *error = nil;
  // AES-128 GCM
  TINKAeadKeyTemplate *tpl =
      [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes128Gcm error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURL);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);

  // AES-256 GCM
  tpl = [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes256Gcm error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURL);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);

  // AES-256 GCM RAW
  tpl = [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes256GcmNoPrefix error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURL);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::RAW);
}

- (void)testAesCtrHmacKeyTemplates {
  static std::string const kTypeURL = "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";

  // AES-128 CTR HMAC SHA-256
  NSError *error = nil;
  TINKAeadKeyTemplate *tpl =
      [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes128CtrHmacSha256 error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURL);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);

  // AES-256 CTR HMAC SHA-256
  tpl = [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes256CtrHmacSha256 error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURL);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

- (void)testAesEaxKeyTemplates {
  static std::string const kTypeURL = "type.googleapis.com/google.crypto.tink.AesEaxKey";

  NSError *error = nil;
  // AES-128 EAX
  TINKAeadKeyTemplate *tpl =
      [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes128Eax error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURL);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);

  // AES-256 EAX
  tpl = [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes256Eax error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURL);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

- (void)testXChaCha20Poly1305KeyTemplates {
  static std::string const kTypeURL = "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";

  NSError *error = nil;
  TINKAeadKeyTemplate *tpl = [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKXChaCha20Poly1305
                                                                        error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURL);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

@end
