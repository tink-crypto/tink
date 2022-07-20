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

#import "objc/TINKSignatureKeyTemplate.h"

#import <XCTest/XCTest.h>

#import "objc/TINKKeyTemplate.h"
#import "objc/core/TINKKeyTemplate_Internal.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

#include "absl/status/status.h"
#include "tink/util/status.h"

@interface TINKSignatureKeyTemplatesTest : XCTestCase
@end

static std::string const kTypeURL = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
static std::string const kTypeURLRsaPss =
    "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey";
static std::string const kTypeURLRsaPkcs1 =
    "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";
static std::string const kTypeURLEd25519 =
    "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";

@implementation TINKSignatureKeyTemplatesTest

- (void)testEcdsaP256KeyTemplateWithDerEncoding {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKEcdsaP256 error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURL);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

- (void)testEcdsaP256KeyTemplateWithIeeeEncoding {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKEcdsaP256Ieee error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURL);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

- (void)testEcdsaP384KeyTemplateWithDerEncoding {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKEcdsaP384 error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURL);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

- (void)testEcdsaP384KeyTemplateWithIeeeEncoding {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKEcdsaP384Ieee error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURL);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

- (void)testEcdsaP521KeyTemplateWithDerEncoding {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKEcdsaP521 error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURL);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

- (void)testEcdsaP521KeyTemplateWithIeeeEncoding {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKEcdsaP521Ieee error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURL);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

- (void)testInvalidKeyTemplate {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:(TINKSignatureKeyTemplates)-1
                                                      error:&error];
  XCTAssertNil(tpl);
  XCTAssertNotNil(error);
  XCTAssertEqual((absl::StatusCode)error.code, absl::StatusCode::kInvalidArgument);
  XCTAssertTrue([error.localizedFailureReason containsString:@"Invalid TINKSignatureKeyTemplate"]);
}

- (void)testRsaSsaPkcs13072Sha256F4KeyTemplate {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKRsaSsaPkcs13072Sha256F4
                                                      error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  error = nil;

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURLRsaPkcs1);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

- (void)testRsaSsaPkcs14096Sha512F4KeyTemplate {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKRsaSsaPkcs14096Sha512F4
                                                      error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURLRsaPkcs1);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

- (void)testRsaSsaPss3072Sha256F4KeyTemplate {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKRsaSsaPss3072Sha256Sha256F4
                                                      error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURLRsaPss);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

- (void)testRsaSsaPss4096Sha512F4KeyTemplate {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl =
      [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKRsaSsaPss4096Sha512Sha512F4
                                                      error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURLRsaPss);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

- (void)testEd25519KeyTemplate {
  NSError *error = nil;
  TINKSignatureKeyTemplate *tpl = [[TINKSignatureKeyTemplate alloc] initWithKeyTemplate:TINKEd25519
                                                                                  error:&error];
  XCTAssertNil(error);
  XCTAssertNotNil(tpl);

  XCTAssertTrue(tpl.ccKeyTemplate->type_url() == kTypeURLEd25519);
  XCTAssertTrue(tpl.ccKeyTemplate->output_prefix_type() ==
                google::crypto::tink::OutputPrefixType::TINK);
}

@end
