/**
 * Copyright 2019 Google Inc.
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

#import "AeadPrimitive.h"

#import "Tink/TINKAead.h"
#import "Tink/TINKAeadFactory.h"
#import "Tink/TINKAeadKeyTemplate.h"
#import "Tink/TINKKeysetHandle.h"

@implementation AeadPrimitive

- (instancetype)init {
  if ((self = [super init])) {
    NSError *error = nil;

    // Generate an AEAD key template for AES 128 GCM.
    TINKAeadKeyTemplate *tpl = [[TINKAeadKeyTemplate alloc] initWithKeyTemplate:TINKAes128Gcm
                                                                          error:&error];
    if (!tpl || error) {
      NSLog(@"Failed to generate tink AEAD key template, error: %@", error);
      return nil;
    }

    // Get a keyset handle from the key template.
    TINKKeysetHandle *handle = [[TINKKeysetHandle alloc] initWithKeyTemplate:tpl error:&error];
    if (!handle || error) {
      NSLog(@"Failed to get keyset handle from key template, error: %@", error);
      return nil;
    }

    // Use the keyset handle to get an AEAD primitive. You can use the primitive to encrypt/decrypt
    // data.
    id<TINKAead> aead = [TINKAeadFactory primitiveWithKeysetHandle:handle error:&error];
    if (!aead || error) {
      NSLog(@"Failed to get AEAD primitive, error: %@", error);
      return nil;
    }
    _tinkAead = aead;
  }
  return self;
}

- (NSData *)encryptUTF8String:(NSString *)plaintext error:(NSError **)error {
  // Convert the UTF-8 string to NSData.
  NSData *plaintextData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];

  // Encrypt.
  NSData *ciphertextData = [self.tinkAead encrypt:plaintextData withAdditionalData:nil error:error];
  if (!ciphertextData || *error) {
    NSLog(@"Failed to encrypt plaintext, error: %@", *error);
    return nil;
  }
  return ciphertextData;
}

- (NSString *)decryptToUTF8String:(NSData *)ciphertextData error:(NSError **)error {
  // Decrypt the ciphertext using the AEAD primitive.
  NSData *decryptedData = [self.tinkAead decrypt:ciphertextData withAdditionalData:nil error:error];
  if (!decryptedData || *error) {
    NSLog(@"Failed to decrypt ciphertext, error: %@", *error);
    return nil;
  }

  // Convert the decrypted data to a UTF-8 string.
  if ([decryptedData length] == 0) {
    return @"";
  }
  return [NSString stringWithUTF8String:[decryptedData bytes]];
}

@end
