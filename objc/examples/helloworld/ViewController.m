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

#import "ViewController.h"

#import "AeadPrimitive.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
  [super viewDidLoad];

  self.aead = [[AeadPrimitive alloc] init];
  self.ciphertext.delegate = self;
  self.decrypted.delegate = self;
}

- (IBAction)encryptButton:(id)sender {
  // Encrypt the plaintext.
  NSError *error = nil;
  NSData *ciphertext = [self.aead encryptUTF8String:self.plaintext.text error:&error];
  if (!ciphertext || error) {
    NSLog(@"Failed to encrypt plaintext, error: %@", error);
    return;
  }
  // Base64 encode the ciphertext and display it in the ciphertext UITextField.
  self.ciphertext.text = [ciphertext base64EncodedStringWithOptions:0];
}

- (IBAction)decryptButton:(id)sender {
  NSData *encryptedData = [[NSData alloc] initWithBase64EncodedString:self.ciphertext.text
                                                              options:0];

  // Decrypt the ciphertext.
  NSError *error = nil;
  NSString *decrypted = [self.aead decryptToUTF8String:encryptedData error:&error];
  if (!decrypted || error) {
    NSLog(@"Failed to decrypt ciphertext, error: %@", error);
    return;
  }
  self.decrypted.text = decrypted;
}

- (IBAction)resetButton:(id)sender {
  self.plaintext.text = @"";
  self.ciphertext.text = @"";
  self.decrypted.text = @"";
}

- (BOOL)textFieldShouldBeginEditing:(UITextField *)textField {
  BOOL editable;
  if (textField == self.plaintext || textField == self.ciphertext) {
    editable = YES;
  } else {
    editable = NO;
  }
  return editable;
}

@end
