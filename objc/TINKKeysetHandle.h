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

#import <Foundation/Foundation.h>

@class TINKKeyTemplate;
@class TINKKeysetReader;
@protocol TINKAead;

NS_ASSUME_NONNULL_BEGIN

/**
 * KeysetHandle provides abstracted access to Keysets, to limit the exposure of actual protocol
 * buffers that hold sensitive key material.
 */
@interface TINKKeysetHandle : NSObject

/**
 * Use -initWithKeysetReader:andKey:error: or -initWithTemplate:error: to get an instance of
 * TINKKeysetHandle.
 */
- (instancetype)init NS_UNAVAILABLE;

/**
 * Creates a TINKKeysetHandle from an encrypted keyset obtained via @c reader using @c aeadKey to
 * decrypt the keyset.
 *
 * @param reader  An instance of TINKKeysetReader.
 * @param aeadKey An instance of TINKAead that's used to decrypt the keyset.
 * @param error   If non-nil it will be populated with a descriptive error message.
 * @return        A TINKKeysetHandle, or nil in case of error.
 */
- (nullable instancetype)initWithKeysetReader:(TINKKeysetReader *)reader
                                       andKey:(id<TINKAead>)aeadKey
                                        error:(NSError **)error;

/**
 * Creates a TINKKeysetHandle from a serialized keyset which contains no secret key material.
 * This can be used to load public keysets or envelope encryption keysets.
 *
 * @param keyset  A serialized keyset.
 * @param error   If non-nil it will be populated with a descriptive error message.
 * @return        A TINKKeysetHandle, or nil in case of error.
 */
- (nullable instancetype)initWithNoSecretKeyset:(NSData *)keyset error:(NSError **)error;

/**
 * Returns a new TINKKeysetHandle that contains a single fresh key generated according to
 * @c keyTemplate. @c keyTemplate can be obtained by using one of the subclasses such as
 * TINKAeadKeyTemplate, TINKHybridKeyTemplate etc.
 *
 * @param keyTemplate An instance of TINKKeyTemplate that describes the key to be generated.
 *                    To get an instance of TINKKeyTemplate use one of the primitive-specific
 *                    subclasses such as: TINKAeadKeyTemplate, TINKHybridKeyTemplate etc.
 * @param error       If non-nil it will be populated with a descriptive error message.
 * @return            A TINKKeysetHandle, or nil in case of error.
 */
- (nullable instancetype)initWithKeyTemplate:(TINKKeyTemplate *)keyTemplate error:(NSError **)error;

/**
 * Creates a TINKKeysetHandle from a keyset obtained from the iOS keychain.
 *
 * @param keysetName  The keyset name that was used to store the keyset to the iOS keychain.
 * @param error       If non-nil it will be populated with a descriptive error message.
 * @return            A TINKKeysetHandle, or nil in case of error.
 */
- (nullable instancetype)initFromKeychainWithName:(NSString *)keysetName error:(NSError **)error;

/**
 * Creates a TINKKeysetHandle from a keyset obtained from the iOS keychain.
 *
 * @param keysetName   The keyset name that was used to store the keyset to the iOS keychain.
 * @param accessGroup  Access group for keychain item used to store the keyset to the iOS keychain.
 * @param error        If non-nil it will be populated with a descriptive error message.
 * @return             A TINKKeysetHandle, or nil in case of error.
 */
- (nullable instancetype)initFromKeychainWithName:(NSString *)keysetName
                                      accessGroup:(nullable NSString *)accessGroup
                                            error:(NSError **)error;

/**
 * Returns a new TINKKeysetHandle that contains the public keys corresponding to the private keys
 * from @c aHandle.
 *
 * @param aHandle   A handle that contains private keys.
 * @param error     If non-nil it will be populated with a descriptive error message.
 * return           An instance of TINKKeysetHandle that contains the corresponding public keys or
 *                  nil in case of error.
 */
+ (nullable instancetype)publicKeysetHandleWithHandle:(TINKKeysetHandle *)aHandle
                                                error:(NSError **)error;

/**
 * Returns the serialized Keyset-proto for this TINKKeysetHandle if it contains
 * no sensitive key material.
 *
 * @param error  If non-nil it will be populated with a descriptive error
 *               message.
 * return        A serialized Keyset-proto if the instance contains no secret
 *               key material or nil in case of error.
 */
- (NSData *)serializedKeysetNoSecret:(NSError **)error;


/**
 * Writes the underlying keyset to the iOS keychain under the name specified by @c keysetName.
 * The keyset can be retrieved from the keychain by using -initFromKeychainWithName:error:.
 *
 * @param keysetName  A unique keyset name that's used to store and retrieve the keyset from the iOS
 *                    keychain. If an item with the same name exists in the keychain an error will
 *                    be returned.
 * @param overwrite   If a keyset with the same name exists in the keychain it will be overwritten
 *                    when this property is set to YES.
 * @param error       If non-nill it will be populated with a descriptive error message.
 * @return            YES if the keyset was successfully written in the keychain.
 *                    Otherwise, returns NO and sets @c error.
 */
- (BOOL)writeToKeychainWithName:(NSString *)keysetName
                      overwrite:(BOOL)overwrite
                          error:(NSError **)error;

/**
 * Writes the underlying keyset to the iOS keychain under the name specified by @c keysetName.
 * The keyset can be retrieved from the keychain by using -initFromKeychainWithName:error:.
 *
 * @param keysetName   A unique keyset name that's used to store and retrieve the keyset from the
 *                     iOS keychain. If an item with the same name exists in the keychain an error
 *                     will be returned.
 * @param accessGroup  Access group for keychain item used to store the keyset to the iOS keychain.
 * @param overwrite    If a keyset with the same name exists in the keychain it will be overwritten
 *                     when this property is set to YES.
 * @param error        If non-nill it will be populated with a descriptive error message.
 * @return             YES if the keyset was successfully written in the keychain.
 *                     Otherwise, returns NO and sets @c error.
 */
- (BOOL)writeToKeychainWithName:(NSString *)keysetName
                    accessGroup:(nullable NSString *)accessGroup
                      overwrite:(BOOL)overwrite
                          error:(NSError **)error;

/**
 * Deletes a keyset from the iOS keychain.
 *
 * @param keysetName The name of the keyset to be deleted.
 * @param error      If non-nil it will be populated with a descriptive error message.
 * @return           YES if the keyset was successfully deleted or if there was no keyset
 *                   with that name in the keychain. Otherwise, returns NO and sets @c error.
 */
+ (BOOL)deleteFromKeychainWithName:(NSString *)keysetName error:(NSError **)error;

/**
 * Deletes a keyset from the iOS keychain.
 *
 * @param keysetName The name of the keyset to be deleted.
 * @param accessGroup  Access group for keychain item used to store the keyset to the iOS keychain.
 * @param error      If non-nil it will be populated with a descriptive error message.
 * @return           YES if the keyset was successfully deleted or if there was no keyset
 *                   with that name in the keychain. Otherwise, returns NO and sets @c error.
 */
+ (BOOL)deleteFromKeychainWithName:(NSString *)keysetName
                       accessGroup:(nullable NSString *)accessGroup
                             error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END

