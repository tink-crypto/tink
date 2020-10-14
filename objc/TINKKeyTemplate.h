/**
 * Copyright 2018 Google Inc.
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

NS_ASSUME_NONNULL_BEGIN

/**
 * Wrapper class that holds key template options that are used to generate keysets.
 * This is the base/parent class that is subclassed by all the TINKXYZKeyTemplate classes.
 *
 * To create an instance of this class you need to use one of the subclasses: TINKAeadKeyTemplate,
 * TINKHybridKeyTemplate etc.
 */
@interface TINKKeyTemplate : NSObject

/**
 * This class is not meant to be instantiated directly; instead use one of the subclasses
 * (TINKAeadKeyTemplate, TINKHybridKeyTemplate etc.) to get an instance.
 */
- (instancetype)init NS_UNAVAILABLE;

- (nullable instancetype)initWithKeyTemplate:(id)keyTemplate error:(NSError **)error NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
