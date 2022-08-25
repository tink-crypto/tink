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

// TINKVersion is only available on Tink v1.3.0+
#define USING_1_3_0 0

#import "AppDelegate.h"

#import "Tink/TINKAllConfig.h"
#import "Tink/TINKConfig.h"
#if USING_1_3_0
#import "Tink/TINKVersion.h"
#endif

@interface AppDelegate ()

@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
  // Initialize Tink.
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    NSError *error = nil;

#if USING_1_3_0
    NSLog(@"Tink v%@", TINKVersion);
#endif

    // Get a config instance that enables all Tink functionality.
    TINKAllConfig *config = [[TINKAllConfig alloc] initWithError:&error];
    if (!config || error) {
      NSLog(@"Failed to init tink config, error: %@", error);
      return;
    }

    // Register the configuration.
    if (![TINKConfig registerConfig:config error:&error]) {
      NSLog(@"Failed to register tink config, error: %@", error);
      return;
    }
  });
  return YES;
}

@end
