//
//  KeychainWrapper.h
//  ChristmasKeeper
//
//  Created by Chris Lowe on 10/31/11.
//  Copyright (c) 2011 USAA. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>

@interface KeychainWrapper : NSObject

// Generic exposed method to search the keychain for a given value.  Limit one result per search.
// NOTE: Modified to use Certificates instead of simply passwords
+ (NSData *)searchKeychainCopyMatchingIdentifier:(NSString *)identifier;

+ (BOOL)createKeychainValueData:(NSData *)value forIdentifier:(NSString *)identifier;

+ (BOOL)updateKeychainValueData:(NSData *)value forIdentifier:(NSString *)identifier;

// Delete a value in the keychain
+ (void)deleteItemFromKeychainWithIdentifier:(NSString *)identifier;

@end
