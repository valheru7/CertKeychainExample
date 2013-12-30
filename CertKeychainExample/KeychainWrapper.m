//
//  KeychainWrapper.m
//  ChristmasKeeper
//
//  Created by Chris Lowe on 10/31/11.
//  Copyright (c) 2011 USAA. All rights reserved.
//

#import "KeychainWrapper.h"

@implementation KeychainWrapper
// *** NOTE *** This class is ARC compliant - any references to CF classes must be paired with a "__bridge" statement to 
// cast between Objective-C and Core Foundation Classes.  WWDC 2011 Video "Introduction to Automatic Reference Counting" explains this
// *** END NOTE ***


+ (NSMutableDictionary *)setupSearchDirectoryForIdentifier:(NSString *)identifier {
    
    // Setup dictionary to access keychain
    NSMutableDictionary *searchDictionary = [[NSMutableDictionary alloc] init];  
    // Specify we are using a Password (vs Certificate, Internet Password, etc)
    [searchDictionary setObject:(__bridge id)kSecClassCertificate forKey:(__bridge id)kSecClass];
    //[searchDictionary setObject:APP_NAME forKey:(__bridge id)kSecAttrAccount];
	
    // Uniquely identify the account who will be accessing the keychain
    NSData *encodedIdentifier = [identifier dataUsingEncoding:NSUTF8StringEncoding];
    [searchDictionary setObject:encodedIdentifier forKey:(__bridge id)kSecAttrLabel];
	
    return searchDictionary; 
}

+ (NSData *)searchKeychainCopyMatchingIdentifier:(NSString *)identifier {
   
    NSMutableDictionary *searchDictionary = [self setupSearchDirectoryForIdentifier:identifier];
    // Limit search results to one
    [searchDictionary setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];
	
    // Specify we want NSData/CFData returned
    [searchDictionary setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnData];
    
    //[searchDictionary setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnAttributes];
	
    // Search
    NSData *result = nil;   
    CFTypeRef foundDict = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)searchDictionary, &foundDict);
    
    if (status == noErr) {
        result = (__bridge_transfer NSData *)foundDict;
    } else {
        result = nil;
    }
    
    return result;
}


+ (BOOL)createKeychainValueData:(NSData *)value forIdentifier:(NSString *)identifier {
    
    NSMutableDictionary *dictionary = [self setupSearchDirectoryForIdentifier:identifier];
    //NSData *valueData = [value dataUsingEncoding:NSUTF8StringEncoding];
    [dictionary setObject:value forKey:(__bridge id)kSecValueData];
    
    
    // Protect the keychain entry so its only valid when the device is unlocked
    //[dictionary setObject:(__bridge id)kSecAttrAccessibleWhenUnlocked forKey:(__bridge id)kSecAttrAccessible];
    
    // Add
    CFTypeRef result;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)dictionary, &result);
	
    // If the Addition was successful, return.  Otherwise, attempt to update existing key or quit (return NO)
    if (status == errSecSuccess) {
        return YES;
    } else if (status == errSecDuplicateItem){
        return [self updateKeychainValueData:value forIdentifier:identifier];
    } else {
        return NO;
    }
}

+ (BOOL)updateKeychainValueData:(NSData *)value forIdentifier:(NSString *)identifier {
    
    NSMutableDictionary *searchDictionary = [self setupSearchDirectoryForIdentifier:identifier];
    NSMutableDictionary *updateDictionary = [[NSMutableDictionary alloc] init];
    //NSData *valueData = [value dataUsingEncoding:NSUTF8StringEncoding];
    [updateDictionary setObject:value forKey:(__bridge id)kSecValueData];
	
    // Update
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)searchDictionary,
                                    (__bridge CFDictionaryRef)updateDictionary);
	
    if (status == errSecSuccess) {
        return YES;
    } else {
        return NO;
    }
}

+ (void)deleteItemFromKeychainWithIdentifier:(NSString *)identifier {
    NSMutableDictionary *searchDictionary = [self setupSearchDirectoryForIdentifier:identifier];
    CFDictionaryRef dictionary = (__bridge CFDictionaryRef)searchDictionary;
    
    //Delete
    SecItemDelete(dictionary);
}

@end
