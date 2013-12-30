//
//  CKEViewController.m
//  CertKeychainExample
//
//  Created by Jerica Truax on 10/24/13.
//  Copyright (c) 2013 Jerica Truax. All rights reserved.
//

#import "KeychainWrapper.h"
#import "CKEViewController.h"


@implementation CKEViewController

#pragma mark - View Lifecycle

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    [self importCertAndShowSummary];
}

#pragma mark - Private Methods

- (void)readCertFromBundle
{
    // Read cert from bundle resource file
    NSString* pathToCert = [NSString stringWithFormat:@"%@/%@", [[NSBundle mainBundle] resourcePath], CERT_NAME];
    
    NSLog(@"Reading cert from *.p12 file: %@", pathToCert);
    _certData = [NSData dataWithContentsOfFile:pathToCert];
}

- (void)importCertAndShowSummary
{
    // If cert doesnt exist in keychain, import it from memory
    if (![KeychainWrapper searchKeychainCopyMatchingIdentifier:CERT_ID])
    {
        NSLog(@"Storing cert in keychain");
        
        [self readCertFromBundle];
        
        if (![KeychainWrapper createKeychainValueData:_certData forIdentifier:CERT_ID])
        {
            NSLog(@"Failed to add cert to keychain");
            return;
        }
    }
    
    NSLog(@"Extracting cert from Keychain");
    NSData* storedData = [KeychainWrapper searchKeychainCopyMatchingIdentifier:CERT_ID];
    if (!storedData)
    {
        NSLog(@"Failed to extract cert from keychain");
        return;
    }
    
    NSLog(@"Extracting cert data from cert");
    SecIdentityRef idRef;
    SecTrustRef trustRef;
    OSStatus status = extractIdentityAndTrust((__bridge CFDataRef)storedData, &idRef, &trustRef, (__bridge CFStringRef)CERT_PASSCODE);
    
    if (status)
    {
        NSLog(@"Failed to extract data from cert");
        UIAlertView* alert = [[UIAlertView alloc] initWithTitle:@"Error" message:@"Error extracting data from cert" delegate:self cancelButtonTitle:@"OK" otherButtonTitles:nil];
        [alert show];
        return;
    }
    else
    {
        NSLog(@"Extracting Summary text to display");
        self.certText.text = copySummaryString(idRef);
    }

}

#pragma mark - IBActions

- (IBAction)deleteCert:(id)sender
{
    NSLog(@"Deleting cert");
    [KeychainWrapper deleteItemFromKeychainWithIdentifier:CERT_ID];
    self.certText.text = @"";
}

- (IBAction)reImportCert:(id)sender
{
    NSLog(@"Reimporting cert");
    [self importCertAndShowSummary];
}

#pragma mark - Cert services code

NSString *copySummaryString(SecIdentityRef identity)
{
    // Get the certificate from the identity.
    SecCertificateRef myReturnedCertificate = NULL;
    OSStatus status = SecIdentityCopyCertificate (identity,
                                                  &myReturnedCertificate);  // 1
    
    if (status) {
        NSLog(@"SecIdentityCopyCertificate failed.\n");
        return NULL;
    }
    
    CFStringRef certSummary = SecCertificateCopySubjectSummary
    (myReturnedCertificate);  // 2
    
    NSString* summaryString = [[NSString alloc]
                               initWithString:(__bridge NSString *)certSummary];  // 3
    
    CFRelease(certSummary);
    
    return summaryString;
}

OSStatus extractIdentityAndTrust(CFDataRef inPKCS12Data,
                                 SecIdentityRef *outIdentity,
                                 SecTrustRef *outTrust,
                                 CFStringRef keyPassword)
{
    OSStatus securityError = errSecSuccess;
    
    
    const void *keys[] =   { kSecImportExportPassphrase };
    const void *values[] = { keyPassword };
    CFDictionaryRef optionsDictionary = NULL;
    
    /* Create a dictionary containing the passphrase if one
     was specified.  Otherwise, create an empty dictionary. */
    optionsDictionary = CFDictionaryCreate(
                                           NULL, keys,
                                           values, (keyPassword ? 1 : 0),
                                           NULL, NULL);  // 1
    
    CFArrayRef items = NULL;
    securityError = SecPKCS12Import(inPKCS12Data,
                                    optionsDictionary,
                                    &items);                    // 2
    
    
    //
    if (securityError == 0) {                                   // 3
        CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex (items, 0);
        const void *tempIdentity = NULL;
        tempIdentity = CFDictionaryGetValue (myIdentityAndTrust,
                                             kSecImportItemIdentity);
        CFRetain(tempIdentity);
        *outIdentity = (SecIdentityRef)tempIdentity;
        const void *tempTrust = NULL;
        tempTrust = CFDictionaryGetValue (myIdentityAndTrust, kSecImportItemTrust);
        
        CFRetain(tempTrust);
        *outTrust = (SecTrustRef)tempTrust;
    }
    
    if (optionsDictionary)                                      // 4
        CFRelease(optionsDictionary);
    
    if (items)
        CFRelease(items);
    
    return securityError;
}

@end
