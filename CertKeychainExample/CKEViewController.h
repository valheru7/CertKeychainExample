//
//  CKEViewController.h
//  CertKeychainExample
//
//  Created by Jerica Truax on 10/24/13.
//  Copyright (c) 2013 Jerica Truax. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface CKEViewController : UIViewController
{
    NSData* _certData;
}

@property (nonatomic, weak) IBOutlet UITextView* certText;
@property (nonatomic, weak) IBOutlet UIButton* delButton;
@property (nonatomic, weak) IBOutlet UIButton* reimpButton;

- (IBAction)deleteCert:(id)sender;
- (IBAction)reImportCert:(id)sender;

@end
