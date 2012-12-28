//
//  ADLViewController.m
//  LiberSignOpenSSL
//
//  Created by Emmanuel Peralta on 10/12/12.
//  Copyright (c) 2012 Emmanuel Peralta. All rights reserved.
//

#import "ADLViewController.h"
#import <AJNotificationView.h>

@interface ADLViewController ()

@end

@implementation ADLViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    [AJNotificationView showNoticeInView:self.view
                                    type:AJNotificationTypeGreen
                                   title:@"Une erreur s'est produite."
                         linedBackground:AJLinedBackgroundTypeStatic
                               hideAfter:2.5f];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
