//
//  ADLAppDelegate.h
//  LiberSignOpenSSL
//
//  Created by Emmanuel Peralta on 10/12/12.
//  Copyright (c) 2012 Emmanuel Peralta. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface ADLAppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;

@property (readonly, strong, nonatomic) NSManagedObjectContext *managedObjectContext;
@property (readonly, strong, nonatomic) NSManagedObjectModel *managedObjectModel;
@property (readonly, strong, nonatomic) NSPersistentStoreCoordinator *persistentStoreCoordinator;

- (void)saveContext;
- (NSURL *)applicationDocumentsDirectory;

@end
