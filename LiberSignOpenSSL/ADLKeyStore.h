//
//  ADLKeyStore.h
//  LiberSignOpenSSL
//
//  Created by Emmanuel Peralta on 27/12/12.
//  Copyright (c) 2012 Emmanuel Peralta. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ADLKeyStore : NSObject {
    NSManagedObjectContext *managedObjectContext;
}

/* Only usable on the soft KeyStore*/

@property (nonatomic, retain) NSManagedObjectContext *managedObjectContext;

-(NSArray*)listPrivateKeys;
-(void)addKey:(NSString*)p12Path withPassword:(NSString*)password andData:(NSData*)data;

@end

