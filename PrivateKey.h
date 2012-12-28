//
//  PrivateKey.h
//  LiberSignOpenSSL
//
//  Created by Emmanuel Peralta on 28/12/12.
//  Copyright (c) 2012 Emmanuel Peralta. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreData/CoreData.h>


@interface PrivateKey : NSManagedObject

@property (nonatomic, retain) NSNumber * caName;
@property (nonatomic, retain) NSString * commonName;
@property (nonatomic, retain) NSString * p12Filename;
@property (nonatomic, retain) NSData * publicKey;
@property (nonatomic, retain) NSString * serialNumber;

@end
