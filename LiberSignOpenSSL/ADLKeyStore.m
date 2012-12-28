//
//  ADLKeyStore.m
//  LiberSignOpenSSL
//
//  Created by Emmanuel Peralta on 27/12/12.
//  Copyright (c) 2012 Emmanuel Peralta. All rights reserved.
//

#import "ADLKeyStore.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/bio.h>
#include <openssl/cms.h>

#import "PrivateKey.h"
#import <CoreData/CoreData.h>

@implementation ADLKeyStore
@synthesize managedObjectContext;


NSData* X509_to_NSData(X509 *cert) {
    unsigned char *cert_data = NULL;
    BIO * mem = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mem, cert);
    (void)BIO_flush(mem);
    int base64Length = BIO_get_mem_data(mem, &cert_data);
    NSData *retVal = [NSData dataWithBytes:cert_data length:base64Length];
    return retVal;
}

- (NSString *)findOrCreateDirectory:(NSSearchPathDirectory)searchPathDirectory
                           inDomain:(NSSearchPathDomainMask)domainMask
                appendPathComponent:(NSString *)appendComponent
                              error:(NSError **)errorOut
{
    // Search for the path
    NSArray* paths = NSSearchPathForDirectoriesInDomains(
                                                         searchPathDirectory,
                                                         domainMask,
                                                         YES);
    if ([paths count] == 0)
    {
        // *** creation and return of error object omitted for space
        return nil;
    }
    
    // Normally only need the first path
    NSString *resolvedPath = [paths objectAtIndex:0];
    
    if (appendComponent)
    {
        resolvedPath = [resolvedPath
                        stringByAppendingPathComponent:appendComponent];
    }
    
    // Create the path if it doesn't exist
    NSError *error;
    BOOL success = [[NSFileManager defaultManager]
                    createDirectoryAtPath:resolvedPath
                    withIntermediateDirectories:YES
                    attributes:nil
                    error:&error];
    if (!success)
    {
        if (errorOut)
        {
            *errorOut = error;
        }
        return nil;
    }
    
    // If we've made it this far, we have a success
    if (errorOut)
    {
        *errorOut = nil;
    }
    return resolvedPath;
}

- (NSURL *)applicationDataDirectory
{
    NSString *appBundleId = [[NSBundle mainBundle] bundleIdentifier];
    
    NSError *error;
    NSString *result =
    [self
     findOrCreateDirectory:NSApplicationSupportDirectory
     inDomain:NSUserDomainMask
     appendPathComponent:appBundleId
     error:&error];
    if (error)
    {
        NSLog(@"Unable to find or create application support directory:\n%@", error);
    }
    return [NSURL fileURLWithPath:result];
}


-(void)recursiveCopyURL:(NSURL*)from toUrl:(NSURL*)to {
    NSFileManager* fileManager = [NSFileManager defaultManager]
    ;
    NSArray *fileList = [fileManager contentsOfDirectoryAtPath:[from path] error:nil];
    for (NSString *s in fileList) {
        NSURL *newFileURL = [to URLByAppendingPathComponent:s];
        NSURL *oldFileURL = [from URLByAppendingPathComponent:s];
        if (![fileManager fileExistsAtPath:[newFileURL path]]) {
            //File does not exist, copy it
            [fileManager copyItemAtPath:[oldFileURL path] toPath:[newFileURL path] error:nil];
        } else {
            // NSLog(@"File exists: %@", [newFileURL path]);
        }
    }
}

-(void) resetKeyStore {
    NSArray *pkeys = [self listPrivateKeys];
    for (PrivateKey *key in pkeys) {
        [self.managedObjectContext deleteObject:key];
    }
    NSError *error;
    if (![self.managedObjectContext save:&error]) {
        // Something's gone seriously wrong
        NSLog(@"Error clearing KeyStore: %@", [error localizedDescription]);
        
    }
}

-(NSArray*) listPrivateKeys {
    NSEntityDescription *entity = [NSEntityDescription entityForName:@"PrivateKey" inManagedObjectContext:self.managedObjectContext];
    NSFetchRequest *request = [[NSFetchRequest alloc] init];
    [request setEntity:entity];
    NSSortDescriptor *sortDescriptor = [[NSSortDescriptor alloc] initWithKey:@"commonName" ascending:YES];
    NSArray *sortDescriptors = [NSArray arrayWithObject:sortDescriptor];
    [sortDescriptor release];
    [request setSortDescriptors:sortDescriptors];
    // Fetch the records and handle an error
    NSError *error;
    NSArray *pkeys = [self.managedObjectContext executeFetchRequest:request error:&error];
    [request release];
    return pkeys;
}


-(NSData*)PKCS7Sign:(NSString*)p12Path withPassword:(NSString*)password andData:(NSData*)data {
    /* Read PKCS12 */
    FILE *fp;
    EVP_PKEY *pkey;
    X509 *cert;
    STACK_OF(X509) *ca = NULL;
    PKCS12 *p12;
    int i = 0;
    
    
    const char *p12_file_path = [p12Path cStringUsingEncoding:NSUTF8StringEncoding];
    const char *p12_password = [password cStringUsingEncoding:NSUTF8StringEncoding];
    
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    EVP_add_digest(EVP_sha1());
    
    if (!(fp = fopen(p12_file_path, "rb"))) {
        fprintf(stderr, "Error opening file %s\n", p12_file_path);
        exit(1);
    }
    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose (fp);
    if (!p12) {
        fprintf(stderr, "Error reading PKCS#12 file\n");
        ERR_print_errors_fp(stderr);
        exit (1);
    }
    if (!PKCS12_parse(p12, p12_password, &pkey, &cert, &ca)) {
        // should notify that the password is probably wrong
        fprintf(stderr, "Error parsing PKCS#12 file\n");
        ERR_print_errors_fp(stderr);
        exit (1);
    }
    PKCS12_free(p12);
    
    if (pkey) {
     //  fprintf(stdout, "***Private Key***\n");
     //  PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
    }
    if (cert) {
        //fprintf(stdout, "***User Certificate***\n");
        //PEM_write_X509_AUX(stdout, cert);
        int len = 0;
        unsigned char *alias = X509_alias_get0(cert, &len);
        printf("%s", alias);
        
    }
    /*
    if (ca && sk_X509_num(ca)) {
        fprintf(stdout, "***Other Certificates***\n");
        for (i = 0; i < sk_X509_num(ca); i++) {
            //PEM_write_X509_AUX(stdout, sk_X509_value(ca, i));
            int len = 0;
            
            unsigned char *alias = X509_alias_get0(sk_X509_value(ca, i), &len);
            printf("%s", alias);
            
        }
    }*/
    
    /* generate a dumb signature */
    BIO * bio_data = BIO_new(BIO_s_mem());
    
    BIO_write(bio_data, [data bytes], [data length]);
    
    
    PKCS7 *p7 = PKCS7_new();
	PKCS7_set_type(p7,NID_pkcs7_signed);
    
	PKCS7_SIGNER_INFO *si=PKCS7_add_signature(p7,cert,pkey,EVP_sha1());
	if (si == NULL) goto err;
    
	/* If you do this then you get signing time automatically added */
	PKCS7_add_signed_attribute(si, NID_pkcs9_contentType, V_ASN1_OBJECT,
                               OBJ_nid2obj(NID_pkcs7_data));
    
	/* we may want to add more */
	PKCS7_add_certificate(p7, cert);
    
	/* Set the content of the signed to 'data' */
	PKCS7_content_new(p7, NID_pkcs7_data);
    
    PKCS7_set_detached(p7,1);
    BIO* p7bio;
	
    if ((p7bio=PKCS7_dataInit(p7,NULL)) == NULL) goto err;
    
    char buf[255];
	for (;;)
    {
		i=BIO_read(bio_data,buf,sizeof(buf));
		if (i <= 0) break;
		BIO_write(p7bio,buf,i);
    }
    
	if (!PKCS7_dataFinal(p7,p7bio)) goto err;
	BIO_free(p7bio);
    
    //TODO: write the signature in NSString + base 64 through bio or NSString+Base64.
    // 
    PEM_write_PKCS7(stdout,p7);
	PKCS7_free(p7);
    goto end;
    
err:
    ERR_print_errors_fp(stderr);
end:
    NSLog(@"ok");
    
    
}

-(void) addKey:(NSString *)p12Path withPassword:(NSString *)password andData:(NSData*)data {
    
    /* Read PKCS12 */
    FILE *fp;
    EVP_PKEY *pkey;
    X509 *cert;
    STACK_OF(X509) *ca = NULL;
    PKCS12 *p12;
   // int i = 0;
    unsigned char *alias = NULL;

    const char *p12_file_path = [p12Path cStringUsingEncoding:NSUTF8StringEncoding];
    const char *p12_password = [password cStringUsingEncoding:NSUTF8StringEncoding];
    
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    EVP_add_digest(EVP_sha1());
    
    if (!(fp = fopen(p12_file_path, "rb"))) {
        fprintf(stderr, "Error opening file %s\n", p12_file_path);
        exit(1);
    }
    p12 = d2i_PKCS12_fp(fp, NULL);
    fclose (fp);
    if (!p12) {
        fprintf(stderr, "Error reading PKCS#12 file\n");
        ERR_print_errors_fp(stderr);
        exit (1);
    }
    if (!PKCS12_parse(p12, p12_password, &pkey, &cert, &ca)) {
        fprintf(stderr, "Error parsing PKCS#12 file\n");
        ERR_print_errors_fp(stderr);
        exit (1);
    }
    PKCS12_free(p12);
    /*if (!(fp = fopen(argv[3], "w"))) {
        fprintf(stderr, "Error opening file %s\n", argv[1]);
        exit(1);
    }*/
    if (pkey) {
      //  fprintf(stdout, "***Private Key***\n");
       // PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
    }
    if (cert) {
       // fprintf(stdout, "***User Certificate***\n");
       // PEM_write_X509_AUX(stdout, cert);
        int len = 0;
        alias = X509_alias_get0(cert, &len);
        
    }
    if (ca && sk_X509_num(ca)) {
       // fprintf(stdout, "***Other Certificates***\n");
        //for (i = 0; i < sk_X509_num(ca); i++) {
            //PEM_write_X509_AUX(stdout, sk_X509_value(ca, i));
           // int len = 0;

           //  unsigned char *alias = X509_alias_get0(sk_X509_value(ca, i), &len);
           //  printf("%s", alias);

        //}
    }
    
    
    // prepare data for the PrivateKey Entity
    NSData *cert_data_to_store = X509_to_NSData(cert);
    
    X509_NAME *issuer_name = X509_get_issuer_name(cert);
    ASN1_INTEGER* cert_serial_number = X509_get_serialNumber(cert);
    BIGNUM *bnser = ASN1_INTEGER_to_BN(cert_serial_number, NULL);
  
    char* big_number_serial_str = BN_bn2hex(bnser);
    
    long serial_number_int =  ASN1_INTEGER_get(cert_serial_number);
    char issuer_name_str[256];
    
    X509_NAME_oneline(issuer_name, issuer_name_str, 256);
    
    
    NSEntityDescription *entityDescription = [NSEntityDescription
                                              entityForName:@"PrivateKey" inManagedObjectContext:self.managedObjectContext];
    NSFetchRequest *request = [[NSFetchRequest alloc] init];
    [request setEntity:entityDescription];
    
    NSString *commonName_to_find = [NSString stringWithCString:(const char*)alias encoding:NSUTF8StringEncoding];
    NSPredicate *predicate = [NSPredicate predicateWithFormat:
                              @"commonName=%@ AND caName=%@ AND serialNumber=%@",
                              commonName_to_find,
                              [NSString stringWithCString:(const char*)issuer_name_str encoding:NSUTF8StringEncoding],
                              [NSString stringWithCString:(const char*)big_number_serial_str encoding:NSUTF8StringEncoding]];
    [request setPredicate:predicate];
    

    
    
    
    NSError *error = nil;
    NSArray *array = [self.managedObjectContext executeFetchRequest:request error:&error];
    if (error) {
        NSLog(@"Error fetching keys: %@", [error localizedDescription]);
    }
    
    [request release];
    if ([array count] == 0) {

        // copy the file to applicationDataDirectory
        [[NSFileManager defaultManager] copyItemAtPath:p12Path toPath:[[self applicationDataDirectory] path] error:&error];
        NSString *p12filename = [p12Path lastPathComponent];
        
        // generate an entry for the new Key
        PrivateKey *new_pk = [NSEntityDescription insertNewObjectForEntityForName:@"PrivateKey" inManagedObjectContext:self.managedObjectContext];
        new_pk.p12Filename = [[[self applicationDataDirectory] path] stringByAppendingPathComponent:p12filename];
        new_pk.publicKey = cert_data_to_store;
        new_pk.commonName = [NSString stringWithCString:(const char*)alias encoding:NSUTF8StringEncoding];
        new_pk.caName = [NSString stringWithCString:(const char*)issuer_name_str encoding:NSUTF8StringEncoding];
        new_pk.serialNumber = [NSString stringWithCString:(const char*)big_number_serial_str encoding:NSUTF8StringEncoding];
        
        error = nil;
        if (![self.managedObjectContext save:&error]) {
            // Something's gone seriously wrong
            NSLog(@"Error saving new PrivateKey: %@", [error localizedDescription]);
        
        }
    }
    else {
        NSLog(@"Object already in KeyStore %@", [[array objectAtIndex:0] commonName]);
    }




}
@end
