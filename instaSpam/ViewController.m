//
//  ViewController.m
//  instaSpam
//
//

#import "ViewController.h"
#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>

@implementation ViewController{
    NSString *ua,*curusr,*url2fetch;
    NSString *key;
    NSArray* nameArr;
    int asd;
}


- (void)viewDidLoad {
    [super viewDidLoad];
    [self loginss];
}

-(void)loginss{
    key = @"Instagram private api secret key - easy to google, but i suggest to reverse it, it's quite easy";
    [self login_user_with_Login:@"LOGIN" andPassword:@"PASSWORD"];
}

- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];
}

-(NSString*)generateString:(int)lenght{
    NSString *alphabet  = @"ABCDEFGHIJKLMNOPQRSTUVWXZY0123456789";
    NSMutableString *s = [NSMutableString stringWithCapacity:lenght];
    for (NSUInteger i = 0U; i < lenght; i++) {
        u_int32_t r = arc4random() % [alphabet length];
        unichar c = [alphabet characterAtIndex:r];
        [s appendFormat:@"%C", c];
    }
    return s;
}

-(void)login_user_with_Login:(NSString*)login andPassword:(NSString*)pass{
    __block NSMutableArray *dates = [NSMutableArray new];
    [dates addObject:[NSDate date]];
    NSLog(@"START");
    curusr = login;
    NSURL *aUrl = [NSURL URLWithString:@"https://i.instagram.com/api/v1/accounts/login/"];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:aUrl];
    ua = @"Instagram 5.1.0 Android";
    [request setHTTPMethod:@"POST"];
    [request setValue:ua forHTTPHeaderField:@"User-Agent"];
    NSMutableString* postquery = [NSMutableString string];
    NSString *ranDevice = [NSString stringWithFormat:@"%@-%@-%@-%@-%@",[self generateString:8],[self generateString:4],[self generateString:4],[self generateString:4],[self generateString:12]];

    NSMutableString *unencodedUrlStringEncode = [NSMutableString string];
    [unencodedUrlStringEncode setString:@"%7B%22_uuid%22%3A%22"];
    [unencodedUrlStringEncode appendString:ranDevice];
    [unencodedUrlStringEncode appendString:@"%22%2C%22password%22%3A%22"];
    [unencodedUrlStringEncode appendString:pass];
    [unencodedUrlStringEncode appendString:@"%22%2C%22username%22%3A%22"];
    [unencodedUrlStringEncode appendString:login];
    [unencodedUrlStringEncode appendString:@"%22%2C%22device_id%22%3A%22"];
    [unencodedUrlStringEncode appendString:ranDevice];
    [unencodedUrlStringEncode appendString:@"%22%2C%22from_reg%22%3A"];
    [unencodedUrlStringEncode appendString:@"false"];
    [unencodedUrlStringEncode appendString:@"%2C%22_csrftoken%22%3A%22"];
    [unencodedUrlStringEncode appendString:@"missing"];
    [unencodedUrlStringEncode appendString:@"%22%7D"];
    NSString *unencodedUrlString = [unencodedUrlStringEncode stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
    NSString *hmacStr = [self signWithKey:key usingData:unencodedUrlString];
    NSString *generatedBoundary = [NSString stringWithFormat:@"%@-%@-%@-%@-%@",[self generateString:8],[self generateString:4],[self generateString:4],[self generateString:4],[self generateString:12]];
    [request setValue:[NSString stringWithFormat:@"multipart/form-data; boundary=%@",generatedBoundary] forHTTPHeaderField:@"Content-Type"];
    [request setValue:@"en;q=1" forHTTPHeaderField:@"Accept-Language"];
    [request setValue:@"gzip, deflate" forHTTPHeaderField:@"Accept-Encoding"];
    [request setValue:@"WiFi" forHTTPHeaderField:@"X-IG-Connection-Type"];
    NSMutableString *startCookie = [NSMutableString string];
    [startCookie setString:@"mid=VH1S5AAAAAG5YncfHQLXFDWMksCe;"];
    [request setValue:startCookie forHTTPHeaderField:@"Cookie"];
    NSString *str = [NSString stringWithFormat:@"--%@\r\nContent-Disposition: form-data; name=\"signed_body\"\r\n\r\n",generatedBoundary];
    [postquery setString:str];
    [postquery appendString:hmacStr];
    [postquery appendString:@"."];
    [postquery appendString:unencodedUrlString];
    [postquery appendString:[NSString stringWithFormat:@"\r\n--%@\r\nContent-Disposition: form-data; name=\"ig_sig_key_version\"\r\n\r\n4\r\n--%@--\r\n",generatedBoundary,generatedBoundary]];
    __block NSHTTPURLResponse   * response;
    [request setHTTPBody:[postquery dataUsingEncoding:NSUTF8StringEncoding]];
    [dates addObject:[NSDate date]];
    dispatch_async(dispatch_get_global_queue(0,0), ^{
        __block NSData *data1 = [NSURLConnection sendSynchronousRequest:request returningResponse:&response error:nil];
        if ( data1 == nil ){
            data1 = [NSURLConnection sendSynchronousRequest:request returningResponse:&response error:nil];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *dataString = [[NSString alloc] initWithData:data1 encoding:NSASCIIStringEncoding];
            NSData* data = [dataString dataUsingEncoding:NSUTF8StringEncoding];
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:kNilOptions error:nil];
            NSString *status = [json objectForKey:@"status"];
            NSLog(@"InstaLogin[%.3fms & %.3fms]:%@",-([dates[0] timeIntervalSinceNow]-[dates[1] timeIntervalSinceNow]),-[dates[1] timeIntervalSinceNow],json);
            NSDictionary *jsonuser = [json objectForKey:@"logged_in_user"];
                if ([status isEqualToString:@"ok"]) {
                    NSDictionary *fields = [response allHeaderFields];
                    NSString *cookie = [fields valueForKey:@"Set-Cookie"];
                    [[NSUserDefaults standardUserDefaults] setValue:cookie forKey:@"muffin"];
                    NSString* token =[[[[cookie componentsSeparatedByString:@"csrftoken="]objectAtIndex:1] componentsSeparatedByString:@";"]objectAtIndex:0];
                    [[NSUserDefaults standardUserDefaults] setValue:token forKey:@"token"];
                    [[NSUserDefaults standardUserDefaults] setValue:[jsonuser objectForKey:@"pk"] forKey:@"uid"];
                    [self startCycle];
                }
        });
    });
}

-(void)startCycle{
    nameArr = [NSArray arrayWithObjects:
                        @"10",
                        @"9",
                        @"8",
                        @"7",
                        @"6",
                        @"5",
                        @"4",
                        @"3",
                        @"2",
                        @"1",
                        nil];

    [self go];
   
}

-(void)go{
    url2fetch = @"http://i.instagram.com/api/v1/feed/user/";
    NSString *rnd_id = [nameArr objectAtIndex:arc4random_uniform((int)[nameArr count]-1)];
    url2fetch = [url2fetch stringByAppendingString:rnd_id];
    NSString *dosent_matter = [NSString stringWithFormat:@"%@-%@-%@-%@-%@",[self generateString:8],[self generateString:4],[self generateString:4],[self generateString:4],[self generateString:12]];
    url2fetch = [url2fetch stringByAppendingString:@"/?rank_token="];
    url2fetch = [url2fetch stringByAppendingString:dosent_matter];
    NSLog(@"%@",url2fetch);
    [self feedforid:url2fetch];
    asd++;
    [self.cycles setStringValue:[NSString stringWithFormat:@"Cycle:%i",asd]];
    NSLog(@"CYCLE:%i",asd);
}


-(void)feedforid:(NSString*)uUrl{
    __block NSMutableArray *dates = [NSMutableArray new];
    [dates addObject:[NSDate date]];
    NSURL *aUrl = [NSURL URLWithString:uUrl];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:aUrl];
    [request setHTTPMethod:@"GET"];
    [request setValue:ua forHTTPHeaderField:@"User-Agent"];
    [request setValue:@"en;q=1" forHTTPHeaderField:@"Accept-Language"];
    [request setValue:@"gzip, deflate" forHTTPHeaderField:@"Accept-Encoding"];
    __block NSHTTPURLResponse   * response;
    [dates addObject:[NSDate date]];
    dispatch_async(dispatch_get_global_queue(0,0), ^{
        __block NSData *data1 = [NSURLConnection sendSynchronousRequest:request returningResponse:&response error:nil];
        if ( data1 == nil ){
            data1 = [NSURLConnection sendSynchronousRequest:request returningResponse:&response error:nil];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *dataString = [[NSString alloc] initWithData:data1 encoding:NSASCIIStringEncoding];
            NSData* data = [dataString dataUsingEncoding:NSUTF8StringEncoding];
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:kNilOptions error:nil];
            NSLog(@"get old photos[%.3fms & %.3fms]:%@",-([dates[0] timeIntervalSinceNow]-[dates[1] timeIntervalSinceNow]),-[dates[1] timeIntervalSinceNow],@"");
                NSDictionary *items1 = [json objectForKey:@"items"][0];
                NSString *item1 = [items1 objectForKey:@"id"];
                NSLog(@"%@", item1);
            if ([item1 isEqualToString:@""] || item1 == nil) {
                [self go];
            } else {
                [self commentPhotoWithId:item1];
            }
        });
    });
}



- (NSString *) md5:(NSString *) input
{
    const char *cStr = [input UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5( cStr, (int)strlen(cStr), digest );
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    return  output;
}


-(void)commentPhotoWithId:(NSString*)imageId{
    NSLog(@"commenting photo");
    if ([imageId isEqualToString:@""]) {
        imageId = @"323232";
    }
    __block NSMutableArray *dates = [NSMutableArray new];
    [dates addObject:[NSDate date]];
    NSArray *apiparts = [[@"https://i.instagram.com/api/v1/accounts/login/" stringByReplacingOccurrencesOfString:@"https" withString:@"http"] componentsSeparatedByString:@"accounts"];
    NSString *mediaUrl = [apiparts[0] stringByAppendingString:@"media/"];
    mediaUrl = [mediaUrl stringByAppendingString:imageId];
    mediaUrl = [mediaUrl stringByAppendingString:@"/comment/"];
    
    
    NSURL *aUrl = [NSURL URLWithString:mediaUrl];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:aUrl];
    [request setHTTPMethod:@"POST"];
    [request setValue:ua forHTTPHeaderField:@"User-Agent"];
    
    [request setValue:@"en;q=1" forHTTPHeaderField:@"Accept-Language"];
    [request setValue:@"gzip, deflate" forHTTPHeaderField:@"Accept-Encoding"];
    [request setValue:@"WiFi" forHTTPHeaderField:@"X-IG-Connection-Type"];
    [request setValue:@"AQ==" forHTTPHeaderField:@"X-IG-Capabilities"];
    
    NSArray *cookies = [[NSHTTPCookieStorage sharedHTTPCookieStorage] cookiesForURL:[NSURL URLWithString:@"https://i.instagram.com/api/v1/accounts/login/"]];
    NSMutableString* rewritedCookie = [NSMutableString string];
    for (NSHTTPCookie *cookie in cookies) {
        if ([cookie.name isEqualToString:@"mid"]) {
            [rewritedCookie appendString:[NSString stringWithFormat:@"igfl=%@; ",curusr]];
        }
        [rewritedCookie appendString:[NSString stringWithFormat:@"%@=%@; ",cookie.name,cookie.value]];
    }
    [request setValue:rewritedCookie forHTTPHeaderField:@"Cookie"];
    
    NSMutableString* s_postToLikePhoto = [NSMutableString string];
    NSMutableString *unencodedUrlStringEncode = [NSMutableString string];
    
    NSString *idempotence_token = [self md5:[self generateString:128]];
    
    [unencodedUrlStringEncode setString:@"%7B%22media_id%22%3A%22"];
    [unencodedUrlStringEncode appendString:imageId];
    [unencodedUrlStringEncode appendString:@"%22%2C%22_csrftoken%22%3A%22"];
    [unencodedUrlStringEncode appendString:[[NSUserDefaults standardUserDefaults] valueForKey:@"token"]];
    [unencodedUrlStringEncode appendString:@"%22%2C%22comment_text%22%3A%22"];
    [unencodedUrlStringEncode appendString:@"TEXT TO POST AS COMMENT"];
    [unencodedUrlStringEncode appendString:@"%22%2C%22idempotence_token%22%3A%22"];
    [unencodedUrlStringEncode appendString:idempotence_token];
    [unencodedUrlStringEncode appendString:@"%22%7D"];
    
    
    NSString *unencodedUrlString = [unencodedUrlStringEncode stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
    NSString *hmacStr = [self signWithKey:key usingData:unencodedUrlString];
    
    NSString *generatedBoundary = [NSString stringWithFormat:@"%@-%@-%@-%@-%@",[self generateString:8],[self generateString:4],[self generateString:4],[self generateString:4],[self generateString:12]];
    
    [request setValue:[NSString stringWithFormat:@"multipart/form-data; boundary=%@",generatedBoundary] forHTTPHeaderField:@"Content-Type"];
    [request setValue:@"en;q=1" forHTTPHeaderField:@"Accept-Language"];
    [request setValue:@"gzip, deflate" forHTTPHeaderField:@"Accept-Encoding"];
    [request setValue:@"WiFi" forHTTPHeaderField:@"X-IG-Connection-Type"];
    
    NSString *str = [NSString stringWithFormat:@"--%@\r\nContent-Disposition: form-data; name=\"signed_body\"\r\n\r\n",generatedBoundary];
    [s_postToLikePhoto setString:str];
    [s_postToLikePhoto appendString:hmacStr];
    [s_postToLikePhoto appendString:@"."];
    [s_postToLikePhoto appendString:unencodedUrlString];
    [s_postToLikePhoto appendString:[NSString stringWithFormat:@"\r\n--%@\r\nContent-Disposition: form-data; name=\"ig_sig_key_version\"\r\n\r\n%@\r\n--%@--\r\n",generatedBoundary,@"4",generatedBoundary]];
    
    __block NSHTTPURLResponse   * response;
    [request setHTTPBody:[s_postToLikePhoto dataUsingEncoding:NSUTF8StringEncoding]];
    
    [dates addObject:[NSDate date]];
    dispatch_async(dispatch_get_global_queue(0,0), ^{
        __block NSData *data1 = [NSURLConnection sendSynchronousRequest:request returningResponse:&response error:nil];
        if ( data1 == nil ){
            data1 = [NSURLConnection sendSynchronousRequest:request returningResponse:&response error:nil];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *dataString = [[NSString alloc] initWithData:data1 encoding:NSASCIIStringEncoding];
            NSData* data = [dataString dataUsingEncoding:NSUTF8StringEncoding];
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:kNilOptions error:nil];
            NSLog(@"InstaComment[%.3fms & %.3fms]:%@",-([dates[0] timeIntervalSinceNow]-[dates[1] timeIntervalSinceNow]),-[dates[1] timeIntervalSinceNow],json);
            [self performSelector:@selector(go) withObject:nil afterDelay:60];
        });
    });
}


-(NSString *)signWithKey:(NSString *)key usingData:(NSString *)data
{
    const char *cKey  = [key cStringUsingEncoding:NSASCIIStringEncoding];
    const char *cData = [data cStringUsingEncoding:NSASCIIStringEncoding];
    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
    NSData *HMAC = [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
    return [[HMAC.description stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"<>"]] stringByReplacingOccurrencesOfString:@" " withString:@""];
}


@end
