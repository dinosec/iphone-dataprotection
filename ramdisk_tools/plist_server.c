#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>
#include <CoreFoundation/CoreFoundation.h>
#include "plist_server.h"
#include "util.h"

#define TCP_PORT            1999

int send_progress_message(int socket, int progress, int total)
{
    const void* keys[3] = {CFSTR("MessageType"), CFSTR("Progress"), CFSTR("Total")};
    const void* values[3] = {CFSTR("Progress"), NULL, NULL};
    
    CFNumberRef number = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &progress);
    CFNumberRef number2 = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &total);
    values[1] = number;
    values[2] = number2;
    CFDictionaryRef msg =  CFDictionaryCreate(kCFAllocatorDefault, keys, values, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRelease(number);
    CFRelease(number2);
    int res = send_object(socket, msg);
    if (msg != NULL) {
        CFRelease(msg);
    }
    return res;
}

int send_object(int socket, CFTypeRef obj)
{
    uint32_t len = 0;
    int res = -1;
    
    if(obj == NULL)
        return res;
    
    //CFDataRef outdata = CFPropertyListCreateData(kCFAllocatorDefault, obj, kCFPropertyListXMLFormat_v1_0, 0, NULL);
    CFDataRef outdata = CFPropertyListCreateXMLData(kCFAllocatorDefault, obj);
    if (outdata != NULL)
    {
        len = CFDataGetLength(outdata);
        write(socket, &len, 4);
        res = write(socket, CFDataGetBytePtr(outdata), CFDataGetLength(outdata));
        CFRelease(outdata);
    }
    return res;
}

int handle_client(int socket, CFDictionaryRef handlers)
{
    uint32_t len=0;
    uint32_t received,i;
    CFDataRef data;
    CFDictionaryRef plist;
    CFTypeRef out = NULL;
    uint8_t* buffer;
    CFTypeRef (*handler)(int, CFDictionaryRef dict) = NULL;
    
    while(1)
    {
        if(recv(socket, &len, 4, 0) != 4)
            break;
        //printf("len=%x\n", len);
        
        if (len > PLIST_MAX_SIZE)
            break;
            
        buffer = malloc(len);
        
        if(buffer == NULL)
            break;

        for(i=0; i < len; )
        {
            received = recv(socket, &buffer[i], len - i, 0);
            if (received == -1)
                break;
            i += received;
        }
    
        data = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, buffer, len, kCFAllocatorNull);

        if(data == NULL)
        {
            free(buffer);
            continue;
        }

//        plist = (CFDictionaryRef) CFPropertyListCreateWithData (kCFAllocatorDefault, data, kCFPropertyListImmutable, NULL, NULL);
        plist = (CFDictionaryRef) CFPropertyListCreateFromXMLData (kCFAllocatorDefault, data, kCFPropertyListImmutable, NULL);
        if(plist == NULL || CFGetTypeID(plist) != CFDictionaryGetTypeID())
        {
            CFRelease(data);
            free(buffer);
            send_object(socket, CFSTR("invalid XML plist dictionary"));
            continue;
        }
        
        if (CFDictionaryContainsKey(plist, CFSTR("Request")))
        {
            CFStringRef request = CFDictionaryGetValue(plist, CFSTR("Request"));
            
            handler = CFDictionaryGetValue(handlers, request);
            
            if (handler != NULL)
            {
                out = handler(socket, plist);
                if (out == NULL)
                    out = CFSTR("Request did not return any result");                
            }
            else
            {
                out = CFSTR("No handler defined for Request");
            }
        }
        else
        {
            out = CFSTR("request dictionary needs to contain Request key");
        }

        if(out == NULL)
            out = CFSTR("no response");
        
        send_object(socket, out);
        CFRelease(out);

        CFRelease(plist);
        CFRelease(data);
        free(buffer);
    }
    send_object(socket, CFSTR("kthxbye"));
    return 0;
}

void serve_plist_rpc(int port, CFDictionaryRef handlers)
{
    int quit = 0;
    int one=1;
    printf("plist_rpc: listening on port %d\n", port);
    int sl = create_listening_socket(port);
    
    while(!quit)
    {
        int  s = accept(sl, NULL, NULL);
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, (void *)&one, sizeof(int));
        
        handle_client(s, handlers);
        shutdown(s, SHUT_RDWR);
        close(s);
    }
    close(sl);
}

CFStringRef testHandler(int s, CFDictionaryRef dict)
{
    printf("lol\n");
    return CFSTR("Hello, World!");
}

