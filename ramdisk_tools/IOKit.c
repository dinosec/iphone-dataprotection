#include <stdio.h>
#include <string.h>
#include "IOKit.h"

struct ioconnectCache {
    const char* serviceName;
    io_connect_t conn;
};

struct ioconnectCache cache[10]={{NULL, 0}};

void __attribute__((destructor)) IOKit_destruct()
{
    int i;
    for (i=0; i < 10 && cache[i].conn != 0; i++) {
        //printf("Closing %s\n", cache[i].serviceName);
        IOServiceClose(cache[i].conn);
    } 
}

io_connect_t IOKit_getConnect(const char* serviceName)
{
    IOReturn ret;
    io_connect_t conn = 0;
    int i;
    
    for (i=0; i < 10 && cache[i].serviceName != NULL; i++) {
        if (!strcmp(serviceName, cache[i].serviceName))
        {
            //printf("got cache for %s\n", serviceName);
            return cache[i].conn;
        }
    }
    
    CFMutableDictionaryRef dict = IOServiceMatching(serviceName);
    io_service_t dev = IOServiceGetMatchingService(kIOMasterPortDefault, dict);
    
    if(!dev) {
        fprintf(stderr, "FAIL: Could not get %s service\n", serviceName);
        return -1;
    }
    
    ret = IOServiceOpen(dev, mach_task_self(), 0, &conn);
    
    IOObjectRelease(dev);
    if(ret != kIOReturnSuccess) {
        fprintf(stderr, "FAIL: Cannot open service %s\n", serviceName);
        return -1;
    }
    
    if (i < 10) {
        cache[i].serviceName = serviceName;
        cache[i].conn = conn;
    }
    
    return conn;
}

IOReturn IOKit_call(const char* serviceName,
                    uint32_t     selector,
                    const uint64_t  *input,
                    uint32_t     inputCnt,
                    const void      *inputStruct,
                    size_t       inputStructCnt,
                    uint64_t    *output,
                    uint32_t    *outputCnt,
                    void        *outputStruct,
                    size_t      *outputStructCnt)
{
    IOReturn ret;
    io_connect_t conn = IOKit_getConnect(serviceName);
    
    ret = IOConnectCallMethod(conn,
                              selector,
                              input,
                              inputCnt,
                              inputStruct,
                              inputStructCnt,
                              output,
                              outputCnt,
                              outputStruct,
                              outputStructCnt);
    
    if (ret != kIOReturnSuccess)
    {
        fprintf(stderr, "IOConnectCallMethod on %s selector %d returned %x\n", serviceName, selector, ret);
    }
    
    return ret;
}