#include <IOKit/IOKitLib.h>

io_connect_t IOKit_getConnect(const char* serviceName);

IOReturn IOKit_call(const char* serviceName,
                    uint32_t     selector,
                    const uint64_t  *input,
                    uint32_t     inputCnt,
                    const void      *inputStruct,
                    size_t       inputStructCnt,
                    uint64_t    *output,
                    uint32_t    *outputCnt,
                    void        *outputStruct,
                    size_t      *outputStructCnt);