#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <CoreFoundation/CoreFoundation.h>
#include "ioflash/ioflash.h"
#include "util.h"

#define LISTEN_PORT     2000

#define CMD_DUMP        0
#define CMD_PROXY       1

IOFlashController_client* iofc = NULL;

void* proxy_thread(void* arg)
{
    int sock = (int) arg;
    nand_proxy(iofc, sock);
    shutdown(sock, SHUT_RDWR);
    close(sock);
    return NULL;
}

int main(int argc, char* argv[])
{
    int one=1;
    int cmd=0;
    pthread_t th;
    size_t bootargs_len = 255;
    char bootargs[256]={0};

    sysctlbyname("kern.bootargs", bootargs, &bootargs_len, NULL, 0);
    if (!strstr(bootargs, "rd=md0"))
    {
        printf("Not running on a ramdisk, trying to patch kernel\n");
        if(!IOFlashStorage_kernel_patch())
            return -1;
    }

    iofc = IOFlashController_init();
    if(iofc == NULL)
    {
        fprintf(stderr, "FAILed to get NAND infos");
        return -1;
    }
    IOFlashController_print(iofc);
    check_special_pages(iofc);

    int sl = create_listening_socket(LISTEN_PORT);
    if(sl == -1)
    {
        fprintf(stderr, "Error calling create_listening_socket\n");
        return -1;
    }

    fprintf(stderr, "NAND dumper listening on port %d\n", LISTEN_PORT);

    while(1)
    {
        int  s = accept(sl, NULL, NULL);
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, (void *)&one, sizeof(int));
        
        int r = read(s, (void*) &cmd, sizeof(int));
        if(r == sizeof(int))
        {
            if(cmd == CMD_DUMP)
            {
                nand_dump(iofc, s);
            }
            else if(cmd == CMD_PROXY)
            {
                pthread_create(&th, NULL, proxy_thread, (void*) s);
                continue;
            }
        }
        shutdown(s, SHUT_RDWR);
        close(s);
    }
    return 0;
}