#include <stdio.h>
#include <unistd.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>

mach_port_t kernel_task=0;

kern_return_t write_kernel(mach_port_t p, void* addr, uint32_t value)
{
    pointer_t buf;
    unsigned int sz;
    
    kern_return_t r = vm_write(p, (vm_address_t)addr, (vm_address_t)&value, sizeof(value));
    if (r)
    {
        fprintf(stderr, "vm_write into kernel_task failed\n");
    }
    else
    {
        //fix cache issue
        vm_read(p, (vm_address_t) addr, sizeof(value), &buf, &sz);
        fprintf(stderr, "vm_write into kernel_task OK %x\n", *((uint32_t*) buf));
    }
    return r;
}

int patch_IOAESAccelerator()
{
    kern_return_t r = task_for_pid(mach_task_self(), 0, &kernel_task);
    
    if( r != 0)
    {
        fprintf(stderr, "task_for_pid returned %x : missing tfp0 kernel patch or wrong entitlements\n", r);
        return 0;
    }
    uint32_t i;
    pointer_t buf;
    unsigned int sz;
    
    vm_address_t addr = 0x80002000;
                                
    while( addr < (0x80002000 + 0xA00000))
    {
        vm_read(kernel_task, addr, 2048, &buf, &sz);
        if( buf == 0 || sz == 0)
            continue;
        uint8_t* p = (uint8_t*) buf;
        
        for(i=0; i < sz; i++)
        {
        //"IOAESAccelerator enable UID" : (h("67 D0 40 F6"), h("00 20 40 F6")),
            if (*((uint32_t*)&p[i]) == 0xF640d067)
            {
                fprintf(stderr, "Found IOAESAccelerator UID ptr at %x, patching kernel\n", (uint32_t)  addr + i);
                write_kernel(kernel_task, (void*) (addr + i), (uint32_t) 0xF6402000);
                return 0;
            }
        }
        addr += 2048;
    }
    fprintf(stderr, "IOAESAccelerator Kernel patching failed\n");
    return -1;
}

/*
int main(int argc, char** argv)
{
    return patch_IOAESAccelerator();
}
*/