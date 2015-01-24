.text
.thumb
//IOFlashControllerUserClient::externalMethod for iOS 5/6 in-place kernel patching
//modified from clang -Os output

externalMethod:
    push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
    sub	sp, #88
    
    ldr r11, IOMemoryDescriptor__withAddress_delta
    add r11, pc //pc points 4 bytes ahead
    mov	r4, r0

//IOMemoryDescriptor__withAddress_delta should hold the delta between here (externalMethod+0xC) and IOMemoryDescriptor__withAddress(+1)

//    cmp	r1, #1
//    bne.n	epilog

    ldr	r6, [r2, #28]

    movs	r5, #0

    ldr.w	r7, [r2, #48]
    movs	r2, #1
    ldr	r0, [r6, #0]
    str	r0, [sp, #4]
    ldr	r0, [r6, #4]
    str	r0, [sp, #0]
    movs	r0, #1
    str	r0, [sp, #12]
    str	r5, [sp, #8]
    ldrb	r1, [r6, #9]
    tst.w	r1, #1	@ 0x1
    itt	ne
    movne	r1, #9
    strne	r1, [sp, #8]
    str	r5, [sp, #20]
    str	r5, [sp, #32]
    str	r5, [sp, #68]
    str	r5, [sp, #60]
    str r5, [sp, #52]
    
    str	r0, [sp, #16]
    add	r0, sp, #4
    str	r0, [sp, #24]
    mov	r0, sp
    str	r0, [sp, #44]
    ldrd	r0, r1, [r6, #12]
    ldr	r3, [r4, #124]
    blx	r11
    str	r0, [sp, #28]
    ldr	r0, [r6, #20]
    cbnz	r0, prepare_spare
    mov	r6, r5
    b.n	docommand

prepare_spare:
        ldr	r0, [r6, #24]
        movs	r2, #1
        str	r0, [sp, #52]
        ldr	r0, [r6, #20]
        ldr	r1, [r6, #24]
        ldr	r3, [r4, #124]
        blx	r11
        mov r1, r5
        mov	r5, r0
        ldr	r2, [r5, #0]
        ldr.w	r2, [r2, #152]
        blx	r2      //map(0)
        mov	r6, r0
        ldr	r1, [r6, #0]
        ldr	r1, [r1, #56]
        blx	r1      //getVirtualAddress
        str	r0, [sp, #48]

docommand:
    ldr	r0, [r4, #120]
    add	r2, sp, #8
    ldr	r1, [r0, #0]
    //ldr.w	r3, [r1, #836] //XXX: ios5
    ldr.w	r3, [r1, #844] //XXX: ios6/7 ?
    movs	r1, #0
    blx	r3
    str.w	r0, [r7]
    ldr	r0, [sp, #28]
    ldr	r1, [r0, #0]
    ldr	r4, [r1, #20]
    blx	r4
    cbz	r6, epilog
    mov	r0, r6
    blx	r4
    mov	r0, r5
    blx	r4
    
epilog:
    movs	r0, #0
    add	sp, #88
    pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}

.align 2
IOMemoryDescriptor__withAddress_delta:
    //delta between externalMethod+0xC and IOMemoryDescriptor__withAddress (+1) appended here by kernel_patcher.py
    //.long 0xdeadbeef
