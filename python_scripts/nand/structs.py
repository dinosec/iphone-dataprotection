from construct.core import Struct, Union
from construct.macros import *

#hardcoded iOS keys
META_KEY = "92a742ab08c969bf006c9412d3cc79a5".decode("hex")
FILESYSTEM_KEY = "f65dae950e906c42b254cc58fc78eece".decode("hex")

def next_power_of_two(z):
    i = 1
    while i < z:
        i <<= 1
    return i

def CEIL_DIVIDE(val, amt):
    return (((val) + (amt) - 1) / (amt))

#from openiboot/plat-s5l8920/h2fmi.c
#blocks_per_ce, pages_per_block, bytes_per_page, bytes_per_spare, unk5, unk6, unk7, banks_per_ce, unk9
#some values change in openiboot/plat-a4/h2fmi.c, but banks_per_ce is ok
nand_chip_info = {
    0x7294D7EC : [ 0x1038, 0x80, 0x2000, 0x1B4, 0xC, 0, 8, 1, 0 ],
    0x72D5DEEC : [ 0x2070, 0x80, 0x2000, 0x1B4, 0xC, 0, 8, 2, 0 ],
    0x29D5D7EC : [ 0x2000, 0x80, 0x1000, 0xDA, 8, 0, 2, 2, 0 ],
    0x2994D5EC : [ 0x1000, 0x80, 0x1000, 0xDA, 8, 0, 2, 1, 0 ],
    0xB614D5EC : [ 0x1000, 0x80, 0x1000, 0x80, 4, 0, 2, 1, 0 ],
    0xB655D7EC : [ 0x2000, 0x80, 0x1000, 0x80, 4, 0, 2, 2, 0 ],
    0xB614D5AD : [ 0x1000, 0x80, 0x1000, 0x80, 4, 0, 3, 1, 0 ],
    0x3294E798 : [ 0x1004, 0x80, 0x2000, 0x1C0, 0x10, 0, 1, 1, 0 ],
    0xBA94D598 : [ 0x1000, 0x80, 0x1000, 0xDA, 8, 0, 1, 1, 0 ],
    0xBA95D798 : [ 0x2000, 0x80, 0x1000, 0xDA, 8, 0, 1, 2, 0 ],
    0x3294D798 : [ 0x1034, 0x80, 0x2000, 0x178, 8, 0, 1, 1, 0 ],
    0x3295DE98 : [ 0x2068, 0x80, 0x2000, 0x178, 8, 0, 1, 2, 0 ],
    0x3295EE98 : [ 0x2008, 0x80, 0x2000, 0x1C0, 0x18, 0, 1, 2, 0 ],
    0x3E94D789 : [ 0x2000, 0x80, 0x1000, 0xDA, 0x10, 0, 5, 1, 0 ],
    0x3ED5D789 : [ 0x2000, 0x80, 0x1000, 0xDA, 8, 0, 6, 2, 0 ],
    0x3ED5D72C : [ 0x2000, 0x80, 0x1000, 0xDA, 8, 0, 5, 2, 0 ],
    0x3E94D72C : [ 0x2000, 0x80, 0x1000, 0xDA, 0xC, 0, 7, 1, 0 ],
    0x4604682C : [ 0x1000, 0x100, 0x1000, 0xE0, 0xC, 0, 7, 1, 0 ],
    0x3294D745 : [ 0x1000, 0x80, 0x2000, 0x178, 8, 0, 9, 1, 0 ],
    0x3295DE45 : [ 0x2000, 0x80, 0x2000, 0x178, 8, 0, 9, 2, 0 ],
    0x32944845 : [ 0x1000, 0x80, 0x2000, 0x1C0, 8, 0, 9, 1, 0 ],
    0x32956845 : [ 0x2000, 0x80, 0x2000, 0x1C0, 8, 0, 9, 2, 0 ],
    0x7ad5deec : [ 0x0000, 0x00, 0x0000, 0x000, 0, 0, 0, 2, 0 ] #iPad2 gsm 64gb
}

#https://github.com/iDroid-Project/openiBoot/blob/master/openiboot/plat-a4/h2fmi.c
def gen_h2fmi_hash_table():
    val = 0x50F4546A;
    h2fmi_hash_table = [0]*256
    for i in xrange(256):
        val = ((0x19660D * val) + 0x3C6EF35F) & 0xffffffff;
        for j in xrange(762):
            val = ((0x19660D * val) + 0x3C6EF35F) & 0xffffffff;
        h2fmi_hash_table[i] = val & 0xffffffff
    return h2fmi_hash_table

# Page types (as defined in the spare data "type" bitfield)
PAGETYPE_INDEX = 0x4 #Index block indicator
PAGETYPE_LBN = 0x10 # User data
PAGETYPE_FTL_CLEAN = 0x20 # FTL context (unmounted, clean)
PAGETYPE_VFL = 0x80 #/ VFL context

SpareData = Struct("SpareData",
                   ULInt32("lpn"),
                   ULInt32("usn"),
                   ULInt8("field_8"),
                   ULInt8("type"),
                   ULInt16("field_A")
)

# Block status (as defined in the BlockStruct structure)
BLOCKSTATUS_ALLOCATED = 0x1
BLOCKSTATUS_FTLCTRL = 0x2
BLOCKSTATUS_GC = 0x4
BLOCKSTATUS_CURRENT = 0x8
BLOCKSTATUS_FTLCTRL_SEL = 0x10
BLOCKSTATUS_I_GC = 0x20
BLOCKSTATUS_I_ALLOCATED = 0x40
BLOCKSTATUS_I_CURRENT = 0x80
BLOCKSTATUS_FREE = 0xFF

ERROR_ARG = 0x80000001
ERROR_NAND = 0x80000002
ERROR_EMPTY = 0x80000003
