from construct import *
from zipfile import crc32

GPT_HFS = "005346480000aa11aa1100306543ecac".decode("hex")
GPT_EMF = "00464d450000aa11aa1100306543ecac".decode("hex")

LWVM_partitionRecord = Struct("LWVM_partitionRecord",
                              String("type", 16),
                              String("guid", 16),
                              ULInt64("begin"),
                              ULInt64("end"),
                              ULInt64("attribute"),
                              String("name", 0x48, encoding="utf-16-le", padchar="\x00")
)

LWVM_MAGIC = "6a9088cf8afd630ae351e24887e0b98b".decode("hex")
LWVM_header = Struct("LWVM_header",
                     String("type",16),
                     String("guid", 16),
                     ULInt64("mediaSize"),
                     ULInt32("numPartitions"),
                     ULInt32("crc32"),
                     Padding(464),
                     Array(12, LWVM_partitionRecord),
                     Array(1024, ULInt16("chunks"))
                     )

GPT_header = Struct("GPT_header",
    String("signature", 8),
    ULInt32("revision"),
    ULInt32("header_size"),
    SLInt32("crc"), #hax to match python signed crc
    ULInt32("zero"),
    ULInt64("current_lba"),
    ULInt64("backup_lba"),
    ULInt64("first_usable_lba"),
    ULInt64("last_usable_lba"),
    String("disk_guid", 16),
    ULInt64("partition_entries_lba"),
    ULInt32("num_partition_entries"),
    ULInt32("size_partition_entry"),
    ULInt32("crc_partition_entries")
)

GPT_entry = Struct("GPT_entry",
                   String("partition_type_guid", 16),
                   String("partition_guid", 16),
                   ULInt64("first_lba"),
                   ULInt64("last_lba"),
                   ULInt64("attributes"),
                   String("name", 72, encoding="utf-16-le", padchar="\x00"),
)

GPT_partitions = RepeatUntil(lambda obj, ctx: obj["partition_type_guid"] == "\x00"*16, GPT_entry)

APPLE_ENCRYPTED = 0xAE
MBR_entry = Struct("MBR_entry",
                   Byte("status"),
                   Bytes("chs_start",3),
                   Byte("type"),
                   Bytes("chs_last",3),
                   ULInt32("lba_start"),
                   ULInt32("num_sectors")
)
                   
MBR = Struct("MBR",
             String("code",440),
             ULInt32("signature"),
             ULInt16("zero"),
             Array(4, MBR_entry),
             OneOf(ULInt16("magic"), [0xAA55])
)

def parse_mbr(data):
    try:
        mbr = MBR.parse(data)
        if mbr.MBR_entry[0].type == 0xEE:
            print "Found protective MBR"
            return None
        res = mbr.MBR_entry[:2]
        for p in res:
            p.first_lba = p.lba_start
            p.last_lba = p.lba_start + p.num_sectors
        return res
    except:
        return None

def parse_gpt(data):
    gpt =  GPT_header.parse(data)
    if gpt.signature != "EFI PART":
        return None
    print "Found GPT header current_lba=%d partition_entries_lba=%d" % (gpt.current_lba, gpt.partition_entries_lba)
    assert gpt.partition_entries_lba > gpt.current_lba
    check = gpt.crc
    gpt.crc = 0
    actual = crc32(GPT_header.build(gpt))
    if actual != check:
        print "GPT crc check fail %d vs %d" % (actual, check)
        return None
    return gpt

def clz32(x):
    if x == 0: return 32
    return bin(x)[2:].rjust(32, "0").find("1")

def parse_lwvm(data, pageSize):
    try:
        hdr = LWVM_header.parse(data)
        if hdr.type != LWVM_MAGIC:
            print "LwVM magic mismatch"
            return
        tocheck = data[:44] + "\x00\x00\x00\x00" + data[48:0x1000]
        check = crc32(tocheck) & 0xffffffff
        if check != hdr.crc32:
            return None
        print "LwVM header CRC OK"
        partitions = hdr.LWVM_partitionRecord[:hdr.numPartitions] 
        LwVM_rangeShiftValue = 32 - clz32((hdr.mediaSize - 1)  >> 10 )

        for i in xrange(len(hdr.chunks)):
            if hdr.chunks[i] == 0x0:
                lba0 = (i << LwVM_rangeShiftValue) / pageSize
                partitions[0].first_lba = lba0
                partitions[0].last_lba = lba0 + (partitions[0].end - partitions[0].begin) / pageSize
            elif hdr.chunks[i] == 0x1000:
                lbad = (i << LwVM_rangeShiftValue) / pageSize
                partitions[1].first_lba = lbad
                partitions[1].last_lba = lbad + (partitions[1].end - partitions[1].begin) / pageSize
        return partitions
    except:
        return None

