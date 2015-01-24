from construct.core import Struct
from construct.macros import *
from construct import RepeatUntil, OneOf
from util import hexdump

SCFGItem = Struct("SCFGItem",
                  String("tag", 4),
                  String("data", 16, padchar="\x00")
                  )

SCFG = Struct("SCFG",
                OneOf(String("magic", 4), ["gfCS"]),
                ULInt32("length"),
                ULInt32("unk1"),
                ULInt32("unk2"),
                ULInt32("unk3"),
                ULInt32("unk4")
            )

def parse_SCFG(data):
    res = {}
    scfg = SCFG.parse(data)
    assert scfg.length > 0x18
    for i in Array((scfg.length - 0x18) / 20, SCFGItem).parse(data[0x18:scfg.length]):
        if i.tag != "\xFF\xFF\xFF\xFF":
            res[str(i.tag)[::-1]] = str(i.data)
    return res
