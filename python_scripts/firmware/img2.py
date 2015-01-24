from construct.core import Struct
from construct.macros import *

IMG2 = Struct("IMG2",
              String("magic",4),
              ULInt32("block_size"),
              ULInt32("images_offset"),
              ULInt32("images_block"),
              ULInt32("images_length"),
              Padding(0x1C),
              ULInt32("crc32"),
              )