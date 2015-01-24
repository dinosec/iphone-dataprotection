#define CEMETARY_GATE   0xdeadcafe

#define kIOFlashPartitionSchemePool           0x008
#define kIOFlashPartitionSchemeUseSLCBlocks   0x100
#define kIOFlashPartitionSchemeUseFullPages   0x200

struct IOFlashPartitionDesc
{
    uint32_t name;
    uint32_t start_block;
    uint32_t num_blocks;
    uint32_t flags;
} __attribute__((packed));

struct IOFlashPartitionSchemeCemetary
{
    uint32_t magic;
    uint8_t pad[6];
    uint8_t cemetary[32];
    uint16_t checksum;
} __attribute__((packed));

struct IOFlashPartitionSchemeSpares
{
    uint32_t magic;
    uint16_t num_spares;
    uint32_t pad;
    uint32_t spares[64];
    uint16_t checksum;
} __attribute__((packed));

struct IOFlashPartitionSchemeSubs
{
    uint32_t magic;
    uint16_t num_subs;
    uint32_t pad;
    uint8_t subs[64];
    uint16_t checksum;
} __attribute__((packed));

struct IOFlashPartitionBBTEntry
{
    uint32_t ce;
    uint32_t block;
} __attribute__((packed));

struct IOFlashPartitionTable
{
    uint32_t magic;//'ndrG'
    uint32_t zero;
    uint32_t major_version;
    uint32_t minor_version;
    uint32_t generation;
    uint16_t checksum1;
    uint8_t unk1[0xA];

    struct IOFlashPartitionBBTEntry factoryBBT[60];
    uint8_t unk2[0x24];

    //0x224
    struct IOFlashPartitionSchemeCemetary cemetary;
    //0x250
    struct IOFlashPartitionSchemeSpares spares;
    //0x35c
    struct IOFlashPartitionSchemeSubs subs;

    uint8_t unk3[0x58];

    //0x400
    struct IOFlashPartitionDesc partitions[32];

} __attribute__((packed));

typedef struct IOFlashPartitionScheme
{
    IOFlashController_client* flash;
    uint32_t    ceCount;

    struct IOFlashPartitionTable ptable;

} IOFlashPartitionScheme;

IOFlashPartitionScheme* IOFlashPartitionScheme_init(IOFlashController_client*, uint8_t*);

uint32_t IOFlashPartitionScheme_get_flags_for_block(IOFlashPartitionScheme*, uint32_t ce, uint32_t block);
uint32_t IOFlashPartitionScheme_remap_bootloader_block(IOFlashPartitionScheme*, uint32_t ce, uint32_t block, uint32_t flags, uint32_t* realCE, uint32_t* realBlock);
uint32_t IOFlashPartitionScheme_read_partition(IOFlashPartitionScheme*, const char*, uint8_t**, uint32_t*);
