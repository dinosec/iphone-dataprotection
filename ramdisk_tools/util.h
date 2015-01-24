struct HFSInfos {
    uint64_t    volumeUUID;
    uint32_t    blockSize;
    uint32_t    dataVolumeOffset;
};

struct HFSPlusVolumeHeader {
    uint16_t              signature;
    uint16_t              version;
    uint32_t              attributes;
    uint32_t              lastMountedVersion;
    uint32_t              journalInfoBlock;
 
    uint32_t              createDate;
    uint32_t              modifyDate;
    uint32_t              backupDate;
    uint32_t              checkedDate;
 
    uint32_t              fileCount;
    uint32_t              folderCount;
 
    uint32_t              blockSize;
    uint32_t              totalBlocks;
    uint32_t              freeBlocks;
 
    uint32_t              nextAllocation;
    uint32_t              rsrcClumpSize;
    uint32_t              dataClumpSize;
    uint32_t              nextCatalogID;
 
    uint32_t              writeCount;
    uint64_t              encodingsBitmap;
 
    uint32_t              finderInfo[6];
    uint64_t              volumeUUID;
 /*
    HFSPlusForkData     allocationFile;
    HFSPlusForkData     extentsFile;
    HFSPlusForkData     catalogFile;
    HFSPlusForkData     attributesFile;
    HFSPlusForkData     startupFile;*/
} __attribute__((packed));

//https://github.com/iDroid-Project/openiBoot/blob/master/openiboot/includes/bdev.h
typedef struct _LwVMPartitionRecord {
	uint64_t type[2];
	uint64_t guid[2];
	uint64_t begin;
	uint64_t end;
	uint64_t attribute; // 0 == unencrypted; 0x1000000000000 == encrypted
	char	partitionName[0x48];
} __attribute__ ((packed)) LwVMPartitionRecord;

typedef struct _LwVM {
	uint64_t type[2];
	uint64_t guid[2];
	uint64_t mediaSize;
	uint32_t numPartitions;
	uint32_t crc32;
	uint8_t unkn[464];
	LwVMPartitionRecord partitions[12];
	uint16_t chunks[1024]; // chunks[0] should be 0xF000
} __attribute__ ((packed)) LwVM;

static const char LwVMType[] = { 0x6A, 0x90, 0x88, 0xCF, 0x8A, 0xFD, 0x63, 0x0A, 0xE3, 0x51, 0xE2, 0x48, 0x87, 0xE0, 0xB9, 0x8B };

int getHFSInfos(struct HFSInfos *infos);

CFMutableStringRef CreateHexaCFString(uint8_t* buffer, size_t len);

void printBytesToHex(const uint8_t* buffer, size_t bytes);
void printHexString(const char* description, const uint8_t* buffer, size_t bytes);
int write_file(const char* filename, uint8_t* data, size_t len);

void addHexaString(CFMutableDictionaryRef out, CFStringRef key, uint8_t* buffer, size_t len);
void saveResults(CFStringRef filename, CFMutableDictionaryRef out);
void writePlistToStdout(CFDictionaryRef out);

int mountDataPartition(const char* mountpoint);

int create_listening_socket(int port);