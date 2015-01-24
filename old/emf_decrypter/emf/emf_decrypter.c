#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <inttypes.h>
#include <libgen.h>
#include <openssl/aes.h>
#include <hfs/hfslib.h>
#include "emf.h"

char endianness;

void TestByteOrder()
{
	short int word = 0x0001;
	char *byte = (char *) &word;
	endianness = byte[0] ? IS_LITTLE_ENDIAN : IS_BIG_ENDIAN;
}

void iv_for_lba(uint32_t lba, uint32_t* iv)
{
	int i;
	for(i = 0; i < 4; i++)
	{
		if(lba & 1)
			lba = 0x80000061 ^ (lba >> 1);
		else
			lba = lba >> 1;
		iv[i] = lba;
	}
}

int EMF_unwrap_filekey_forclass(EMFInfo* emf, uint8_t* wrapped_file_key, uint32_t protection_class_id, AES_KEY* file_key)
{
	uint8_t fk[32]={0};

	if (protection_class_id < 1 || protection_class_id >= MAX_CLASS_KEYS)
		return -1;

	if ((emf->classKeys_bitset & (1 << protection_class_id)) == 0)
	{
		printf("Class key %d not available\n", protection_class_id);
		return -1;
	}

	if(AES_unwrap_key(&(emf->classKeys[protection_class_id-1]), NULL, fk, wrapped_file_key, 40)!= 32)
	{
		fprintf(stderr, "EMF_unwrap_filekey_forclass unwrap FAIL, protection_class_id=%d\n", protection_class_id);
		return -1;
	}
	AES_set_decrypt_key(fk, 32*8, file_key);

	return 0;
}

void EMF_fix_and_decrypt_block(EMFInfo* emf, uint8_t* buffer, uint32_t lba, uint32_t blockSize, AES_KEY* filekey)
{
	uint32_t volumeOffset = emf->volume_offset;
	uint32_t iv[4];
	
	//reencrypt with emf key to get correct ciphertext
	iv_for_lba(volumeOffset + lba, iv);
	AES_cbc_encrypt(buffer, buffer, blockSize, &(emf->emfkey), (uint8_t*) iv, AES_ENCRYPT);

	//decrypt with file key
	iv_for_lba(volumeOffset + lba, iv);
	AES_cbc_encrypt(buffer, buffer, blockSize, filekey, (uint8_t*) iv, AES_DECRYPT);
}

int EMF_decrypt_file_blocks(EMFInfo* emf, HFSPlusCatalogFile* file, uint8_t* wrapped_file_key, uint32_t protection_class)
{
	AES_KEY filekey;
	
	if( EMF_unwrap_filekey_forclass(emf, wrapped_file_key, protection_class, &filekey))
	{
		return -1;
	}

	io_func* io = openRawFile(file->fileID, &file->dataFork, (HFSPlusCatalogRecord*)file, emf->volume);
	if(io == NULL)
	{
		fprintf(stderr, "openRawFile %d FAIL!\n", file->fileID);
		return -1;
	}
	RawFile* rawFile = (RawFile*) io->data;
	Extent* extent = rawFile->extents;
	uint32_t blockSize = emf->volume->volumeHeader->blockSize;
	uint32_t i;
	uint8_t* buffer = malloc(blockSize);
	
	if(buffer == NULL)
		return -1;

	//decrypt all blocks in all extents
	//the last block can contain stuff from erased files maybe ?
	while( extent != NULL)
	{
		for(i=0; i < extent->blockCount; i++)
		{
			if(READ(emf->volume->image, (extent->startBlock + i) * blockSize, blockSize, buffer))
			{
				EMF_fix_and_decrypt_block(emf, buffer, extent->startBlock + i, blockSize, &filekey);
				
				//write back to image
				WRITE(emf->volume->image, (extent->startBlock + i) * blockSize, blockSize, buffer);
			}
		}
		extent = extent->next;
	}
	
	free(buffer);
	return 0;
}

int EMF_decrypt_folder(EMFInfo* emf, HFSCatalogNodeID folderID)
{
	CatalogRecordList* list;
	CatalogRecordList* theList;
	HFSPlusCatalogFolder* folder;
	HFSPlusCatalogFile* file;
	char* name;
	cprotect_xattr_v2* cprotect_xattr;
	uint8_t* wrapped_file_key;
	
	theList = list = getFolderContents(folderID, emf->volume);
	
	while(list != NULL)
	{
		name = unicodeToAscii(&list->name);
		
		if(list->record->recordType == kHFSPlusFolderRecord)
		{
			folder = (HFSPlusCatalogFolder*)list->record;
			EMF_decrypt_folder(emf, folder->folderID);
		}
		else if(list->record->recordType == kHFSPlusFileRecord)
		{
			file = (HFSPlusCatalogFile*)list->record;
			
			size_t attr_len = getAttribute(emf->volume, file->fileID, "com.apple.system.cprotect", (uint8_t**) &cprotect_xattr);
			
			if(cprotect_xattr != NULL && attr_len > 0)
			{
				if (cprotect_xattr->xattr_major_version == 2 && attr_len == CPROTECT_V2_LENGTH)
				{
					printf("Decrypting %s\n", name);
					if(!EMF_decrypt_file_blocks(emf, file, cprotect_xattr->persistent_key, cprotect_xattr->persistent_class))
					{
						//TODO HAX: update cprotect xattr version field (bit1) to mark file as decrypted ?
						//cprotect_xattr->version |= 1;
						//setAttribute(volume, file->fileID, "com.apple.system.cprotect", (uint8_t*) cprotect_xattr, CPROTECT_V2_LENGTH);
					}
				}
				else if (cprotect_xattr->xattr_major_version == 4 && attr_len == CPROTECT_V4_LENGTH)
				{
					//not just yet :)
				}
				else if (cprotect_xattr->xattr_major_version & 1)
				{
					//TODO: file already decrypted by this tool ?
				}
				else
				{
					fprintf(stderr, "Unknown cprotect xattr version/length : %x/%zx\n", cprotect_xattr->xattr_major_version, attr_len);
				}
			}
		}
		
		free(name);
		list = list->next;
	}
	releaseCatalogRecordList(theList);
}

int main(int argc, const char *argv[]) {
	io_func* io;
	Volume* volume;
	
	TestByteOrder();
	
	if(argc < 2) {
		printf("usage: %s <image-file>\n", argv[0]);
		return 0;
	}
	
	io = openFlatFile(argv[1]);

	if(io == NULL) {
		fprintf(stderr, "error: Cannot open image-file.\n");
		return 1;
	}
	
	volume = openVolume(io); 
	if(volume == NULL) {
		fprintf(stderr, "error: Cannot open volume.\n");
		CLOSE(io);
		return 1;
	}
	printf("WARNING ! This tool will modify the hfs image and possibly wreck it if something goes wrong !\n" 
			"Make sure to backup the image before proceeding\n");
	printf("Press a key to continue or CTRL-C to abort\n");
	getchar();

	char* dir = dirname((char*)argv[1]);
	EMFInfo* emf = EMF_init(volume, dir);
	
	if(emf != NULL)
	{
		EMF_decrypt_folder(emf, kHFSRootFolderID);
	}

	closeVolume(volume);
	CLOSE(io);
	
	return 0;
}
