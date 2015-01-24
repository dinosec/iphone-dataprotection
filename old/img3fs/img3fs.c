#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <openssl/evp.h>

#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION  26
#include <fuse.h>

#define MAX_IMG3_ELEMENTS    15

struct img3_config
{
    char *img3filename;
    char *iv;
    char *key;
};

#define MYFS_OPT(t, p, v) { t, offsetof(struct img3_config, p), v }

static struct fuse_opt img3_opts[] = {
     MYFS_OPT("-iv %s", iv, 0),
     MYFS_OPT("-key %s", key, 0),
     FUSE_OPT_END
};

typedef struct IMG3Header
{
    uint32_t magic;
    uint32_t fullSize;
    uint32_t sizeNoPack;
    uint32_t sigCheckArea;
    uint32_t iden;
} __attribute__((packed)) IMG3Header;

typedef struct IMG3Element
{
    uint32_t magic;
    uint32_t total_length;
    uint32_t data_length;
    uint32_t offset;
    char     name[10];
} __attribute__((packed)) IMG3Element;

typedef struct KBAG
{
    uint32_t cryptState;// 1 if the key and IV in the KBAG are encrypted with the GID-key
                       // 2 is used with a second KBAG for the S5L8920, use is unknown.
    uint32_t aesType; // 0x80 = aes-128, 0xc0 = aes-192, 0x100 = aes256
    char   EncIV[16];
    union
    {
        char  EncKey128[16];
        char  EncKey192[24];
        char  EncKey256[32];
    } key;
} KBAG;

typedef struct IMG3
{
    int fd;
    uint8_t* mmap;
    uint32_t aesType;//0=no aes, 0x80 = aes-128, 0xc0 = aes-192, 0x100 = aes256
    const EVP_CIPHER* cipherType;
    uint8_t iv[16];
    uint8_t key[32];
    uint8_t* decrypted_data;
    int data_was_modified;
    
    uint32_t size;
    struct IMG3Header header;
    uint32_t num_elements;
    struct IMG3Element* data_element;
    struct IMG3Element elements[MAX_IMG3_ELEMENTS];
} IMG3;

void hexToBytes(const char* hex, uint8_t* buffer, size_t bufferLen) {
    size_t i;
    for(i = 0; i < bufferLen && *hex != '\0'; i++) {
        uint32_t byte;
        sscanf(hex, "%02x", &byte);
        buffer[i] = byte;
        hex += 2;
    }
}

/**
Check for magic constants/strings in decrypted data to get an idea if the IV/key were ok
**/
char* img3_check_decrypted_data(const uint8_t* buffer, uint32_t len)
{
    if (len > 16 && !strncmp("complzss", buffer, 8))
    {
        return "kernelcache";
    }
    if (len > 0x800 && !strncmp("H+", &buffer[0x400], 2))
    {
        return "ramdisk";
    }
    if (len > 0x300 && !strncmp("iBoot", &buffer[0x280], 5))
    {
        return "bootloader";
    }
    //TODO devicetree, logos
    return NULL;
}

IMG3* img3_init(struct img3_config* config)
{
    IMG3* img3 = NULL;
    struct stat st;
    uint32_t len,offset,i,keylen;
    
    if(stat(config->img3filename, &st) == -1)
    {
        perror("stat");
        return NULL;
    }
    len = st.st_size;
    
    int fd = open(config->img3filename, O_RDWR);
    if (fd == -1)
    {
        perror("open");
        return NULL;
    }
    
    img3 = malloc(sizeof(IMG3));
    
    if (img3 == NULL)
    {
        perror("malloc");
        return NULL;
    }
    
    img3->fd = fd;
    img3->size = len;
    img3->num_elements = 0;
    img3->aesType = 0;
    img3->data_was_modified = 0;
    img3->cipherType = NULL;
    img3->decrypted_data = NULL;
    img3->data_element = NULL;
    img3->mmap = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (img3->mmap == (void*) -1)
    {
        perror("mmap");
        free(img3);
        return NULL;
    }
    
    keylen = 0;
    if (config->iv != NULL && config->key != NULL)
    {
        if(strlen(config->iv) != 32)
        {
            printf("IV must be 16 bytes\n");
            free(img3);
            return NULL;
        }
        keylen = strlen(config->key);
        if (keylen != 32 && keylen != 64 && keylen != 48)
        {
            printf("Key must be 16,24 or 32 bytes\n");
            free(img3);
            return NULL;
        }
        hexToBytes(config->iv, img3->iv, 16);
        hexToBytes(config->key, img3->key, 32);
    }
    
    if(read(fd, &img3->header, sizeof(IMG3Header)) != sizeof(IMG3Header))
    {
        perror("read IMG3 header");
        free(img3);
        return NULL;
    }
    if(img3->header.magic != 'Img3' || img3->header.fullSize != len)
    {
        printf("bad magic or len\n");
        free(img3);
        return NULL;
    }
    
    for(offset=sizeof(IMG3Header),i=0; offset < len && i < MAX_IMG3_ELEMENTS; i++)
    {
        if(lseek(fd, offset, SEEK_SET) == -1)
            break;
        if(read(fd, &img3->elements[i], 12) != 12)
            break;
        if(img3->elements[i].total_length < 12)
            break;
        if(img3->elements[i].data_length > img3->elements[i].total_length)
            break;
        if(offset + img3->elements[i].data_length < offset)
            break;
        if(offset + img3->elements[i].total_length < offset)
            break;
        if(offset + img3->elements[i].total_length > len)
            break;
        img3->elements[i].offset = offset + 12;
        img3->elements[i].name[0] = (img3->elements[i].magic & 0xff000000) >> 24;
        img3->elements[i].name[1] = (img3->elements[i].magic & 0xff0000) >> 16;
        img3->elements[i].name[2] = (img3->elements[i].magic & 0xff00) >> 8;
        img3->elements[i].name[3] = (img3->elements[i].magic & 0xff);
        img3->elements[i].name[4] = 0;
        
        printf("TAG: %s OFFSET %x data_length:%x\n", img3->elements[i].name, offset, img3->elements[i].data_length);
        
        if (img3->elements[i].magic == 'KBAG')
        {
            KBAG* kbag = (KBAG*) &(img3->mmap[offset+12]);
            if(kbag->cryptState == 1)
            {
                if( kbag->aesType != 0x80 && kbag->aesType != 0xC0 && kbag->aesType != 0x100)
                {
                    printf("Unknown aesType %x\n", kbag->aesType);
                }
                else if (keylen*4 != kbag->aesType)
                {
                    printf("Wrong length for key parameter, got %d, aesType is %x\n", keylen, kbag->aesType);
                    free(img3);
                    return NULL;
                }
                else
                {
                    printf("KBAG cryptState=%x aesType=%x\n", kbag->cryptState, kbag->aesType);
                    img3->aesType = kbag->aesType;
                }
            }
        }
        else if (img3->elements[i].magic == 'DATA')
        {
            img3->data_element = &img3->elements[i];
            
            if (img3->header.iden == 'rdsk')
            {
                //XXX hdiutil fails if extension is not .dmg
                strcpy(img3->elements[i].name, "DATA.dmg");
            }
        }
        offset += img3->elements[i].total_length;
    }
    img3->num_elements = i;
    
    if(img3->data_element != NULL && img3->aesType != 0)
    {
        img3->decrypted_data = malloc(img3->data_element->data_length);
        if (img3->decrypted_data == NULL)
        {
            perror("FAIL: malloc(img3->data_element->data_length)");
            free(img3);
            return NULL;
        }
        switch(img3->aesType)
        {
            case 0x80:
                img3->cipherType = EVP_aes_128_cbc();
                break;
            case 0xC0:
                img3->cipherType = EVP_aes_192_cbc();
                break;
            case 0x100:
                img3->cipherType = EVP_aes_256_cbc();
                break;
            default:
                return img3; //should not reach
        }
        EVP_CIPHER_CTX ctx;
        uint32_t decryptedLength = (img3->data_element->total_length - 12) & ~0xf;
        printf("Decrypting DATA section\n");

        EVP_CIPHER_CTX_init(&ctx);
        EVP_DecryptInit_ex(&ctx, img3->cipherType, NULL, img3->key, img3->iv);
        EVP_DecryptUpdate(&ctx, img3->decrypted_data, &decryptedLength,
                    &img3->mmap[img3->data_element->offset], decryptedLength);
                    
        char* info = img3_check_decrypted_data(img3->decrypted_data, decryptedLength);
        if(info != NULL)
        {
            printf("Decrypted data seems OK : %s\n", info);
        }
        else
        {
            printf("Unknown decrypted data, key/iv might be wrong\n");
        }
    }
    return img3;
}
static IMG3* img3 = NULL;

static void img3_destroy()
{
    if (img3->aesType != 0 && img3->decrypted_data != NULL && img3->data_was_modified)
    {
        EVP_CIPHER_CTX ctx;
        uint32_t encryptedLength = img3->data_element->total_length - 12;
        //printf("Encrypting DATA section\n");
        EVP_CIPHER_CTX_init(&ctx);
        EVP_EncryptInit_ex(&ctx, img3->cipherType, NULL, img3->key, img3->iv);
        EVP_EncryptUpdate(&ctx, &img3->mmap[img3->data_element->offset], &encryptedLength,
                        img3->decrypted_data, encryptedLength);
    }
}

static int
img3_getattr(const char *path, struct stat *stbuf)
{
    int i;
    memset(stbuf, 0, sizeof(struct stat));

    if(!strcmp(path, "/"))
    {
        stbuf->st_mode = S_IFDIR | 0777;
        stbuf->st_nlink = 3;
        return 0;
    }
    for(i=0; i < img3->num_elements; i++)
    {
        if(!strcmp(path+1, img3->elements[i].name))
        {
            stbuf->st_mode = S_IFREG | 0666;
            stbuf->st_nlink = 1;
            stbuf->st_size = img3->elements[i].data_length;
            return 0;
        }
    }
    return -ENOENT;
}

static int
img3_open(const char *path, struct fuse_file_info *fi)
{
    int i;
    for(i=0; i < img3->num_elements; i++)
    {
        if(!strcmp(path+1, img3->elements[i].name))
        {
            fi->fh = i;
            return 0;
        }
    }
    return -ENOENT;
}

static int
img3_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
              off_t offset, struct fuse_file_info *fi)
{
    int i;
    if(strcmp(path, "/"))
    {
        return -ENOENT;
    }

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    for(i=0; i < img3->num_elements; i++)
    {
        filler(buf, img3->elements[i].name, NULL, 0);
    }
    return 0;
}

static int
img3_read(const char *path, char *buf, size_t size, off_t offset,
           struct fuse_file_info *fi)
{
    IMG3Element* element = &img3->elements[fi->fh];

    if (offset >= element->data_length) {
        return 0;
    }

    if (offset + size > element->data_length) { /* Trim the read to the file size. */
        size = element->data_length - offset;
    }
    
    if (img3->aesType != 0 && element == img3->data_element)
    {
        memcpy(buf, img3->decrypted_data + offset, size);
        return size;
    }
    lseek(img3->fd, element->offset + offset, SEEK_SET);
    return read(img3->fd, buf, size);
}

static int
img3_write(const char *path, const char *buf, size_t size, off_t offset,
           struct fuse_file_info *fi)
{
    IMG3Element* element = &img3->elements[fi->fh];

    if (offset >= element->data_length) {
        return 0;
    }

    if (offset + size > element->data_length) { /* Trim the write to the file size. */
        size = element->data_length - offset;
    }
    
    if (img3->aesType != 0 && element == img3->data_element)
    {
        img3->data_was_modified = 1;
        memcpy(img3->decrypted_data + offset, buf, size);
        return size;
    }
    
    lseek(img3->fd, element->offset + offset, SEEK_SET);
    return write(img3->fd, buf, size);
}


static struct fuse_operations img3_filesystem_operations = {
    .getattr = img3_getattr,
    .open    = img3_open,
    .read    = img3_read,
    .write   = img3_write,
    .readdir = img3_readdir,
    .destroy = img3_destroy
};


static int img3_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
    static int i = -1;
    struct img3_config* config = (struct img3_config*) data;
    
    i++;
    if (key == FUSE_OPT_KEY_NONOPT && i == 1)
    {
        config->img3filename = strdup(arg);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct img3_config commandline_conf;
    memset(&commandline_conf, 0, sizeof(commandline_conf));

    fuse_opt_parse(&args, &commandline_conf, img3_opts, img3_opt_proc);

    if (commandline_conf.img3filename == NULL)
    {
        printf("Usage %s mountpoint img3filename [-key KEY -iv IV]\n", argv[0]);
        return -1;
    }
    img3 = img3_init(&commandline_conf);
    if (img3 != NULL)
    {
        return fuse_main(args.argc, args.argv, &img3_filesystem_operations, img3_opt_proc);
    }
    return 0;
}