/* tools/mkbootimg/mkbootimg.c
**
** Copyright 2007, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/


#define _GNU_SOURCE


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>

#include "mincrypt/sha.h"
#include "mincrypt/sha256.h"
#include "bootimg.h"
#include "params.h"


enum hash_alg {
    HASH_UNKNOWN = -1,
    HASH_SHA1 = 0,
    HASH_SHA256,
};

struct params {
	boot_img_hdr_v1 hdr;

	char *output_fn;
	char *kernel_fn;
	char *ramdisk_fn;
	char *dt_fn;
	char *second_fn;
	char *recovery_dtbo_fn;

	char *cmdline;
	char *board;
	uint32_t base;

	enum hash_alg hash_alg;
	bool get_id;
};


typedef int param_func(struct params *params, const char *opt, char *val,
void *extra);

static param_func parse_str, parse_uint;

static param_func parse_os_version, parse_os_patch_level;

static param_func parse_pagesize, parse_header_vers;

static param_func parse_hash_alg, get_id_arg_func;


extern struct params *fake_params_ptr;
#define PARAMS_STR_IDX(arg) (void *)((char **)(&fake_params_ptr->arg)-(char **)fake_params_ptr)
#define PARAMS_UINT_IDX(arg) (void *)((uint32_t *)(&fake_params_ptr->arg)-(uint32_t *)fake_params_ptr)

struct param_entry {
	const char *const name;
	param_func *func;
	void *extra;
} options[]={
	{BASE_OPT,	parse_uint,	PARAMS_UINT_IDX(base)},
	{BOARD_OPT,	parse_str,	PARAMS_UINT_IDX(board)},
	{CMDLINE_OPT,	parse_str,	PARAMS_STR_IDX(cmdline)},
	{DT_OPT,	parse_str,	PARAMS_STR_IDX(dt_fn)},
	{HASH_OPT,	parse_hash_alg,	NULL},
	{HEADER_VERS_OPT, parse_header_vers, NULL},
	{"id",		get_id_arg_func, NULL},
	{KERNEL_OPT,	parse_str,	PARAMS_STR_IDX(kernel_fn)},
	{KERNEL_OFF_OPT, parse_uint,	PARAMS_UINT_IDX(hdr.kernel_addr)},
	{OS_PATCH_OPT,	parse_os_patch_level, NULL},
	{OS_VER_OPT,	parse_os_version, NULL},
	{"output",	parse_str,	PARAMS_STR_IDX(output_fn)},
	{PAGE_OPT,	parse_pagesize,	NULL},
	{RAMDISK_OPT,	parse_str,	PARAMS_STR_IDX(ramdisk_fn)},
	{RAMDISK_OFF_OPT, parse_uint,	PARAMS_UINT_IDX(hdr.ramdisk_addr)},
	{RECOVERY_DT_OPT, parse_str,	PARAMS_STR_IDX(recovery_dtbo_fn)},
	{SECOND_OPT,	parse_str,	PARAMS_STR_IDX(second_fn)},
	{SECOND_OFF_OPT, parse_uint,	PARAMS_UINT_IDX(hdr.second_addr)},
	{TAGS_OFF_OPT,	parse_uint,	PARAMS_UINT_IDX(hdr.tags_addr)},
};

#undef PARAMS_STR_IDX
#undef PARAMS_UINT_IDX


static int load_file(const char *const usage, const char *const fn,
uint32_t *_sz, void **_data)
{
    char *data = NULL;
    off_t sz = 0;
    int fd = -1;

    if(fn) {
        fd = open(fn, O_RDONLY);
        if(fd < 0) goto oops;

        sz = lseek(fd, 0, SEEK_END);
        if(sz < 0) goto oops;

        if(lseek(fd, 0, SEEK_SET) != 0) goto oops;

        data = (char*) malloc(sz);
        if(!data) goto oops;

        if(read(fd, data, sz) != sz) goto oops;
    }

    while(0) {
oops:
        if(data) {
            free(data);
            data = NULL;
        }

        fprintf(stderr,"error: could not load %s '%s'\n", usage, fn);

        sz = -1;
    }

    if(fd>=0) close(fd);

    *_data = data;
    *_sz = sz;

    return sz;
}

int usage(void)
{
    fprintf(stderr,"usage: mkbootimg\n"
            "       --" KERNEL_OPT " <filename>\n"
            "       [ --" RAMDISK_OPT " <filename> ]\n"
            "       [ --" SECOND_OPT " <2ndbootloader-filename> ]\n"
            "       [ --" RECOVERY_DT_OPT " <recoverydtbo-filename> ]\n"
            "       [ --" CMDLINE_OPT " <kernel-commandline> ]\n"
            "       [ --" BOARD_OPT " <boardname> ]\n"
            "       [ --" BASE_OPT " <address> ]\n"
            "       [ --" PAGE_OPT " <pagesize> ]\n"
            "       [ --" DT_OPT " <dtb-filename> ]\n"
            "       [ --" KERNEL_OFF_OPT " <base offset> ]\n"
            "       [ --" RAMDISK_OFF_OPT " <base offset> ]\n"
            "       [ --" SECOND_OFF_OPT " <base offset> ]\n"
            "       [ --" TAGS_OFF_OPT " <base offset> ]\n"
            "       [ --" OS_VER_OPT " <A.B.C version> ]\n"
            "       [ --" OS_PATCH_OPT " <YYYY-MM date> ]\n"
            "       [ --" HEADER_VERS_OPT " <version number> ]\n"
            "       [ --" HASH_OPT " <sha1(default)|sha256> ]\n"
            "       [ --id ]\n"
            "       -o|--output <filename>\n"
            );
    return 1;
}


static void print_id(const uint8_t *id, size_t id_len)
{
    printf("0x");
    unsigned i = 0;
    for(i = 0; i < id_len; i++) {
        printf("%02x", id[i]);
    }
    printf("\n");
}


int write_padded(int fd, unsigned pagesize, const void *buf, size_t itemsize)
{
    unsigned pagemask = pagesize - 1;
    ssize_t count;
    off_t len;

    if(write(fd, buf, itemsize) != itemsize) return -1;

    if((itemsize & pagemask) == 0) {
        return itemsize;
    }

    count = pagesize - (itemsize & pagemask);

    /* For the uninitiated: Yes, it is perfectly legal to seek beyond the end
    ** of file. */

    if((len = lseek(fd, count, SEEK_CUR))<0) return -1;

    /* Yes, it is also perfectly legal to truncate a file to longer than it
    ** previously was.  This creates a "hole" which is filled with zeros
    ** (we could simply leave the file pointer here, but if no further data was
    ** written, the file would be left unpadded). */

    if(ftruncate(fd, len)<0) return -1;

    return itemsize;
}


/* generic string accepting function */
static int parse_str(struct params *_params, const char *opt, char *val,
void *extra)
{
	char **params=(char **)_params;
	intptr_t index=(intptr_t)extra;

	if(!val) return -1; /* indicates no argument */

	params[index]=val;

	return 2;
}


/* generic uint32 accepting function */
static int parse_uint(struct params *_params, const char *opt, char *val,
void *extra)
{
	uint32_t *params=(uint32_t *)_params;
	intptr_t index=(intptr_t)extra;

	if(!val||!val[0]) return -1; /* indicates no argument */

	errno=0;

	params[index]=strtoul(val, 0, 16);

	if(errno) return -errno;

	return 2;
}


static int parse_pagesize(struct params *params, const char *opt, char *val,
void *extra)
{
	uint32_t pagesize;

	if(!val||!val[0]) return -1; /* indicates no argument */

	errno=0;

	pagesize = strtoul(val, 0, 10);

	if(errno) return -errno;

	if ((pagesize & (pagesize-1)) || (pagesize < (1<<11))) {
		fprintf(stderr,"error: unsupported page size %d\n", pagesize);
		return -1;
	}

	params->hdr.page_size=pagesize;

	return 2;
}


static int parse_os_version(struct params *params, const char *opt, char *ver,
void *extra)
{
    unsigned int a, b = 0, c = 0;
    int i;

    if(!ver||!ver[0]) return -1; /* indicates no argument */

    i = sscanf(ver, "%u.%u.%u", &a, &b, &c);

    params->hdr.os_version &= 0x7FFUL;
    if((i < 1) || (a >= 128) || (b >= 128) || (c >= 128))
        return -1;

    params->hdr.os_version |= (a << 25) | (b << 18) | (c << 11);
    return 2;
}

static int parse_os_patch_level(struct params *params, const char *opt,
char *lvl, void *extra)
{
    unsigned int y, m;
    int i;

    if(!lvl||!lvl[0]) return -1; /* indicates no argument */

    i = sscanf(lvl, "%u-%u", &y, &m);
    y -= 2000;

    params->hdr.os_version &= ~0x7FFUL;
    if((i != 2) || (y >= 128) || (m <= 0) || (m > 12))
        return -1;

    params->hdr.os_version |= (y << 4) | m;
    return 2;
}


static int parse_header_vers(struct params *params, const char *opt, char *val,
void *extra)
{
	if(!val||!val[0]) return -1; /* indicates no argument */

	errno=0;

	params->hdr.header_version=strtoul(val, 0, 10);

	if(errno) return -errno;

	return 2;
}


struct hash_name {
    const char *name;
    enum hash_alg alg;
};

const struct hash_name hash_names[] = {
    { "sha1", HASH_SHA1 },
    { "sha256", HASH_SHA256 },
    { NULL, /* Sentinel */ },
};

static int parse_hash_alg(struct params *params, const char *opt, char *name,
void *extra)
{
    const struct hash_name *ptr = hash_names;

    if(!name||!name[0]) return -1; /* indicates no argument */

    while(ptr->name) {
        if(!strcmp(ptr->name, name)) {
            params->hash_alg = ptr->alg;
            return 2;
        }
        ptr++;
    }

    return -1;
}


static int get_id_arg_func(struct params *params, const char *opt, char *val,
void *extra)
{
	params->get_id=true;
	return 1; /* we don't take an argument, someone else can have it */
}


void generate_id_sha1(boot_img_hdr_v1 *hdr, void *kernel_data, void *ramdisk_data,
                      void *second_data, void *dt_data, void *recovery_dtbo_data)
{
    SHA_CTX ctx;
    const uint8_t *sha;

    SHA_init(&ctx);
    SHA_update(&ctx, kernel_data, hdr->kernel_size);
    SHA_update(&ctx, &hdr->kernel_size, sizeof(hdr->kernel_size));
    SHA_update(&ctx, ramdisk_data, hdr->ramdisk_size);
    SHA_update(&ctx, &hdr->ramdisk_size, sizeof(hdr->ramdisk_size));
    SHA_update(&ctx, second_data, hdr->second_size);
    SHA_update(&ctx, &hdr->second_size, sizeof(hdr->second_size));
    if(dt_data) {
        SHA_update(&ctx, dt_data, hdr->dt_size);
        SHA_update(&ctx, &hdr->dt_size, sizeof(hdr->dt_size));
    } else if(hdr->header_version > 0) {
        SHA_update(&ctx, recovery_dtbo_data, hdr->recovery_dtbo_size);
        SHA_update(&ctx, &hdr->recovery_dtbo_size, sizeof(hdr->recovery_dtbo_size));
    }
    sha = SHA_final(&ctx);
    memcpy(hdr->id, sha, SHA_DIGEST_SIZE > sizeof(hdr->id) ? sizeof(hdr->id) : SHA_DIGEST_SIZE);
}

void generate_id_sha256(boot_img_hdr_v1 *hdr, void *kernel_data, void *ramdisk_data,
                        void *second_data, void *dt_data, void *recovery_dtbo_data)
{
    SHA256_CTX ctx;
    const uint8_t *sha;

    SHA256_init(&ctx);
    SHA256_update(&ctx, kernel_data, hdr->kernel_size);
    SHA256_update(&ctx, &hdr->kernel_size, sizeof(hdr->kernel_size));
    SHA256_update(&ctx, ramdisk_data, hdr->ramdisk_size);
    SHA256_update(&ctx, &hdr->ramdisk_size, sizeof(hdr->ramdisk_size));
    SHA256_update(&ctx, second_data, hdr->second_size);
    SHA256_update(&ctx, &hdr->second_size, sizeof(hdr->second_size));
    if(dt_data) {
        SHA256_update(&ctx, dt_data, hdr->dt_size);
        SHA256_update(&ctx, &hdr->dt_size, sizeof(hdr->dt_size));
    } else if(hdr->header_version > 0) {
        SHA256_update(&ctx, recovery_dtbo_data, hdr->recovery_dtbo_size);
        SHA256_update(&ctx, &hdr->recovery_dtbo_size, sizeof(hdr->recovery_dtbo_size));
    }
    sha = SHA256_final(&ctx);
    memcpy(hdr->id, sha, SHA256_DIGEST_SIZE > sizeof(hdr->id) ? sizeof(hdr->id) : SHA256_DIGEST_SIZE);
}

void generate_id(enum hash_alg alg, boot_img_hdr_v1 *hdr, void *kernel_data,
                 void *ramdisk_data, void *second_data, void *dt_data, void *recovery_dtbo_data)
{
    switch(alg) {
        case HASH_SHA1:
            generate_id_sha1(hdr, kernel_data, ramdisk_data, second_data, dt_data, recovery_dtbo_data);
            break;
        case HASH_SHA256:
            generate_id_sha256(hdr, kernel_data, ramdisk_data, second_data, dt_data, recovery_dtbo_data);
            break;
        case HASH_UNKNOWN:
        default:
            fprintf(stderr, "Unknown hash type.\n");
    }
}

int main(int argc, char **argv)
{
    struct params params;
    boot_img_hdr_v1 hdr;

    memset(&params, 0, sizeof(params));

    char *kernel_fn = NULL;
    void *kernel_data = NULL;
    char *ramdisk_fn = NULL;
    void *ramdisk_data = NULL;
    char *second_fn = NULL;
    void *second_data = NULL;
    char *recovery_dtbo_fn = NULL;
    void *recovery_dtbo_data = NULL;
    char *cmdline = "";
    params.cmdline = "";
    char *bootimg = NULL;
    char *board = "";
    params.board = "";
    int os_version = 0;
    int os_patch_level = 0;
    int header_version = 0;
    char *dt_fn = NULL;
    void *dt_data = NULL;
    uint32_t pagesize = 2048;
    params.hdr.page_size = 2048;
    int fd;
    uint32_t base           = 0x10000000U;
    params.base             = 0x10000000U;
    uint32_t kernel_offset  = 0x00008000U;
    params.hdr.kernel_addr  = 0x00008000U;
    uint32_t ramdisk_offset = 0x01000000U;
    params.hdr.ramdisk_addr = 0x01000000U;
    uint32_t second_offset  = 0x00f00000U;
    params.hdr.second_addr  = 0x00f00000U;
    uint32_t tags_offset    = 0x00000100U;
    params.hdr.tags_addr    = 0x00000100U;
    uint32_t kernel_sz      = 0;
    uint32_t ramdisk_sz     = 0;
    uint32_t second_sz      = 0;
    uint32_t dt_sz          = 0;
    uint32_t rec_dtbo_sz    = 0;
    uint64_t rec_dtbo_offset= 0;
    uint32_t header_sz      = 0;
    int ret;

    size_t cmdlen;
    enum hash_alg hash_alg = HASH_SHA1;
    params.hash_alg = HASH_SHA1;

    argc--;
    argv++;

    memset(&hdr, 0, sizeof(hdr));

    bool get_id = false;
    while(argc > 0){
        char *arg = argv[0];

        if(strncmp("--", arg, 2)) {
            if(arg[1]=='o'&&arg[2]==0&&argc>=2) {
                params.output_fn=argv[1];
                argc-=2;
                argv+=2;
            } else return usage();
        } else {
            unsigned lo=0, hi=sizeof(options)/sizeof(options[0]), mid;
            int res;
            int l;
            char *val;
            val=strchrnul(arg+2, '=');
            l=val-arg-2;
            if(val) ++val;
            else if(argc>=2) val=argv[1];
            else val=NULL;

            while(mid=(hi+lo)/2, (res=strncmp(arg+2, options[mid].name, l))||options[mid].name[l]) {
                if(res<=0) hi=mid;
                else lo=mid+1;
                if(lo==hi) return usage();
            }

            l=options[mid].func(&params, options[mid].name, val, options[mid].extra);
            if(l<0) return usage();

            l=(l==2)&&(val==argv[1])?2:1;
            argc-=l;
            argv+=l;
        }


#if 0
        if(!strcmp(arg, "--id")) {
            get_id = true;
            argc -= 1;
            argv += 1;
        } else if(argc >= 2) {
            char *val = argv[1];
            argc -= 2;
            argv += 2;
            if(!strcmp(arg, "--output") || !strcmp(arg, "-o")) {
                bootimg = val;
            } else if(!strcmp(arg, "--" KERNEL_OPT)) {
                kernel_fn = val;
            } else if(!strcmp(arg, "--" RAMDISK_OPT)) {
                ramdisk_fn = val;
            } else if(!strcmp(arg, "--" SECOND_OPT)) {
                second_fn = val;
            } else if(!strcmp(arg, "--" RECOVERY_DT_OPT)) {
                recovery_dtbo_fn = val;
            } else if(!strcmp(arg, "--" CMDLINE_OPT)) {
                cmdline = val;
            } else if(!strcmp(arg, "--" BASE_OPT)) {
                base = strtoul(val, 0, 16);
            } else if(!strcmp(arg, "--" KERNEL_OFF_OPT)) {
                kernel_offset = strtoul(val, 0, 16);
            } else if(!strcmp(arg, "--" RAMDISK_OFF_OPT)) {
                ramdisk_offset = strtoul(val, 0, 16);
            } else if(!strcmp(arg, "--" SECOND_OFF_OPT)) {
                second_offset = strtoul(val, 0, 16);
            } else if(!strcmp(arg, "--" TAGS_OFF_OPT)) {
                tags_offset = strtoul(val, 0, 16);
            } else if(!strcmp(arg, "--" BOARD_OPT)) {
                board = val;
            } else if(!strcmp(arg,"--" PAGE_OPT)) {
                pagesize = strtoul(val, 0, 10);
                if ((pagesize & (pagesize-1)) || (pagesize < (1<<11))) {
                    fprintf(stderr,"error: unsupported page size %d\n", pagesize);
                    return -1;
                }
            } else if(!strcmp(arg, "--" DT_OPT)) {
                dt_fn = val;
            } else if(!strcmp(arg, "--" OS_VER_OPT)) {
                os_version = parse_os_version(val);
            } else if(!strcmp(arg, "--" OS_PATCH_OPT)) {
                os_patch_level = parse_os_patch_level(val);
            } else if(!strcmp(arg, "--" HEADER_VERS_OPT)) {
                header_version = strtoul(val, 0, 10);
            } else if(!strcmp(arg, "--" HASH_OPT)) {
                hash_alg = parse_hash_alg(val);
                if (hash_alg == HASH_UNKNOWN) {
                    fprintf(stderr, "error: unknown hash algorithm '%s'\n", val);
                    return -1;
                }
            } else {
                return usage();
            }
        } else {
            return usage();
        }
#endif
    }
    hdr.page_size = pagesize;

    hdr.kernel_addr =  base + kernel_offset;
    hdr.ramdisk_addr = base + ramdisk_offset;
    hdr.second_addr =  base + second_offset;
    hdr.tags_addr =    base + tags_offset;

    params.hdr.kernel_addr += params.base;
    params.hdr.ramdisk_addr += params.base;
    params.hdr.second_addr += params.base;
    params.hdr.tags_addr += params.base;

    hdr.os_version = (os_version << 11) | os_patch_level;
    hdr.header_version = header_version;

    if(bootimg == 0) {
        fprintf(stderr,"error: no output filename specified\n");
        return usage();
    }

    if(kernel_fn == 0) {
        fprintf(stderr,"error: no kernel image specified\n");
        return usage();
    }

    if(strlen(board) >= BOOT_NAME_SIZE) {
        fprintf(stderr,"error: board name too large\n");
        return usage();
    }

    strcpy((char *) hdr.name, board);

    memcpy(hdr.magic, BOOT_MAGIC, BOOT_MAGIC_SIZE);

    cmdlen = strlen(cmdline);
    if(cmdlen <= BOOT_ARGS_SIZE) {
        strcpy((char *)hdr.cmdline, cmdline);
    } else if(cmdlen <= BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE) {
        /* exceeds the limits of the base command-line size, go for the extra */
        memcpy(hdr.cmdline, cmdline, BOOT_ARGS_SIZE);
        strcpy((char *)hdr.extra_cmdline, cmdline+BOOT_ARGS_SIZE);
    } else {
        fprintf(stderr,"error: kernel commandline too large\n");
        return 1;
    }

    if((ret=load_file("kernel", kernel_fn, &kernel_sz, &kernel_data))<=0) {
        /* unlike most files, kernel is required and even zero is error */
        if(!ret) fprintf(stderr,"error: could not load kernel '%s'\n", kernel_fn);
        return 1;
    }
    hdr.kernel_size = kernel_sz;

    if(load_file("ramdisk", ramdisk_fn, &ramdisk_sz, &ramdisk_data)<0)
        return 1;
    hdr.ramdisk_size = ramdisk_sz;

    if(load_file("secondstage", second_fn, &second_sz, &second_data)<0)
        return 1;
    hdr.second_size = second_sz;

    if(header_version == 0) {
        if(load_file("device tree image", dt_fn, &dt_sz, &dt_data)<0)
            return 1;
        hdr.dt_size = dt_sz; /* overrides hdr.header_version */
    } else {
        if((ret=load_file("recovery dtbo image", recovery_dtbo_fn, &rec_dtbo_sz, &recovery_dtbo_data))) {
            if(ret<0)
                return 1;
            /* header occupies a page */
            rec_dtbo_offset = pagesize * (1 + \
                                          (kernel_sz + pagesize - 1) / pagesize + \
                                          (ramdisk_sz + pagesize - 1) / pagesize + \
                                          (second_sz + pagesize - 1) / pagesize);
        }
        header_sz = sizeof(hdr);
    }
    hdr.recovery_dtbo_size = rec_dtbo_sz;
    hdr.recovery_dtbo_offset = rec_dtbo_offset;
    hdr.header_size = header_sz;

    /* put a hash of the contents in the header so boot images can be
     * differentiated based on their first 2k.
     */
    generate_id(hash_alg, &hdr, kernel_data, ramdisk_data, second_data, dt_data, recovery_dtbo_data);

    fd = open(bootimg, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if(fd < 0) {
        fprintf(stderr,"error: could not create '%s'\n", bootimg);
        return 1;
    }

    if(write_padded(fd, pagesize, &hdr, sizeof(hdr))<=0) goto fail;

    if(write_padded(fd, pagesize, kernel_data, hdr.kernel_size)<=0) goto fail;

    if(write_padded(fd, pagesize, ramdisk_data, hdr.ramdisk_size)<0) goto fail;

    if(second_data) {
        if(write_padded(fd, pagesize, second_data, hdr.second_size)<0) goto fail;
    }

    if(dt_data) {
        if(write_padded(fd, pagesize, dt_data, hdr.dt_size)<0) goto fail;
    } else if(recovery_dtbo_data) {
        if(write_padded(fd, pagesize, recovery_dtbo_data, hdr.recovery_dtbo_size)<0) goto fail;
    }

    if(get_id) {
        print_id((uint8_t *) hdr.id, sizeof(hdr.id));
    }
    return 0;

fail:
    unlink(bootimg);
    close(fd);
    fprintf(stderr,"error: failed writing '%s': %s\n", bootimg,
            strerror(errno));
    return 1;
}
