/* unpackbootimg.c
**
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
**
** Portions Copyright 2019, Elliott Mitchell
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "mincrypt/sha.h"
#include "bootimg.h"
#include "params.h"

typedef unsigned char byte;

#ifdef __GLIBC__
/* FSF, please support the standard libc API by including this function... */
/* NOTE: this is a VERY low performance implementation of this function */
size_t strlcpy(char *dst, const char *src, size_t size)
{
	size_t len=strlen(src);
	if(len<size)
		memcpy(dst, src, len+1);
	else {
		memcpy(dst, src, size-1);
		dst[size-1]='\0';
	}
	return len;
}
#endif


struct {
	char path[PATH_MAX];
	int pathlen;
	enum {FILES, PARAM_TEXT, PARAM_BIN} type;
	FILE *file;
	char sep;
} format={"", 0, FILES, NULL, '\n'};


int read_padding(FILE* f, unsigned itemsize, int pagesize)
{
    byte* buf = (byte*)malloc(sizeof(byte) * pagesize);
    unsigned pagemask = pagesize - 1;
    unsigned count;

    if((itemsize & pagemask) == 0) {
        free(buf);
        return 0;
    }

    count = pagesize - (itemsize & pagemask);

    if(fread(buf, count, 1, f)){};
    free(buf);
    return count;
}

void write_string_to_file(const char* file, const char* string)
{
    FILE* f;
    if((f = format.file)) {
        fputs(file, f);
        fputc('=', f);
    } else {
        strlcpy(format.path+format.pathlen, file, sizeof(format.path)-format.pathlen);
        f = fopen(format.path, "w");
    }
    fwrite(string, strlen(string), 1, f);
    fputc(format.sep, f);
    if(!format.file)
        fclose(f);
}

const char *detect_hash_type(boot_img_hdr_v1 *hdr)
{
    /*
     * This isn't a sophisticated or 100% reliable method to detect the hash
     * type but it's probably good enough.
     *
     * sha256 is expected to have no zeroes in the id array
     * sha1 is expected to have zeroes in id[5], id[6] and id[7]
     * Zeroes anywhere else probably indicates neither.
     */
    const uint32_t *id = hdr->id;
    if (id[0] != 0 && id[1] != 0 && id[2] != 0 && id[3] != 0 &&
        id[4] != 0 && id[5] != 0 && id[6] != 0 && id[7] != 0) {
        return "sha256";
    } else if (id[0] != 0 && id[1] != 0 && id[2] != 0 && id[3] != 0 &&
               id[4] != 0 && id[5] == 0 && id[6] == 0 && id[7] == 0) {
        return "sha1";
    } else {
        return "unknown";
    }
}

int usage()
{
    printf("usage: unpackbootimg\n");
    printf("\t-i|--input boot.img\n");
    printf("\t[ -o|--output output_directory]\n");
    printf("\t[ -p|--pagesize <size-in-hexadecimal> ]\n");
    printf("\t[ -P|--params ]    (generate text combined parameters file)\n");
    printf("\t[ -0|--bin-params ]   (generate binary combined parameters file)\n");
    return 0;
}

int main(int argc, char** argv)
{
    char tmp[PATH_MAX];
    char* directory = ".";
    char* filename = NULL;
    int pagesize = 0;
    int base = 0;

    int seeklimit = 65536; /* arbitrary byte limit to search in input file for ANDROID! magic */
    int hdr_ver_max = 4; /* arbitrary maximum header version value; when greater assume the field is appended dtb size */

    argc--;
    argv++;
    while(argc > 0){
        char *arg = argv[0];
        char *val = argv[1];
        argc -= 2;
        argv += 2;
        if(!strcmp(arg, "--input") || !strcmp(arg, "-i")) {
            filename = val;
        } else if(!strcmp(arg, "--output") || !strcmp(arg, "-o")) {
            directory = val;
        } else if(!strcmp(arg, "--pagesize") || !strcmp(arg, "-p")) {
            pagesize = strtoul(val, 0, 16);
        } else if(!strcmp(arg, "--params") || !strcmp(arg, "-P")) {
            format.type=PARAM_TEXT;
        } else if(!strcmp(arg, "--bin-params") || !strcmp(arg, "-0")) {
            format.type=PARAM_BIN;
        } else {
            return usage();
        }
    }

    if (filename == NULL) {
        return usage();
    }

    int total_read = 0;
    FILE* f = fopen(filename, "rb");
    boot_img_hdr_v1 header;

    if (!f) {
        printf("Could not open input file: %s\n", strerror(errno));
        return (1);
    }

    if(chdir(directory)<0) {
        fprintf(stderr, "Could not change to directory %s: %s\n", directory, strerror(errno));
        return 1;
    }

    format.pathlen = snprintf(format.path, sizeof(format.path), "%s-", basename(filename));

    if(format.type!=FILES) {
        char *formatstr;
        char *mode;

        if(format.type==PARAM_BIN) {
            format.sep='\0';
            mode="wb";
            formatstr="format=binary";
        } else {
            mode="wt";
            formatstr="format=text";
        }

        strlcpy(format.path+format.pathlen, PARAMS_OPT, sizeof(format.path)-strlen(PARAMS_OPT));

        format.file=fopen(format.path, mode);
        fputs(formatstr, format.file);
        fputc(format.sep, format.file);
    }

    //printf("Reading header...\n");
    int i;
    for (i = 0; i <= seeklimit; i++) {
        fseek(f, i, SEEK_SET);
        if(fread(tmp, BOOT_MAGIC_SIZE, 1, f)){};
        if (memcmp(tmp, BOOT_MAGIC, BOOT_MAGIC_SIZE) == 0) {
            break;
        }
    }
    total_read = i;
    if (i > seeklimit) {
        printf("Android boot magic not found.\n");
        return 1;
    }
    fseek(f, i, SEEK_SET);
    if (i > 0) {
        printf("Android magic found at: %d\n", i);
    }

    if(fread(&header, sizeof(header), 1, f)){};
    base = header.kernel_addr - 0x00008000;
    printf("BOARD_KERNEL_CMDLINE %.*s%.*s\n", BOOT_ARGS_SIZE, header.cmdline, BOOT_EXTRA_ARGS_SIZE, header.extra_cmdline);
    printf("BOARD_KERNEL_BASE 0x%08x\n", base);
    printf("BOARD_NAME %s\n", header.name);
    printf("BOARD_PAGE_SIZE %d\n", header.page_size);
    printf("BOARD_HASH_TYPE %s\n", detect_hash_type(&header));
    printf("BOARD_KERNEL_OFFSET 0x%08x\n", header.kernel_addr - base);
    printf("BOARD_RAMDISK_OFFSET 0x%08x\n", header.ramdisk_addr - base);
    printf("BOARD_SECOND_OFFSET 0x%08x\n", header.second_addr - base);
    printf("BOARD_TAGS_OFFSET 0x%08x\n", header.tags_addr - base);

    int a=0, b=0, c=0, y=0, m=0;
    if (header.os_version != 0) {
        int os_version,os_patch_level;
        os_version = header.os_version >> 11;
        os_patch_level = header.os_version&0x7ff;

        a = (os_version >> 14)&0x7f;
        b = (os_version >> 7)&0x7f;
        c = os_version&0x7f;

        y = (os_patch_level >> 4) + 2000;
        m = os_patch_level&0xf;

        if((a < 128) && (b < 128) && (c < 128) && (y >= 2000) && (y < 2128) && (m > 0) && (m <= 12)) {
            printf("BOARD_OS_VERSION %d.%d.%d\n", a, b, c);
            printf("BOARD_OS_PATCH_LEVEL %d-%02d\n", y, m);
        } else {
            header.os_version = 0;
        }
    }

    if (header.dt_size > hdr_ver_max) {
        printf("BOARD_DT_SIZE %d\n", header.dt_size);
    } else {
        printf("BOARD_HEADER_VERSION %d\n", header.header_version);
    }
    if (header.header_version > 0 && header.header_version <= hdr_ver_max) {
        if (header.recovery_dtbo_size != 0) {
            printf("BOARD_RECOVERY_DTBO_SIZE %d\n", header.recovery_dtbo_size);
            printf("BOARD_RECOVERY_DTBO_OFFSET %"PRId64"\n", header.recovery_dtbo_offset);
        }
        printf("BOARD_HEADER_SIZE %d\n", header.header_size);
    }

    if (pagesize == 0) {
        pagesize = header.page_size;
    }

    //printf("cmdline...\n");
    char cmdlinetmp[BOOT_ARGS_SIZE+BOOT_EXTRA_ARGS_SIZE+1];
    sprintf(cmdlinetmp, "%.*s%.*s", BOOT_ARGS_SIZE, header.cmdline, BOOT_EXTRA_ARGS_SIZE, header.extra_cmdline);
    cmdlinetmp[BOOT_ARGS_SIZE+BOOT_EXTRA_ARGS_SIZE]='\0';
    write_string_to_file(CMDLINE_OPT, cmdlinetmp);

    //printf("board...\n");
    write_string_to_file(BOARD_OPT, (char *)header.name);

    //printf("base...\n");
    char basetmp[200];
    sprintf(basetmp, "0x%08x", base);
    write_string_to_file(BASE_OPT, basetmp);

    //printf("pagesize...\n");
    char pagesizetmp[200];
    sprintf(pagesizetmp, "%d", header.page_size);
    write_string_to_file(PAGE_OPT, pagesizetmp);

    //printf("kernel_offset...\n");
    char kernelofftmp[200];
    sprintf(kernelofftmp, "0x%08x", header.kernel_addr - base);
    write_string_to_file(KERNEL_OFF_OPT, kernelofftmp);

    //printf("ramdisk_offset...\n");
    char ramdiskofftmp[200];
    sprintf(ramdiskofftmp, "0x%08x", header.ramdisk_addr - base);
    write_string_to_file(RAMDISK_OFF_OPT, ramdiskofftmp);

    //printf("second_offset...\n");
    char secondofftmp[200];
    sprintf(secondofftmp, "0x%08x", header.second_addr - base);
    write_string_to_file(SECOND_OFF_OPT, secondofftmp);

    //printf("tags_offset...\n");
    char tagsofftmp[200];
    sprintf(tagsofftmp, "0x%08x", header.tags_addr - base);
    write_string_to_file(TAGS_OFF_OPT, tagsofftmp);

    if (header.os_version != 0) {
        //printf("os_version...\n");
        char osvertmp[200];
        sprintf(osvertmp, "%d.%d.%d", a, b, c);
        write_string_to_file(OS_VER_OPT, osvertmp);

        //printf("os_patch_level...\n");
        char oslvltmp[200];
        sprintf(oslvltmp, "%d-%02d", y, m);
        write_string_to_file(OS_PATCH_OPT, oslvltmp);
    }

    if (header.dt_size < hdr_ver_max) {
        //printf("header_version...\n");
        char hdrvertmp[200];
        sprintf(hdrvertmp, "%d", header.header_version);
        write_string_to_file(HEADER_VERS_OPT, hdrvertmp);
    }

    //printf("hash...\n");
    const char *hashtype = detect_hash_type(&header);
    write_string_to_file(HASH_OPT, hashtype);

    total_read += sizeof(header);
    //printf("total read: %d\n", total_read);
    total_read += read_padding(f, sizeof(header), pagesize);

    sprintf(tmp, "%s-zImage", basename(filename));
    FILE *k = fopen(tmp, "wb");
    byte* kernel = (byte*)malloc(header.kernel_size);
    //printf("Reading kernel...\n");
    if(fread(kernel, header.kernel_size, 1, f)){};
    total_read += header.kernel_size;
    fwrite(kernel, header.kernel_size, 1, k);
    fclose(k);

    //printf("total read: %d\n", header.kernel_size);
    total_read += read_padding(f, header.kernel_size, pagesize);

    sprintf(tmp, "%s-ramdisk.gz", basename(filename));
    FILE *r = fopen(tmp, "wb");
    byte* ramdisk = (byte*)malloc(header.ramdisk_size);
    //printf("Reading ramdisk...\n");
    if(fread(ramdisk, header.ramdisk_size, 1, f)){};
    total_read += header.ramdisk_size;
    fwrite(ramdisk, header.ramdisk_size, 1, r);
    fclose(r);

    //printf("total read: %d\n", header.ramdisk_size);
    total_read += read_padding(f, header.ramdisk_size, pagesize);

    if (header.second_size > 0) {
        sprintf(tmp, "%s-%s", basename(filename), SECOND_OPT);
        FILE *s = fopen(tmp, "wb");
        byte* second = (byte*)malloc(header.second_size);
        //printf("Reading second...\n");
        if(fread(second, header.second_size, 1, f)){};
        total_read += header.second_size;
        fwrite(second, header.second_size, 1, s);
        fclose(s);
    }

    //printf("total read: %d\n", header.second_size);
    total_read += read_padding(f, header.second_size, pagesize);

    if (header.dt_size > hdr_ver_max) {
        sprintf(tmp, "%s-%s", basename(filename), DT_OPT);
        FILE *d = fopen(tmp, "wb");
        byte* dtb = (byte*)malloc(header.dt_size);
        //printf("Reading dtb...\n");
        if(fread(dtb, header.dt_size, 1, f)){};
        total_read += header.dt_size;
        fwrite(dtb, header.dt_size, 1, d);
        fclose(d);
    } else if (header.recovery_dtbo_size != 0) {
        sprintf(tmp, "%s-%s", basename(filename), RECOVERY_DT_OPT);
        FILE *o = fopen(tmp, "wb");
        byte* dtbo = (byte*)malloc(header.recovery_dtbo_size);
        //printf("Reading recoverydtbo...\n");
        if(fread(dtbo, header.recovery_dtbo_size, 1, f)){};
        total_read += header.recovery_dtbo_size;
        fwrite(dtbo, header.recovery_dtbo_size, 1, o);
        fclose(o);
    }

    fclose(f);

    //printf("Total Read: %d\n", total_read);
    return 0;
}
