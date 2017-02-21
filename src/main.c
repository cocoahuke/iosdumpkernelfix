//
//  main.m
//  FixKernelFromMem
//
//  Created by huke on 2/23/16.
//  Copyright (c) 2016 com.cocoahuke. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach-o/loader.h>
#include <mach/machine.h>
#include <mach-o/fat.h>
#include <mach-o/nlist.h>
#include <sys/stat.h>

uint64_t kr_baseAddr = 0;
size_t krcache_size = 0;

void FixSegOffset(char *pathOfkernelFile);
void FixFuncSymbol(char *pathOfkernelFile);
uint64_t machoGetVMAddr(uint8_t firstPage[4096],char *segname,char *sectname);
uint64_t machoGetFileAddr(uint8_t firstPage[4096],char *segname,char *sectname);
uint64_t machoGetSize(uint8_t firstPage[4096],char *segname,char *sectname);
uint64_t FilegetSize(char *file_path);
uint64_t FilegetSize(char *file_path){
    struct stat buf;
    if ( stat(file_path,&buf) < 0 )
    {
        perror(file_path);
        exit(1);
    }
    return buf.st_size;
}

int check_file_exist(const char *path){
    if(!access(path,F_OK)){
        if(!access(path,R_OK)){
            return 0;
        }
        return -1;
    }
    return -1;
}

int check_file_able_to_write(const char *path){
    if(!access(path,F_OK)){
        printf("%s already have same name file here\n",path);
        return -1;
    }
    return 0;
}

void usage(){
    printf("Usage: iosdumpkernelfix <orig kernel path> <output path after fixed>\n\n");
}

int main(int argc, const char * argv[]) {
    const char *orig_path = NULL;
    const char *output_path = NULL;
    
    if(argc==1){
        printf("wrong args\n");usage();exit(1);
    }
    
    for(int i=0;i<argc;i++){
        if(!strcmp(argv[i],"-h")){
            usage();exit(1);
        }
    }
    
    if(argc>2){
        orig_path = check_file_exist(argv[1])?NULL:argv[1];
        output_path = check_file_able_to_write(argv[2])?NULL:argv[2];
    }
    
    if(!orig_path){
        printf("Error: Missing orig_path\n");exit(1);
    }
    
    if(!output_path){
        printf("Error: Missing output_path\n");exit(1);
    }
    
    char cp_cmd[strlen(orig_path)+strlen(output_path)+30];
    sprintf(cp_cmd,"cp %s %s",orig_path,output_path);
    system(cp_cmd);
    
    if(check_file_exist(output_path))do{
        printf("output path(%s) is not able to write\n",output_path);exit(1);
    }while(0);
    
    printf("Start repairing the Mach-o header...\n");
    
    FixSegOffset(output_path);
    FixFuncSymbol(output_path);
    
    printf("output saved successful!\n");
    return 0;
}

#pragma mark imp:FixSegOffset(修复Seg/Sec)
void FixSegOffset(char *pathOfkernelFile){

    FILE *fp_open = fopen(pathOfkernelFile,"r");
    if(!fp_open){
        printf("file isn't exist\n");
        exit(1);
    }
    krcache_size  = FilegetSize(pathOfkernelFile);
    uint8_t firstPage[4096];
    if(fread(firstPage,1,4096,fp_open)!=4096){
        printf("fread error\n");
        exit(1);
    }
    
    fclose(fp_open);
    
    int is32 = 1;
    
    struct mach_header *mh = (struct mach_header*)firstPage;
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        is32 = 1;
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        is32 = 0;
    }
    
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)firstPage+(is32?sizeof(struct mach_header):sizeof(struct mach_header_64)));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SEGMENT:
            {
                printf("\n");
                struct segment_command *seg = (struct segment_command*)cmd;
                if(!strcmp(seg->segname,"__TEXT")){
                    kr_baseAddr = (uint64_t)seg->vmaddr;
                    if(kr_baseAddr==0)
                        exit(1);
                }
                else{
                    
                    printf("Get correctly value after cacl: 0x%x-0x%llx=0x%llx\n",seg->vmaddr,(uint64_t)kr_baseAddr,(uint64_t)seg->vmaddr-(uint64_t)kr_baseAddr);
                    seg->fileoff = (uint64_t)seg->vmaddr-(uint64_t)kr_baseAddr;
                    seg->fileoff = ((seg->fileoff+seg->filesize)>krcache_size)?krcache_size-seg->fileoff:seg->fileoff;
                    printf("Start repairing:\n");
                    
                    printf("LC_SEGMENT name:%s\n",seg->segname);
                    printf("|size:0x%x\n",cmd->cmdsize);
                    printf("|vmaddr:0x%x\n",seg->vmaddr);
                    printf("|vmsize:0x%x\n",seg->vmsize);
                    printf("|(MODIFIED)fileoff:0x%x\n",seg->fileoff);
                    printf("|filesize:0x%x\n",seg->filesize);
                    
                    printf("Then check each sections:\n");
                    
                    const uint32_t sec_count = seg->nsects;
                    struct section *sec = (struct section*)((char*)seg + sizeof(struct segment_command));
                    
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        
                        sec->offset = (uint32_t)sec->addr - (uint32_t)kr_baseAddr;
                        sec->size = ((sec->offset+sec->size)>krcache_size)?krcache_size-sec->offset:sec->size;
                        
                        printf("|---section name: %s\n",sec->sectname);
                        printf("|---section fileoff: 0x%x   (MODIFIED)\n",sec->offset);
                        
                        sec = (struct section*)((char*)sec + sizeof(struct section));
                    }
                    printf("|---------------\n");
                }
                
            }
                break;
            case LC_SEGMENT_64:
            {
                printf("\n");
                struct segment_command_64 *seg = (struct segment_command_64*)cmd;
                if(!strcmp(seg->segname,"__TEXT")){
                    kr_baseAddr = (uint64_t)seg->vmaddr;
                    if(kr_baseAddr==0)
                        exit(1);
                }
                else{
                    printf("Get correctly value after cacl: 0x%llx-0x%llx=0x%llx\n",seg->vmaddr,(uint64_t)kr_baseAddr,(uint64_t)seg->vmaddr-(uint64_t)kr_baseAddr);
                    seg->fileoff = (uint64_t)seg->vmaddr-(uint64_t)kr_baseAddr;
                    seg->fileoff = ((seg->fileoff+seg->filesize)>krcache_size)?krcache_size-seg->fileoff:seg->fileoff;
                    printf("Start repairing:\n");
                    
                    printf("LC_SEGMENT name:%s\n",seg->segname);
                    printf("|size:0x%x\n",cmd->cmdsize);
                    printf("|vmaddr:0x%llx\n",seg->vmaddr);
                    printf("|vmsize:0x%llx\n",seg->vmsize);
                    printf("|fileoff:0x%llx   (MODIFIED)\n",seg->fileoff);
                    printf("|files%llxe:0x%x\n",seg->filesize);
                    
                    printf("Then check each sections:\n");
                    
                    const uint32_t sec_count = seg->nsects;
                    struct section_64 *sec = (struct section_64*)((char*)seg + sizeof(struct segment_command_64));
                    
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        
                        sec->offset = (uint64_t)sec->addr - (uint64_t)kr_baseAddr;
                        sec->size = ((sec->offset+sec->size)>krcache_size)?krcache_size-sec->offset:sec->size;
                        
                        printf("|---section name: %s\n",sec->sectname);
                        printf("|---section fileoff: 0x%x   (MODIFIED)\n",sec->offset);
                        
                        sec = (struct section*)((char*)sec + sizeof(struct section_64));
                    }
                    printf("|---------------\n");
                }
                
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    FILE *aa = fopen(pathOfkernelFile,"r+");
    if(!aa){
        printf("error when write back 1\n");
        exit(1);
    }
    fwrite(firstPage,1,4096,aa);
}

#pragma mark imp:FixFuncSymbol(修复内核函数符号)
void FixFuncSymbol(char *pathOfkernelFile){
    printf("\n\n");
    
    FILE *fp_open = fopen(pathOfkernelFile,"r");
    if(!fp_open){
        printf("file isn't exist\n");
        exit(1);
    }
    krcache_size  = FilegetSize(pathOfkernelFile);
    printf("file size is 0x%llx\n\n",krcache_size);
    void *file_buf = malloc(krcache_size);
    if(fread(file_buf,1,krcache_size,fp_open)!=krcache_size){
        printf("fread error\n");
        exit(1);
    }
    
    fclose(fp_open);
    
    
    int is32 = 1;
    
    struct mach_header *mh = (struct mach_header*)file_buf;
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        is32 = 1;
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        is32 = 0;
    }
    
    uint32_t linkedit_fileoff = (uint32_t)machoGetFileAddr(file_buf,"__LINKEDIT",NULL);
    uint32_t linkedit_size = (uint32_t)machoGetSize(file_buf,"__LINKEDIT",NULL);
    uint64_t text_vm = machoGetVMAddr(file_buf,"__TEXT","__text");
    uint32_t text_size = (uint32_t)machoGetSize(file_buf,"__TEXT","__text");
    
    if(linkedit_fileoff==-1||linkedit_size==-1||text_vm==-1){
        printf("machoXXX 函数错误\n");
        exit(1);
    }
    
    uint32_t symoff = 0;
    uint32_t nsyms = 0;
    uint32_t stroff = 0;
    uint32_t strsize = 0;
    
    uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)file_buf+(is32?sizeof(struct mach_header):sizeof(struct mach_header_64)));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SYMTAB:{
                struct symtab_command *sym_cmd = (struct symtab_command*)cmd;
                nsyms = sym_cmd->nsyms;
                strsize = sym_cmd->strsize;
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    
    printf("Symbol table %d entries,String table %d bytes\n\n",nsyms,strsize);
    
    if(is32){
        struct nlist *nn;
        for(int i = 0;i<linkedit_size;i++){
            nn = file_buf+linkedit_fileoff+i;
            if(nn->n_un.n_strx<strsize&&nn->n_type==0xf&&nn->n_sect==0x1&&nn->n_value>=text_vm&&nn->n_value<text_vm+text_size){
                //3个条件足够找到Symbol table
                //1.nn->n_type为0xf
                //2.nn->n_sect为0x1
                //3.nn->n_value在__TEXT.__text范围内
                symoff = linkedit_fileoff+i;
                stroff = symoff + nsyms*sizeof(struct nlist);
                printf("Locate Symbol table in fileoff 0x%x\nand String table in fileoff 0x%x\n\n",symoff,stroff);
                break;
            }
        }
        
        if(symoff==0||stroff==0){
            printf("Can't locate sym/str table\n");
            exit(1);
        }
    }
    else{
        struct nlist_64 *nn;
        for(int i = 0;i<linkedit_size;i++){
            nn = file_buf+linkedit_fileoff+i;
            if(nn->n_un.n_strx<strsize&&nn->n_type==0xf&&nn->n_sect==0x1&&nn->n_value>=text_vm&&nn->n_value<text_vm+text_size){
                //3个条件足够找到Symbol table
                //1.nn->n_type为0xf
                //2.nn->n_sect为0x1
                //3.nn->n_value在__TEXT.__text范围内
                symoff = linkedit_fileoff+i;
                stroff = symoff + nsyms*sizeof(struct nlist_64);
                printf("Locate Symbol table in fileoff 0x%x\nand String table in fileoff 0x%x\n\n",symoff,stroff);
                break;
            }
        }
        
        if(symoff==0||stroff==0){
            printf("Can't locate sym/str table\n");
            exit(1);
        }
    }
    
    cmd_count = mh->ncmds;
    cmds = (struct load_command*)((char*)file_buf+(is32?sizeof(struct mach_header):sizeof(struct mach_header_64)));
    cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SYMTAB:{
                struct symtab_command *sym_cmd = (struct symtab_command*)cmd;
                (*sym_cmd).symoff = symoff;
                (*sym_cmd).stroff = stroff;
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    
    FILE *aa = fopen(pathOfkernelFile,"r+");
    if(!aa){
        printf("ptr error when write back 2\n");
        exit(1);
    }
    fwrite(file_buf,1,4096,aa);
    free(file_buf);
    printf("restore symbol/str table Done!\n");
}

uint64_t machoGetVMAddr(uint8_t firstPage[4096],char *segname,char *sectname){
    if(!segname){
        printf("machoH missing segname,it must need segname\n");
        exit(1);
    }
    
    struct fat_header* fileStartAsFat = (struct fat_header*)firstPage;
    if(fileStartAsFat->magic==FAT_CIGAM||fileStartAsFat->magic==FAT_MAGIC){
        printf("machoH is fat\n");
        exit(1);
    }
    
    struct mach_header *mh = (struct mach_header*)firstPage;
    
    int is32 = 1;
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        is32 = 1;
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        is32 = 0;
    }
    
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)firstPage+(is32?sizeof(struct mach_header):sizeof(struct mach_header_64)));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg = (struct segment_command_64*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->vmaddr;
                    }
                    
                    const uint32_t sec_count = seg->nsects;
                    struct section_64 *sec = (struct section_64*)((char*)seg + sizeof(struct segment_command_64));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->addr;
                        }
                        sec = (struct section_64*)((char*)sec + sizeof(struct section_64));
                    }
                    
                }
                
            }
            case LC_SEGMENT:
            {
                struct segment_command *seg = (struct segment_command*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->vmaddr;
                    }
                    
                    
                    const uint32_t sec_count = seg->nsects;
                    struct section *sec = (struct section*)((char*)seg + sizeof(struct segment_command));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->addr;
                        }
                        sec = (struct section*)((char*)sec + sizeof(struct section));
                    }
                    
                }
                
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return -1;
}

uint64_t machoGetFileAddr(uint8_t firstPage[4096],char *segname,char *sectname){
    if(!segname){
        printf("machoH missing segname,it must need segname\n");
        exit(1);
    }
    
    struct fat_header* fileStartAsFat = (struct fat_header*)firstPage;
    if(fileStartAsFat->magic==FAT_CIGAM||fileStartAsFat->magic==FAT_MAGIC){
        printf("machoH is fat\n");
        exit(1);
    }
    
    struct mach_header *mh = (struct mach_header*)firstPage;
    
    int is32 = 1;
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        is32 = 1;
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        is32 = 0;
    }
    
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)firstPage+(is32?sizeof(struct mach_header):sizeof(struct mach_header_64)));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg = (struct segment_command_64*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->fileoff;
                    }
                    
                    const uint32_t sec_count = seg->nsects;
                    struct section_64 *sec = (struct section_64*)((char*)seg + sizeof(struct segment_command_64));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->offset;
                        }
                        sec = (struct section_64*)((char*)sec + sizeof(struct section_64));
                    }
                    
                }
                
            }
            case LC_SEGMENT:
            {
                struct segment_command *seg = (struct segment_command*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->fileoff;
                    }
                    
                    const uint32_t sec_count = seg->nsects;
                    struct section *sec = (struct section*)((char*)seg + sizeof(struct segment_command));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->offset;
                        }
                        sec = (struct section*)((char*)sec + sizeof(struct section));
                    }
                    
                }
                
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return -1;
}

uint64_t machoGetSize(uint8_t firstPage[4096],char *segname,char *sectname){
    if(!segname){
        printf("machoH missing segname,it must need segname\n");
        exit(1);
    }
    
    struct fat_header* fileStartAsFat = (struct fat_header*)firstPage;
    if(fileStartAsFat->magic==FAT_CIGAM||fileStartAsFat->magic==FAT_MAGIC){
        printf("machoH is fat\n");
        exit(1);
    }
    
    struct mach_header *mh = (struct mach_header*)firstPage;
    
    int is32 = 1;
    
    if(mh->magic==MH_MAGIC||mh->magic==MH_CIGAM){
        is32 = 1;
    }
    else if(mh->magic==MH_MAGIC_64||mh->magic==MH_CIGAM_64){
        is32 = 0;
    }
    
    const uint32_t cmd_count = mh->ncmds;
    struct load_command *cmds = (struct load_command*)((char*)firstPage+(is32?sizeof(struct mach_header):sizeof(struct mach_header_64)));
    struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i){
        switch (cmd->cmd) {
            case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg = (struct segment_command_64*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->filesize;
                    }
                    
                    const uint32_t sec_count = seg->nsects;
                    struct section_64 *sec = (struct section_64*)((char*)seg + sizeof(struct segment_command_64));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->size;
                        }
                        sec = (struct section_64*)((char*)sec + sizeof(struct section_64));
                    }
                    
                }
                
            }
            case LC_SEGMENT:
            {
                struct segment_command *seg = (struct segment_command*)cmd;
                if(memcmp(seg->segname,segname,strlen(seg->segname))==0){
                    if(!sectname){
                        return seg->filesize;
                    }
                
                    const uint32_t sec_count = seg->nsects;
                    struct section *sec = (struct section*)((char*)seg + sizeof(struct segment_command));
                    for(uint32_t ii = 0; ii <sec_count; ++ii){
                        if(memcmp(sec->sectname,sectname,strlen(sec->sectname))==0){
                            return sec->size;
                        }
                        sec = (struct section*)((char*)sec + sizeof(struct section));
                    }
                    
                }
                
            }
                break;
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    return -1;
}