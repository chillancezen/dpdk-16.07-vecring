#include "hugepage_util.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>



#define HUGEPAGE_PATH "/dev/hugepages"

#define MAX_HUGEHUGE_PAGE_NR (16*1024) /*maximum 32GB*/


void hugepage_util_init(char* huge_dir)
{
	char cmd[128];
	memset(cmd,0x0,sizeof(cmd));
	sprintf(cmd,"rm -f %s/vecring*",huge_dir?huge_dir:HUGEPAGE_PATH);
	system(cmd);
}
uint64_t preserve_vm_area(int nr_pages,void **raw_addr)
{
        void* addr=NULL;
        int fd;
        fd=open("/dev/zero",O_RDONLY);
        if(fd<0)
                goto ret;
        addr=mmap(0,(nr_pages+2)*HUGEPAGE_2M, PROT_READ, MAP_PRIVATE, fd, 0);
        if(!addr)
                goto fails;
        //printf("[x]unaligned preserved memory start address:%"PRIx64"\n",(uint64_t)addr);
        if(raw_addr)
                *raw_addr=(void*)addr;
        munmap(addr,(nr_pages+2)*HUGEPAGE_2M);

        addr=(void*)((HUGEPAGE_2M+(uint64_t)addr)&(uint64_t)(~HUGEPAGE_2M_MASK));
        //printf("[x]aligned preserved memory start address:%"PRIx64"\n",(uint64_t)addr);
        ret:
        return (uint64_t)addr;

        fails:
                close(fd);
                goto ret;
}

static int find_numa_socket_for_hugepgae(char *path)
{
	int target_socket_id=0;
	FILE *fp;
	char buffer[256];
	char *ptr;
	char *node_str;
	fp=fopen("/proc/self/numa_maps","r");
	if(!fp)
		return 0;
	memset(buffer,0x0,sizeof(buffer));
	while(!0){
		memset(buffer,0x0,sizeof(buffer));
		if(fgets(buffer,sizeof(buffer),fp)==NULL)
			break;
		ptr=strstr(buffer,path);
		if(!ptr)
			continue;
		ptr=strstr(buffer," huge ");
		if(!ptr)
			continue;
		node_str=strstr(buffer," N");
		if(!node_str)
			continue;
		node_str+=2;
		for(ptr=node_str;(*ptr>='0')&&(*ptr<='9');ptr++);
		if(*ptr!='=')
			continue;
		*ptr='\0';
		target_socket_id=atoi(node_str);
		break;
	}
	fclose(fp);
	return target_socket_id;
}
static int map_all_hugepages_original(
		char *huge_dir,
		char *vring_id,
		int alloc_length,
		int prefered_node,
		struct hugepage_file **hp_file_ptr,
		int *nr_hp_files)
{/*vring_id is a string which identifys which vector ring the hugefile belongs to*/
	struct hugepage_file hp_files[MAX_HUGEHUGE_PAGE_NR];
	int max_huge_nr=MAX_HUGEHUGE_PAGE_NR;
	int idx=0;
	int fd;
	int nr_orig_valid_pages=0;
	int mem_on_all_sockets=0;
	int mem_on_target_socket=0;
	int mem_on_remote_socket=0;
	int mem_on_remote_socket_needed;

	*hp_file_ptr=NULL;
	*nr_hp_files=0;
	for(idx=0;idx<max_huge_nr;idx++){
		memset(&hp_files[idx],0x0,sizeof(struct hugepage_file));
		sprintf(hp_files[idx].path,"%s/vecring-%s-%d",huge_dir?huge_dir:HUGEPAGE_PATH,vring_id,idx);
		fd=open(hp_files[idx].path,O_CREAT|O_RDWR,0755);
		if(fd<0)
			break;
		hp_files[idx].mapped_base=mmap(NULL,HUGEPAGE_2M,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_POPULATE,fd,0);
		if(hp_files[idx].mapped_base==MAP_FAILED){
			close(fd);
			unlink(hp_files[idx].path);
			break;
		}
		nr_orig_valid_pages++;
		close(fd);
		
		hp_files[idx].socket_id=find_numa_socket_for_hugepgae(hp_files[idx].path);
		if(hp_files[idx].socket_id==prefered_node)
			mem_on_target_socket+=HUGEPAGE_2M;
		mem_on_all_sockets+=HUGEPAGE_2M;
		
		if(mem_on_target_socket>=alloc_length)
			break;
	}
	if(mem_on_target_socket>=alloc_length){/*find all the mapped local pages,mark them as is_used=True*/
		for(idx=0;idx<nr_orig_valid_pages;idx++){
			if(hp_files[idx].socket_id==prefered_node)
				hp_files[idx].is_used=1;
		}
		
	}else if(mem_on_all_sockets>=alloc_length){
		mem_on_remote_socket_needed=alloc_length-mem_on_target_socket;
		for(idx=0;idx<nr_orig_valid_pages;idx++){
			if(hp_files[idx].socket_id==prefered_node)
				hp_files[idx].is_used=1;
			else{
				if(mem_on_remote_socket>=mem_on_remote_socket_needed)
					hp_files[idx].is_used=0;
				else{
					mem_on_remote_socket+=HUGEPAGE_2M;
					hp_files[idx].is_used=1;
				}
			}
		}
	}else {/*not enough memory at all,release all the hugepages by default*/
	}
	
	/*release unused hugepage*/
	for(idx=0;idx<nr_orig_valid_pages;idx++)
		if(hp_files[idx].is_used != 1){
			unlink(hp_files[idx].path);
			munmap(hp_files[idx].mapped_base,HUGEPAGE_2M);
			hp_files[idx].mapped_base=NULL;
	}
	if(mem_on_all_sockets>=alloc_length){
		int real_nr_of_files=0;
		int local_ptr=0;
		for(idx=0;idx<nr_orig_valid_pages;idx++)
			real_nr_of_files+=hp_files[idx].is_used==1;
		*hp_file_ptr=malloc(sizeof(struct hugepage_file)*real_nr_of_files);
		*nr_hp_files=real_nr_of_files;
		
		assert(*hp_file_ptr);
		memset(*hp_file_ptr,0x0,sizeof(struct hugepage_file)*real_nr_of_files);
		for(idx=0;idx<nr_orig_valid_pages;idx++){
			if(hp_files[idx].is_used==0)
				continue;
			(*hp_file_ptr)[local_ptr].socket_id=hp_files[idx].socket_id;
			(*hp_file_ptr)[local_ptr].mapped_base=hp_files[idx].mapped_base;
			memcpy((*hp_file_ptr)[local_ptr].path,hp_files[idx].path,sizeof(hp_files[idx].path));
			local_ptr++;
		}
	}
	
	return mem_on_all_sockets>=alloc_length;
}
static int remap_all_hugepages(struct hugepage_file *hp_file,int nr_files,uint64_t *base_ptr)
{
	uint64_t base;
	
	int idx=0;
	for(idx=0;idx<nr_files;idx++){/*release previous mapping first*/
		munmap(hp_file[idx].mapped_base,HUGEPAGE_2M);
	}
	
	*base_ptr=base=preserve_vm_area(nr_files,NULL);
	if(!base)
		return 0;
	for(idx=0;idx<nr_files;idx++){
		int fd=open(hp_file[idx].path,O_RDWR,0);
		if(fd<0)
			return 0;
		hp_file[idx].mapped_base=mmap((void*)(base+idx*HUGEPAGE_2M),
			HUGEPAGE_2M,
			PROT_READ|PROT_WRITE,
			MAP_SHARED|MAP_POPULATE,
			fd,
			0);
		if(hp_file[idx].mapped_base!=(void*)(base+idx*HUGEPAGE_2M)){
			close(fd);
			return 0;
		}
		close(fd);
	}
	return 1;
}
void free_hugepage_files(struct hugepage_file*hp_file,int nr_files)
{
	int idx;
	for (idx=0;idx<nr_files;idx++){
		if(hp_file[idx].mapped_base){
			munmap(hp_file[idx].mapped_base,HUGEPAGE_2M);
			hp_file[idx].mapped_base=NULL;
		}
		unlink(hp_file[idx].path);
	}
	free(hp_file);
}
int allocate_mmeory_from_hugepage_fs(struct hugepage_memory *hp_mem,char*huge_dir,char *vring_id,int length,int prefered_node)
{
	int rc;
	rc=map_all_hugepages_original(huge_dir,
		vring_id,
		length,
		prefered_node,
		&hp_mem->hp_files,
		&hp_mem->nr_files);
	if(!rc)
		return -1;
	hp_mem->prefered_socket_node=prefered_node;
	rc=remap_all_hugepages(hp_mem->hp_files,hp_mem->nr_files,&hp_mem->base);
	if(!rc){
		free_hugepage_files(hp_mem->hp_files,hp_mem->nr_files);
		return -1;
	}
	return 0;
}

int hugepage_util_module_test(void)
{
	#if 0
	struct hugepage_memory hp_mem;
	hugepage_util_init(NULL);
	int rc=allocate_mmeory_from_hugepage_fs(&hp_mem,NULL,"foo",1024*1024*2*25+1,0);
	printf("rc:%d %p\n",rc,(void*)hp_mem.base);
	
	struct hugepage_file *hp_file;
	int nr_files;
	int idx=0;
	uint64_t base;
	int rc=map_all_hugepages_original("foo1",1024*1024*2*35,0,&hp_file,&nr_files);
	printf("rc:%d  nr_files:%d\n",rc,nr_files);
	for(idx=0;idx<nr_files;idx++){
		printf("%s %p %d\n",hp_file[idx].path,hp_file[idx].mapped_base,hp_file[idx].socket_id);
	}
	remap_all_hugepages(hp_file,nr_files,&base);
	printf("remap:%p\n",base);
	free_hugepage_files(hp_file,nr_files);
	#endif
	return 0;
}
