#ifndef _LIBVECRING_HUGEPAGE_UTIL_H
#define _LIBVECRING_HUGEPAGE_UTIL_H
/*only support 2M hugepage size*/
#include <inttypes.h>
#ifndef HUGEPAGE_2M
#define HUGEPAGE_2M (1<<21)
#endif

#ifndef HUGEPAGE_2M_MASK
#define HUGEPAGE_2M_MASK ((1<<21)-1)
#endif

struct hugepage_file{
	int is_used;
	char path[64];
	void * mapped_base;
	int socket_id;
};
struct hugepage_memory{
	struct hugepage_file * hp_files;
	int nr_files;
	uint64_t base;
	int prefered_socket_node;
};
uint64_t preserve_vm_area(int nr_pages,void **raw_addr);
void hugepage_util_init(char* huge_dir);
void free_hugepage_files(struct hugepage_file*hp_file,
	int nr_files);
int allocate_mmeory_from_hugepage_fs(struct hugepage_memory *hp_mem,
	char*huge_dir,
	char *vring_id,
	int length,
	int prefered_node);
int hugepage_util_module_test(void);
#endif