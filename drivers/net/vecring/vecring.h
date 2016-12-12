#ifndef _LIBVECRING_VECRING_H
#define _LIBVECRING_VECRING_H
#include <inttypes.h>

#define DEFAULT_NR_BLOCK64 (1L<<15)
/*why this value:1703936=1024*(1600+64) ,then round up to 32768*/

#define IS_CACHELINE_ALIGNED(addr) (!(((uint64_t)(addr))&0x3f))

struct vecring_block64{
	union{
		struct{
			__attribute__((aligned(32))) void *dummy32_0 ;
			__attribute__((aligned(32))) void *dummy32_1 ;
		};
		struct{
			__attribute__((aligned(16))) void *dummy16_0 ;
			__attribute__((aligned(16))) void *dummy16_1 ;
			__attribute__((aligned(16))) void *dummy16_2 ;
			__attribute__((aligned(16))) void *dummy16_3 ;
		};
	};
};

struct vecring_header_t{
	uint64_t vring_ready;
	uint64_t front;
	uint64_t rear;
	uint32_t nr_block64;/*must be power of 2*/
	/*where nr_block64-1 is the mask*/
	__attribute__((aligned(64))) struct vecring_block64 data[0] ;
};

struct vecring_element_t{
	union{
		uint64_t data_start_index;
		struct {
			uint32_t data_start_index0;
			uint32_t data_start_index1;
		};
	};
	union{
		uint32_t data_u32;
		struct {
			uint16_t data_length;
			uint8_t is_fetched;
			uint8_t end_of_local_block;
		};
	};
	uint32_t reserved_32;
}__attribute__((packed));


#define needed_memory(nr_block64) ((nr_block64)+1)*sizeof(struct vecring_block64)
#define vecring_available(vr)  ((vr)->nr_block64-((vr)->rear-(vr)->front))
#define vecring_used(vr) ((vr)->rear-(vr)->front)
void vecring_init(struct vecring_header_t *vr,int nr_block);


#endif


