#ifndef _LIBRTE_VECRING_H
#define _LIBRTE_VECRING_H


#include "vecring.h"
#include <rte_mbuf.h>


#define CACHELINE_SIZE 0x40


#ifndef likely
#define likely(x)  __builtin_expect((x),1)
#endif

#ifndef unlikely
#define unlikely(x)  __builtin_expect((x),0)
#endif

#define CEIL_BY_CACHELINE(a) (((a)&(~(uint64_t)0x3f))+(((a)&0x3f)?0x40:0))
#define CEIL_BY_HALF_CACHELINE(a) (((a)&(~(uint64_t)0x1f))+(((a)&0x3f)?0x20:0))

//#include <hugepage_util.h>
int rte_vecring_enqueues(struct vecring_header_t* vring,struct rte_mbuf **mbufs,int nr_bufs);
int rte_vecring_dequeues(struct vecring_header_t *vring,struct rte_mbuf **mbufs,int nr_max_bufs,struct rte_mempool *pool);

#endif
