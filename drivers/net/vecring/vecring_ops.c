#include "vecring_ops.h"
#include <x86intrin.h>
#include <assert.h>

#if defined(__AVX__) && defined(__AVX2__)
	#define COPY_CACHE_LINE_ALIGNED(dst,src) {\
		__m256i block32= \
		_mm256_stream_load_si256((__m256i*)((uint64_t)(src))); \
		_mm256_stream_si256((__m256i*)((uint64_t)(dst)),block32); \
		block32= \
		_mm256_stream_load_si256((__m256i*)(32+(uint64_t)(src))); \
		_mm256_stream_si256((__m256i*)(32+(uint64_t)(dst)),block32); \
	}
	
	#define COPY_CACHE_LINE_UNALIGNED(dst,src) {\
		__m256i block32= \
		_mm256_loadu_si256((__m256i*)((uint64_t)(src))); \
		_mm256_storeu_si256((__m256i*)((uint64_t)(dst)),block32); \
		block32= \
		_mm256_loadu_si256((__m256i*)(32+(uint64_t)(src))); \
		_mm256_storeu_si256((__m256i*)(32+(uint64_t)(dst)),block32); \
	}
#elif defined(__SSE4_1__) && defined(__SSE4_2__)
	#define COPY_CACHE_LINE_ALIGNED(dst,src) {\
		__m128i block16= \
		_mm_stream_load_si128((__m128i*)((uint64_t)(src))); \
		_mm_stream_si128((__m128i*)((uint64_t)(dst)),block16); \
		block16= \
		_mm_stream_load_si128((__m128i*)(16+(uint64_t)(src))); \
		_mm_stream_si128((__m128i*)(16+(uint64_t)(dst)),block16); \
		block16= \
		_mm_stream_load_si128((__m128i*)(32+(uint64_t)(src))); \
		_mm_stream_si128((__m128i*)(32+(uint64_t)(dst)),block16); \
		block16= \
		_mm_stream_load_si128((__m128i*)(48+(uint64_t)(src))); \
		_mm_stream_si128((__m128i*)(48+(uint64_t)(dst)),block16); \
	}
	
	#define COPY_CACHE_LINE_UNALIGNED(dst,src) {\
		__m128i block16= \
		_mm_loadu_si128((__m128i*)((uint64_t)(src))); \
		_mm_storeu_si128((__m128i*)((uint64_t)(dst)),block16); \
		block16= \
		_mm_loadu_si128((__m128i*)(16+(uint64_t)(src))); \
		_mm_storeu_si128((__m128i*)(16+(uint64_t)(dst)),block16); \
		block16= \
		_mm_loadu_si128((__m128i*)(32+(uint64_t)(src))); \
		_mm_storeu_si128((__m128i*)(32+(uint64_t)(dst)),block16); \
		block16= \
		_mm_loadu_si128((__m128i*)(48+(uint64_t)(src))); \
		_mm_storeu_si128((__m128i*)(48+(uint64_t)(dst)),block16); \
	}
	

#else
	#define COPY_CACHE_LINE_ALIGNED(dst,src) {\
		int idx=0; \
		for(idx=0;idx<8;idx++) \
			((uint64_t*)(dst))[idx]=((uint64_t*)(src))[idx]; \
	}
	#define COPY_CACHE_LINE_UNALIGNED(dst,src) COPY_CACHE_LINE_ALIGNED((dst),(src))
#endif

inline __attribute__((always_inline)) int vecring_enqueue_x4(struct vecring_header_t *vring,struct rte_mbuf **mbufs);
inline __attribute__((always_inline)) int vecring_enqueue_x2(struct vecring_header_t *vring,struct rte_mbuf **mbufs);
inline __attribute__((always_inline)) int vecring_enqueue_x1(struct vecring_header_t *vring,struct rte_mbuf **mbufs);

/*before calling vecring_enqueue ,we should warm the cache by prefetching rte_mbufs*/
inline __attribute__((always_inline)) int vecring_enqueue_x4(struct vecring_header_t *vring,struct rte_mbuf **mbufs)
{

	uint32_t vring_mask=vring->nr_block64-1;
	uint32_t target_index;
	uint64_t packet_start_addr;
	int loop;
	int idx=0;
	__m128i index0,index1,index2,index3;
	
	uint16_t start_block_len[4];/*real block length, may be unaligned*/
	
	uint64_t start_block_index[4];
	
	uint64_t index_block=vring->rear;
	index_block=index_block&vring_mask;
	
	for(idx=0;idx<4;idx++){
		start_block_len[idx]=mbufs[idx]->pkt_len;
		if(idx==0)
			start_block_index[idx]=vring->rear+1;
		else
			start_block_index[idx]=start_block_index[idx-1]+
			CEIL_BY_CACHELINE(start_block_len[idx-1])/CACHELINE_SIZE;
	}
	index0=_mm_set_epi32((uint32_t)(start_block_index[0]>>32),
		(uint32_t)start_block_index[0],
		start_block_len[0]<<16,
		0);
	index1=_mm_set_epi32((uint32_t)(start_block_index[1]>>32),
		(uint32_t)start_block_index[1],
		start_block_len[1]<<16,
		0);
	index2=_mm_set_epi32((uint32_t)(start_block_index[2]>>32),
		(uint32_t)start_block_index[2],
		start_block_len[2]<<16,
		0);
	index3=_mm_set_epi32((uint32_t)(start_block_index[3]>>32),
		(uint32_t)start_block_index[3],
		start_block_len[3]<<16/*|0<<8*/|1,
		0);

	/*1.copy into index cache line*/
	_mm_stream_si128((__m128i*)&vring->data[index_block].dummy16_0,index0);
	_mm_stream_si128((__m128i*)&vring->data[index_block].dummy16_1,index1);
	_mm_stream_si128((__m128i*)&vring->data[index_block].dummy16_2,index2);
	_mm_stream_si128((__m128i*)&vring->data[index_block].dummy16_3,index3);
	/*2.copy packets data into memory buffer*/
	/*transfer packet 0*/
	loop=CEIL_BY_HALF_CACHELINE(start_block_len[0])/32;
	packet_start_addr=rte_pktmbuf_mtod(mbufs[0],uint64_t);
	if(unlikely(!IS_CACHELINE_ALIGNED(packet_start_addr)))
		for(idx=0,
				target_index=start_block_index[0]&vring_mask;
			idx<loop;
			idx+=2,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
			COPY_CACHE_LINE_UNALIGNED(&vring->data[target_index],packet_start_addr);
		}
	else
		for(idx=0,
				target_index=start_block_index[0]&vring_mask;
			idx<loop;
			idx+=2,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
			COPY_CACHE_LINE_ALIGNED(&vring->data[target_index],packet_start_addr);
		}
	/*transfer packet 1*/
	loop=CEIL_BY_HALF_CACHELINE(start_block_len[1])/32;
	packet_start_addr=rte_pktmbuf_mtod(mbufs[1],uint64_t);
	if(unlikely(!IS_CACHELINE_ALIGNED(packet_start_addr)))
		for(idx=0,
				target_index=start_block_index[1]&vring_mask;
			idx<loop;
			idx+=2,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
			COPY_CACHE_LINE_UNALIGNED(&vring->data[target_index],packet_start_addr);
		}
	else
		for(idx=0,
				target_index=start_block_index[1]&vring_mask;
			idx<loop;
			idx+=2,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
			COPY_CACHE_LINE_ALIGNED(&vring->data[target_index],packet_start_addr);
		}
	/*transfer packet 2*/
	loop=CEIL_BY_HALF_CACHELINE(start_block_len[2])/32;
	packet_start_addr=rte_pktmbuf_mtod(mbufs[2],uint64_t);
	if(unlikely(!IS_CACHELINE_ALIGNED(packet_start_addr)))
		for(idx=0,
				target_index=start_block_index[2]&vring_mask;
			idx<loop;
			idx+=2,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
			COPY_CACHE_LINE_UNALIGNED(&vring->data[target_index],packet_start_addr);
		}
	else
		for(idx=0,
				target_index=start_block_index[2]&vring_mask;
			idx<loop;
			idx+=2,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
			COPY_CACHE_LINE_ALIGNED(&vring->data[target_index],packet_start_addr);
		}
	/*transfer packet 3*/
	loop=CEIL_BY_HALF_CACHELINE(start_block_len[3])/32;
	packet_start_addr=rte_pktmbuf_mtod(mbufs[3],uint64_t);
	if(unlikely(!IS_CACHELINE_ALIGNED(packet_start_addr)))
		for(idx=0,
				target_index=start_block_index[3]&vring_mask;
			idx<loop;
			idx+=2,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
			COPY_CACHE_LINE_UNALIGNED(&vring->data[target_index],packet_start_addr);
		}
	else
		for(idx=0,
				target_index=start_block_index[3]&vring_mask;
			idx<loop;
			idx+=2,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
			COPY_CACHE_LINE_ALIGNED(&vring->data[target_index],packet_start_addr);
		}
	/*3.update rear pointer of vecring*/
	_mm_sfence();
	vring->rear=start_block_index[3]+CEIL_BY_CACHELINE(start_block_len[3])/CACHELINE_SIZE;
	return 0;
}
inline __attribute__((always_inline)) int vecring_enqueue_x2(struct vecring_header_t *vring,struct rte_mbuf **mbufs)
{
	uint32_t vring_mask=vring->nr_block64-1;
	uint32_t target_index;
	uint64_t packet_start_addr;
	int loop;
	int idx=0;
	__m128i index0,index1;
	uint16_t start_block_len[2];
	uint64_t start_block_index[2];
	uint64_t index_block=vring->rear;
	index_block=index_block&vring_mask;

	start_block_len[0]=mbufs[0]->pkt_len;
	start_block_len[1]=mbufs[1]->pkt_len;
	start_block_index[0]=vring->rear+1;
	start_block_index[1]=start_block_index[0]+
		CEIL_BY_CACHELINE(start_block_len[0])/CACHELINE_SIZE;
	
	index0=_mm_set_epi32((uint32_t)(start_block_index[0]>>32),
		(uint32_t)start_block_index[0],
		start_block_len[0]<<16,
		0);
	index1=_mm_set_epi32((uint32_t)(start_block_index[1]>>32),
		(uint32_t)start_block_index[1],
		start_block_len[1]<<16|1,
		0);
	_mm_stream_si128((__m128i*)&vring->data[index_block].dummy16_0,index0);
	_mm_stream_si128((__m128i*)&vring->data[index_block].dummy16_1,index1);

	loop=CEIL_BY_HALF_CACHELINE(start_block_len[0])/32;
	packet_start_addr=rte_pktmbuf_mtod(mbufs[0],uint64_t);
	if(unlikely(!IS_CACHELINE_ALIGNED(packet_start_addr)))
		for(idx=0,
				target_index=start_block_index[0]&vring_mask;
			idx<loop;
			idx+=2,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
			COPY_CACHE_LINE_UNALIGNED(&vring->data[target_index],packet_start_addr);
		}
	else
		for(idx=0,
				target_index=start_block_index[0]&vring_mask;
			idx<loop;
			idx+=2,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
			COPY_CACHE_LINE_ALIGNED(&vring->data[target_index],packet_start_addr);
		}
	/*transfer packet 1*/
	loop=CEIL_BY_HALF_CACHELINE(start_block_len[1])/32;
	packet_start_addr=rte_pktmbuf_mtod(mbufs[1],uint64_t);
	if(unlikely(!IS_CACHELINE_ALIGNED(packet_start_addr)))
		for(idx=0,
				target_index=start_block_index[1]&vring_mask;
			idx<loop;
			idx+=2,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
			COPY_CACHE_LINE_UNALIGNED(&vring->data[target_index],packet_start_addr);
		}
	else
		for(idx=0,
				target_index=start_block_index[1]&vring_mask;
			idx<loop;
			idx+=2,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
			COPY_CACHE_LINE_ALIGNED(&vring->data[target_index],packet_start_addr);
		}
	_mm_sfence();
	vring->rear=start_block_index[1]+CEIL_BY_CACHELINE(start_block_len[1])/CACHELINE_SIZE;
	return 0;
}

inline __attribute__((always_inline)) int vecring_enqueue_x1(struct vecring_header_t *vring,struct rte_mbuf **mbufs)
{
	uint32_t vring_mask=vring->nr_block64-1;
	uint32_t target_index;
	uint64_t packet_start_addr;
	int loop;
	int idx=0;
	__m128i index0;
	uint16_t start_block_len[1];
	uint64_t start_block_index[1];
	uint64_t index_block=vring->rear;
	index_block=index_block&vring_mask;

	start_block_len[0]=mbufs[0]->pkt_len;
	start_block_index[0]=vring->rear+1;
	index0=_mm_set_epi32((uint32_t)(start_block_index[0]>>32),
		(uint32_t)start_block_index[0],
		start_block_len[0]<<16|1,
		0);
	
	_mm_stream_si128((__m128i*)&vring->data[index_block].dummy16_0,index0);

	loop=CEIL_BY_HALF_CACHELINE(start_block_len[0])/32;
	packet_start_addr=rte_pktmbuf_mtod(mbufs[0],uint64_t);
	if(unlikely(!IS_CACHELINE_ALIGNED(packet_start_addr)))
		for(idx=0,
				target_index=start_block_index[0]&vring_mask;
			idx<loop;
			idx+=2,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
			COPY_CACHE_LINE_UNALIGNED(&vring->data[target_index],packet_start_addr);
		}
	else
		for(idx=0,
				target_index=start_block_index[0]&vring_mask;
			idx<loop;
			idx+=2,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
			COPY_CACHE_LINE_ALIGNED(&vring->data[target_index],packet_start_addr);
		}
	/*transfer packet 1*/
	_mm_sfence();
	vring->rear=start_block_index[0]+CEIL_BY_CACHELINE(start_block_len[0])/CACHELINE_SIZE;
	
	return 0;
}




/*the max frame size is 1600 bytes,i.e baby giant frame*/
#define ESTIMATED_ROOM_X4 101 /*(25*4+1)*/
#define ESTIMATED_ROOM_X2 51 /*(25*2+1)*/
#define ESTIMATED_ROOM_X1 26 /*(25*1+1)*/

int rte_vecring_enqueues(struct vecring_header_t* vring,struct rte_mbuf **mbufs,int nr_bufs)
{
	int nr_enqueued=0;
	int nr_left=nr_bufs;
	uint32_t nr_avail;
	if(!vring->vring_ready)
		return 0;
	while(nr_left>0){
		nr_avail=vecring_available(vring);
		
		if(nr_left>=4)
			goto xmit_x4;
		else if(nr_left>=2)
			goto xmit_x2;
		else if(nr_left==1)
			goto xmit_x1;
		break;
		
		xmit_x4:
			if(nr_avail<ESTIMATED_ROOM_X4)
				goto xmit_x2;
			vecring_enqueue_x4(vring,mbufs+nr_enqueued);
			nr_enqueued+=4;
			nr_left-=4;
			continue;
		xmit_x2:
			if(nr_avail<ESTIMATED_ROOM_X2)
				goto xmit_x1;
			vecring_enqueue_x2(vring,mbufs+nr_enqueued);
			nr_enqueued+=2;
			nr_left-=2;
			continue;
		xmit_x1:
			if(nr_avail<ESTIMATED_ROOM_X1)
				goto xmit_none;
			vecring_enqueue_x1(vring,mbufs+nr_enqueued);
			nr_enqueued+=1;
			nr_left-=1;
			continue;
		xmit_none:
			break;
	}
	return nr_enqueued;
}
inline __attribute__((always_inline)) int vecring_fetch_block_once(struct vecring_header_t *vring,struct rte_mbuf **mbufs,struct rte_mempool *pool);
/*the mbufs must can contain at least 4 mbufs when it's  called*/
inline __attribute__((always_inline)) int vecring_fetch_block_once(struct vecring_header_t *vring,struct rte_mbuf **mbufs,struct rte_mempool *pool)
{
	uint32_t nr_block_pending=vecring_used(vring);
	uint32_t vring_mask=vring->nr_block64-1;
	uint32_t index_block=vring->front&vring_mask;
	
	uint8_t is_fetched;
	uint8_t is_end_of_block=0;
	uint16_t pkt_len=0;
	uint64_t pkt_start_index=0;
	uint32_t target_index;
	uint64_t packet_start_addr;
	__m128i index0,index1,index2,index3;
	int mbuf_ptr=0;
	int idx;
	int loop;
	struct rte_mbuf * mbuf;
	
	if(nr_block_pending==0 || !vring->vring_ready)/*no blocks left in the queue at all*/
		return 0;
	
	index0=_mm_stream_load_si128((__m128i*)&vring->data[index_block].dummy16_0);
	index1=_mm_stream_load_si128((__m128i*)&vring->data[index_block].dummy16_1);
	index2=_mm_stream_load_si128((__m128i*)&vring->data[index_block].dummy16_2);
	index3=_mm_stream_load_si128((__m128i*)&vring->data[index_block].dummy16_3);


	/*.1 fetch metadata*/
	is_fetched=_mm_extract_epi8(index0,5);
	is_end_of_block=_mm_extract_epi8(index0,4);
	//printf("0.fetch:%d:%d\n",is_fetched,is_end_of_block);
	if(is_fetched==1)
		goto fetch1;
	pkt_len=_mm_extract_epi16(index0,3);
	pkt_start_index=(((uint64_t)_mm_extract_epi32(index0,3))<<32)
			|(uint64_t)_mm_extract_epi32(index0,2);
	//printf("0.len:%d,index:%"PRIu64"\n",pkt_len,pkt_start_index);
	/*.2 prepare rte_mbuf*/
	mbuf=rte_pktmbuf_alloc(pool);
	if(unlikely(!mbuf))
		goto mbuf_exception;
	/*to this,the all two cache lines are in the cache,so there is no reason
		susing stream instruction set*/
	/*3.copy data into mbuf*/
	mbuf->pkt_len=pkt_len;
	mbuf->data_len=pkt_len;
	loop=CEIL_BY_CACHELINE(pkt_len)/CACHELINE_SIZE;
	packet_start_addr=rte_pktmbuf_mtod(mbuf,uint64_t);
	if(unlikely(!IS_CACHELINE_ALIGNED(packet_start_addr)))
		for(idx=0,
				target_index=pkt_start_index&vring_mask;
			idx<loop;
			idx++,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
				COPY_CACHE_LINE_UNALIGNED(packet_start_addr,&vring->data[target_index]);
		}
	else 
		for(idx=0,
				target_index=pkt_start_index&vring_mask;
			idx<loop;
			idx++,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
				COPY_CACHE_LINE_ALIGNED(packet_start_addr,&vring->data[target_index]);
		}
	mbufs[mbuf_ptr++]=mbuf;
	index0=_mm_insert_epi8(index0,1,5);/*mark it as fetched*/
	if(is_end_of_block)
		goto finish;
	
	fetch1:
	is_fetched=_mm_extract_epi8(index1,5);
	is_end_of_block=_mm_extract_epi8(index1,4);
	//printf("1.fetch:%d:%d\n",is_fetched,is_end_of_block);
	if(is_fetched==1)
		goto fetch2;
	pkt_len=_mm_extract_epi16(index1,3);
	pkt_start_index=(((uint64_t)_mm_extract_epi32(index1,3))<<32)
			|(uint64_t)_mm_extract_epi32(index1,2);
	//printf("1.len:%d,index:%"PRIu64"\n",pkt_len,pkt_start_index);
	mbuf=rte_pktmbuf_alloc(pool);
	if(unlikely(!mbuf))
		goto mbuf_exception;
	mbuf->pkt_len=pkt_len;
	mbuf->data_len=pkt_len;
	loop=CEIL_BY_CACHELINE(pkt_len)/CACHELINE_SIZE;
	packet_start_addr=rte_pktmbuf_mtod(mbuf,uint64_t);
	if(unlikely(!IS_CACHELINE_ALIGNED(packet_start_addr)))
		for(idx=0,
				target_index=pkt_start_index&vring_mask;
			idx<loop;
			idx++,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
				COPY_CACHE_LINE_UNALIGNED(packet_start_addr,&vring->data[target_index]);
		}
	else
		for(idx=0,
				target_index=pkt_start_index&vring_mask;
			idx<loop;
			idx++,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
				COPY_CACHE_LINE_ALIGNED(packet_start_addr,&vring->data[target_index]);
		}
	mbufs[mbuf_ptr++]=mbuf;
	index1=_mm_insert_epi8(index1,1,5);
	if(is_end_of_block)
		goto finish;
	fetch2:
	is_fetched=_mm_extract_epi8(index2,5);
	is_end_of_block=_mm_extract_epi8(index2,4);
	//printf("2.fetch:%d:%d\n",is_fetched,is_end_of_block);
	if(is_fetched==1)
		goto fetch3;
	pkt_len=_mm_extract_epi16(index2,3);
	pkt_start_index=(((uint64_t)_mm_extract_epi32(index2,3))<<32)
			|(uint64_t)_mm_extract_epi32(index2,2);
	//printf("2.len:%d,index:%"PRIu64"\n",pkt_len,pkt_start_index);
	mbuf=rte_pktmbuf_alloc(pool);
	if(unlikely(!mbuf))
		goto mbuf_exception;
	mbuf->pkt_len=pkt_len;
	mbuf->data_len=pkt_len;
	loop=CEIL_BY_CACHELINE(pkt_len)/CACHELINE_SIZE;
	packet_start_addr=rte_pktmbuf_mtod(mbuf,uint64_t);
	if(unlikely(!IS_CACHELINE_ALIGNED(packet_start_addr)))
		for(idx=0,
				target_index=pkt_start_index&vring_mask;
			idx<loop;
			idx++,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
				COPY_CACHE_LINE_UNALIGNED(packet_start_addr,&vring->data[target_index]);
		}
	else 
		for(idx=0,
				target_index=pkt_start_index&vring_mask;
			idx<loop;
			idx++,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
				COPY_CACHE_LINE_ALIGNED(packet_start_addr,&vring->data[target_index]);
		}
	mbufs[mbuf_ptr++]=mbuf;
	index2=_mm_insert_epi8(index2,1,5);
	if(is_end_of_block)
		goto finish;
	fetch3:
	is_fetched=_mm_extract_epi8(index3,5);
	is_end_of_block=_mm_extract_epi8(index3,4);
	//printf("3.fetch:%d:%d\n",is_fetched,is_end_of_block);
	if(is_fetched==1)
		goto finish;/*this should never happen*/
	pkt_len=_mm_extract_epi16(index3,3);
	pkt_start_index=(((uint64_t)_mm_extract_epi32(index3,3))<<32)
			|(uint64_t)_mm_extract_epi32(index3,2);
	//printf("3.len:%d,index:%"PRIu64"\n",pkt_len,pkt_start_index);
	mbuf=rte_pktmbuf_alloc(pool);
	if(unlikely(!mbuf))
		goto mbuf_exception;
	mbuf->pkt_len=pkt_len;
	mbuf->data_len=pkt_len;
	loop=CEIL_BY_CACHELINE(pkt_len)/CACHELINE_SIZE;
	packet_start_addr=rte_pktmbuf_mtod(mbuf,uint64_t);
	if(unlikely(!IS_CACHELINE_ALIGNED(packet_start_addr)))
		for(idx=0,
				target_index=pkt_start_index&vring_mask;
			idx<loop;
			idx++,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
				COPY_CACHE_LINE_UNALIGNED(packet_start_addr,&vring->data[target_index]);
		}
	else
		for(idx=0,
				target_index=pkt_start_index&vring_mask;
			idx<loop;
			idx++,
				target_index=(target_index+1)&vring_mask,
				packet_start_addr=packet_start_addr+CACHELINE_SIZE){
				COPY_CACHE_LINE_ALIGNED(packet_start_addr,&vring->data[target_index]);
		}
	mbufs[mbuf_ptr++]=mbuf;
	index3=_mm_insert_epi8(index3,1,5);
	/*mandatorily go to finish label*/
	goto finish;
	
	mbuf_exception:
		/*write index0/1/2/3 backto main memory*/
		_mm_stream_si128((__m128i*)&vring->data[index_block].dummy16_0,index0);
		_mm_stream_si128((__m128i*)&vring->data[index_block].dummy16_1,index1);
		_mm_stream_si128((__m128i*)&vring->data[index_block].dummy16_2,index2);
		_mm_stream_si128((__m128i*)&vring->data[index_block].dummy16_3,index3);
		return mbuf_ptr;

	finish:
		/*update vring->front pointer,by last pkt_start_index and pkt_len*/
		_mm_lfence();
		vring->front=pkt_start_index+CEIL_BY_CACHELINE(pkt_len)/CACHELINE_SIZE;
		return mbuf_ptr;
}
int rte_vecring_dequeues(struct vecring_header_t *vring,struct rte_mbuf **mbufs,int nr_max_bufs,struct rte_mempool *pool)
{
	int nr_dequeued=0;
	int nr_left=nr_max_bufs;
	int nr_fetched;
	while(nr_left>=4){
		nr_fetched=vecring_fetch_block_once(vring,&mbufs[nr_dequeued],pool);
		if(!nr_fetched)
			break;
		nr_dequeued+=nr_fetched;
		nr_left-=nr_fetched;
	}
	return nr_dequeued;
}
