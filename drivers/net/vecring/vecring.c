#include "vecring.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <x86intrin.h>

void vecring_init(struct vecring_header_t *vr,int nr_block)
{
	
	memset(vr,0x0,sizeof(struct vecring_header_t));
	{/*delay for a little while to reduce risk that other side of vring  crashes*/
		int idx=0;
		vr->vring_ready=0;
		for(idx=0;idx<1024*1024*16;idx++)
			_mm_mfence();
	}
	vr->front=0;
	vr->rear=0;
	vr->nr_block64=nr_block;
	vr->vring_ready=1;
	_mm_mfence();
}
__attribute__((constructor)) void  vecring_arch_detect(void);
__attribute__((constructor)) void  vecring_arch_detect(void) 
{
	#define _(cpuflag) {\
		fprintf(stderr,"[x]cpu does not support %s instruction set\n",(cpuflag)); \
	}

	#ifndef __SSE__
		_("sse");
	#endif

	
	#ifndef __SSE2__
		_("sse2");
	#endif

	
	#ifndef __SSE3__
		_("sse3");
	#endif

	#ifndef __SSE4_1__
		_("sse4.1");
	#endif

	#ifndef __SSE4_1__
		_("sse4.2");
	#endif

	#ifndef __AVX__
		_("avx");
	#endif

	#ifndef __AVX2__
		_("avx2");
	#endif
	#undef _

	assert(sizeof(struct vecring_block64)==64);
	assert(sizeof(struct vecring_header_t)==64);
}


