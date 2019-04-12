#ifndef MEMCONTEXT_H
#define MEMCONTEXT_H

#include <stdbool.h>

typedef struct mcxt_memory_chunk	*mcxt_chunk_t;
typedef struct mcxt_context_data	*mcxt_context_t;

enum {
	MCXT_THREAD_CONFLICT = 0x01
} mcxt_errors;

struct mcxt_context_data
{
	uint32_t		lock;
	pthread_t		ptid;
	mcxt_context_t	parent;
	mcxt_context_t	firstchild;
	mcxt_context_t	prevchild;
	mcxt_context_t	nextchild;

	mcxt_chunk_t	lastchunk;
};

extern __thread mcxt_context_t current_mcxt;

mcxt_context_t mcxt_new(mcxt_context_t parent);
mcxt_context_t mcxt_switch_to(mcxt_context_t to);
int mcxt_reset(mcxt_context_t context, bool recursive);
int mcxt_delete(mcxt_context_t context);
void *mcxt_alloc_mem(mcxt_context_t context, size_t size, bool zero);
void mcxt_free_mem(mcxt_context_t context, void *p);
int mcxt_chunks_count(mcxt_context_t context);

static inline void *mcxt_alloc(size_t size)
{
	assert(current_mcxt != NULL);
	return mcxt_alloc_mem(current_mcxt, size, false);
}

static inline void *mcxt_alloc0(size_t size)
{
	assert(current_mcxt != NULL);
	return mcxt_alloc_mem(current_mcxt, size, true);
}

static inline void mcxt_free(void *p)
{
	mcxt_context_t context = *((mcxt_context_t *) ((char *) p - sizeof(void *)));
	mcxt_free_mem(context, p);
}

#endif
