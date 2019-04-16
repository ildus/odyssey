#ifndef MEMCONTEXT_H
#define MEMCONTEXT_H

#include <stdbool.h>

typedef struct mcxt_memory_chunk	*mcxt_chunk_t;
typedef struct mcxt_context_data	*mcxt_context_t;

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
void mcxt_reset(mcxt_context_t context, bool recursive);
void mcxt_delete(mcxt_context_t context);
void *mcxt_alloc_mem(mcxt_context_t context, size_t size, bool zero);
void *mcxt_realloc(void *ptr, size_t size);
void mcxt_free_mem(mcxt_context_t context, void *p);
int mcxt_chunks_count(mcxt_context_t context);
char *mcxt_strdup_in(mcxt_context_t context, const char *string);

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

static inline char *mcxt_strdup(const char *string)
{
	assert(current_mcxt != NULL);
	return mcxt_strdup_in(current_mcxt, string);
}

#ifdef MCXT_PROTECTION_CHECK
void mcxt_incr_refcount(void *ptr);
void mcxt_decr_refcount(void *ptr);
void mcxt_check(void *ptr, void *context, int refcount);
#else
#define mcxt_incr_refcount(ptr)
#define mcxt_decr_refcount(ptr)
#endif

#endif
