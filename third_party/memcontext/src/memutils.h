#ifndef MEMUTILS_H
#define MEMUTILS_H

#define MAXIMUM_ALIGNOF 8
#define TYPEALIGN(ALIGNVAL,LEN)  \
	(((uintptr_t) (LEN) + ((ALIGNVAL) - 1)) & ~((uintptr_t) ((ALIGNVAL) - 1)))

#define MAXALIGN(LEN)	TYPEALIGN(MAXIMUM_ALIGNOF, (LEN))

typedef enum {
	mct_alloc		= 0x01,
	mct_context		= 0x02
} mcxt_chunk_type;

struct mcxt_memory_chunk
{
	mcxt_chunk_type chunk_type;
	mcxt_chunk_t		prev;
	mcxt_chunk_t		next;
	mcxt_context_t	context;
};

#define MEMORY_CHUNK_SIZE (MAXALIGN(sizeof(struct mcxt_memory_chunk)))
#define GetMemoryChunk(p) ((mcxt_chunk_t)((char *)(p) - MEMORY_CHUNK_SIZE))
#define ChunkDataOffset(c) ((void *)((char *)(c) + MEMORY_CHUNK_SIZE))

#endif
