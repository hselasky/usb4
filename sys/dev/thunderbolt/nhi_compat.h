#ifndef _NHI_COMPAT_H
#define _NHI_COMPAT_H

#if (__FreeBSD_version < 1300069)

typedef struct {
	bus_dma_tag_t		parent;
	bus_size_t		alignment;
	bus_addr_t		boundary;
	bus_addr_t		lowaddr;
	bus_addr_t		highaddr;
	bus_size_t		maxsize;
	int			nsegments;
	bus_size_t		maxsegsize;
	int			flags;
	bus_dma_lock_t		*lockfunc;
	void			*lockfuncarg;
} bus_dma_template_t;

static __inline void
bus_dma_template_init(bus_dma_template_t *t, bus_dma_tag_t parent)
{
	t->parent = parent;
	t->alignment = 1;
	t->boundary = 0;
	t->lowaddr = t->highaddr = BUS_SPACE_MAXADDR;
	t->lockfunc = NULL;
	t->lockfuncarg = NULL;
	t->maxsize = t->maxsegsize = BUS_SPACE_MAXSIZE;
	t->nsegments = BUS_SPACE_UNRESTRICTED;
	t->flags = 0;
}

static __inline int
bus_dma_template_tag(bus_dma_template_t *t, bus_dma_tag_t *dmat)
{

	return (bus_dma_tag_create(t->parent, t->alignment, t->boundary,
	    t->lowaddr, t->highaddr, NULL, NULL, t->maxsize, t->nsegments,
	    t->maxsegsize, t->flags, t->lockfunc, t->lockfuncarg, dmat));
}

#endif
#endif /* _NHI_COMPAT_H */
