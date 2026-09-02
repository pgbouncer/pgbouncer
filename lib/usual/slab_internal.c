#include <usual/slab_internal.h>
#include <usual/logging.h>
#include <string.h>

/* fill struct contents */
void init_slab(struct Slab *slab, const char *name, unsigned obj_size,
	       unsigned align, slab_init_fn init_func,
	       CxMem *cx)
{
	unsigned slen = strlen(name);

	list_init(&slab->head);
	statlist_init(&slab->freelist, name);
	statlist_init(&slab->fraglist, name);
	slab->total_count = 0;
	slab->init_func = init_func;
	slab->cx = cx;

	if (slen >= sizeof(slab->name))
		slen = sizeof(slab->name) - 1;
	memcpy(slab->name, name, slen);
	slab->name[slen] = 0;

	/* don't allow too small align, as we want to put pointers into area */
	if (align < sizeof(long))
		align = 0;

	/* actual area for one object */
	if (align == 0)
		slab->final_size = ALIGN(obj_size);
	else
		slab->final_size = CUSTOM_ALIGN(obj_size, align);

	/* allow small structs */
	if (slab->final_size < sizeof(struct List))
		slab->final_size = sizeof(struct List);
}

/* free fragments and the slab itself */
void slab_destroy_internal(struct Slab *slab)
{
	struct List *item, *tmp;
	struct SlabFrag *frag;

	statlist_for_each_safe(item, &slab->fraglist, tmp) {
		frag = container_of(item, struct SlabFrag, head);
		cx_free(slab->cx, frag);
	}
	cx_free(slab->cx, slab);
}
