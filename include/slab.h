
typedef struct ObjectCache ObjectCache;

typedef void (*obj_init_fn)(void *obj);
typedef void (*obj_clean_fn)(void *obj);

ObjectCache *objcache_create(const char *name, unsigned obj_size, unsigned align,
			     obj_init_fn init_func, obj_clean_fn clean_func);
void objcache_destroy(ObjectCache *cache);

void * obj_alloc(ObjectCache *cache) _MALLOC _MUSTCHECK;
void obj_free(ObjectCache *cache, void *obj);

int objcache_total_count(ObjectCache *cache);
int objcache_free_count(ObjectCache *cache);
int objcache_active_count(ObjectCache *cache);


