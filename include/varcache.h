#include <usual/strpool.h>

#define MAX_NUM_CACHE_VARS 100

enum VarCacheIdx {
	VDateStyle = 0,
	VClientEncoding,
	VTimeZone,
	VStdStr,
	VAppName,
	VSearchPath,
	NumVars
};

typedef struct VarCache VarCache;

struct VarCache {
	struct PStr *var_list[MAX_NUM_CACHE_VARS];
};

void init_var_lookup(const char *cf_cache_vars);
bool varcache_set(VarCache *cache, const char *key, const char *value) /* _MUSTCHECK */;
bool varcache_apply(PgSocket *server, PgSocket *client, bool *changes_p) _MUSTCHECK;
void varcache_fill_unset(VarCache *src, PgSocket *dst);
void varcache_clean(VarCache *cache);
void varcache_add_params(PktBuf *pkt, VarCache *vars);
void varcache_deinit(void);
