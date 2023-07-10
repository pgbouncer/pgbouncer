#include <usual/strpool.h>

#undef HASH_FUNCTION
#define HASH_FUNCTION(keyptr,keylen,hashv) HASH_JEN_LOWERCASE(keyptr, keylen, hashv)

#define HASH_JEN_LOWERCASE(key,keylen,hashv) \
do {                                                                             \
  unsigned _hj_i,_hj_j,_hj_k;                                                    \
  unsigned const char *_hj_key=(unsigned const char*)(key);                      \
  hashv = 0xfeedbeefu;                                                           \
  _hj_i = _hj_j = 0x9e3779b9u;                                                   \
  _hj_k = (unsigned)(keylen);                                                    \
  while (_hj_k >= 12U) {                                                         \
    _hj_i +=    (tolower(_hj_key[0]) + ( (unsigned)tolower(_hj_key[1]) << 8 )                      \
	+ ( (unsigned)tolower(_hj_key[2]) << 16 )                                         \
	+ ( (unsigned)tolower(_hj_key[3]) << 24 ) );                                      \
    _hj_j +=    (tolower(_hj_key[4]) + ( (unsigned)tolower(_hj_key[5]) << 8 )                      \
	+ ( (unsigned)tolower(_hj_key[6]) << 16 )                                         \
	+ ( (unsigned)tolower(_hj_key[7]) << 24 ) );                                      \
    hashv += (tolower(_hj_key[8]) + ( (unsigned)tolower(_hj_key[9]) << 8 )                         \
	+ ( (unsigned)tolower(_hj_key[10]) << 16 )                                        \
	+ ( (unsigned)tolower(_hj_key[11]) << 24 ) );                                     \
     HASH_JEN_MIX(_hj_i, _hj_j, hashv);                                          \
     _hj_key += 12;                                                              \
     _hj_k -= 12U;                                                               \
  }                                                                              \
  hashv += (unsigned)(keylen);                                                   \
  switch ( _hj_k ) {                                                             \
    case 11: hashv += ( (unsigned)tolower(_hj_key[10]) << 24 ); /* FALLTHROUGH */         \
    case 10: hashv += ( (unsigned)tolower(_hj_key[9]) << 16 );  /* FALLTHROUGH */         \
    case 9:  hashv += ( (unsigned)tolower(_hj_key[8]) << 8 );   /* FALLTHROUGH */         \
    case 8:  _hj_j += ( (unsigned)tolower(_hj_key[7]) << 24 );  /* FALLTHROUGH */         \
    case 7:  _hj_j += ( (unsigned)tolower(_hj_key[6]) << 16 );  /* FALLTHROUGH */         \
    case 6:  _hj_j += ( (unsigned)tolower(_hj_key[5]) << 8 );   /* FALLTHROUGH */         \
    case 5:  _hj_j += tolower(_hj_key[4]);                      /* FALLTHROUGH */         \
    case 4:  _hj_i += ( (unsigned)tolower(_hj_key[3]) << 24 );  /* FALLTHROUGH */         \
    case 3:  _hj_i += ( (unsigned)tolower(_hj_key[2]) << 16 );  /* FALLTHROUGH */         \
    case 2:  _hj_i += ( (unsigned)tolower(_hj_key[1]) << 8 );   /* FALLTHROUGH */         \
    case 1:  _hj_i += tolower(_hj_key[0]);                      /* FALLTHROUGH */         \
    default: ;                                                                   \
  }                                                                              \
  HASH_JEN_MIX(_hj_i, _hj_j, hashv);                                             \
} while (0)

#undef HASH_KEYCMP
#define HASH_KEYCMP(a,b,len) (strcasecmp(a,b))

enum VarCacheIdx {
	VDateStyle = 0,
	VClientEncoding,
	VTimeZone,
	VStdStr,
	VAppName,
	NumVars
};

typedef struct VarCache VarCache;

struct VarCache {
	struct PStr **var_list;
};

void init_var_lookup(const char *cf_track_extra_parameters);
int get_num_var_cached(void);
bool varcache_set(VarCache *cache, const char *key, const char *value) /* _MUSTCHECK */;
bool varcache_apply(PgSocket *server, PgSocket *client, bool *changes_p) _MUSTCHECK;
void varcache_fill_unset(VarCache *src, PgSocket *dst);
void varcache_clean(VarCache *cache);
void varcache_add_params(PktBuf *pkt, VarCache *vars);
void varcache_deinit(void);
