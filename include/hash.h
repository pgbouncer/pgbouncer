
uint32_t lookup3_hash(const void *data, size_t len);

uint32_t hash32(uint32_t v);

static inline uint32_t ptr_hash32(const void *ptr)
{
	return hash32((uint32_t)(long)ptr);
}

