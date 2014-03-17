#include <string.h>
#include <openssl/sha.h>

#include "miner.h"
#include "hefty1.h"
#include "sph_keccak.h"
#include "sph_blake.h"
#include "sph_groestl.h"

/* Combines top 64-bits from each hash into a single hash */
static void combine_hashes(uint32_t *out, uint32_t *hash1, uint32_t *hash2, uint32_t *hash3, uint32_t *hash4)
{
	uint32_t *hash[4] = { hash1, hash2, hash3, hash4 };

	/* Transpose first 64 bits of each hash into out */
	memset(out, 0, 32);
	int bits = 0;
	for (unsigned int i = 7; i >= 6; i--) {
		for (uint32_t mask = 0x80000000; mask; mask >>= 1) {
			for (unsigned int k = 0; k < 4; k++) {
				out[(255 - bits)/32] <<= 1;
				if ((hash[k][i] & mask) != 0)
					out[(255 - bits)/32] |= 1;
				bits++;
			}
		}
	}
}

void heavycoin_hash(const char* input, char* output, int len)
{
	unsigned char hash1[32];
	HEFTY1(input, len, hash1);

	/* HEFTY1 is new, so take an extra security measure to eliminate
	 * the possiblity of collisions:
	 *
	 *     Hash(x) = SHA256(x + HEFTY1(x))
	 *
	 * N.B. '+' is concatenation.
	 */
	unsigned char hash2[32];;
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, len);
	SHA256_Update(&ctx, hash1, sizeof(hash1));
	SHA256_Final(hash2, &ctx);

	/* Additional security: Do not rely on a single cryptographic hash
	 * function.  Instead, combine the outputs of 4 of the most secure
	 * cryptographic hash functions-- SHA256, KECCAK512, GROESTL512
	 * and BLAKE512.
	 */

	uint32_t hash3[16];
	sph_keccak512_context keccakCtx;
	sph_keccak512_init(&keccakCtx);
	sph_keccak512(&keccakCtx, input, len);
	sph_keccak512(&keccakCtx, hash1, sizeof(hash1));
	sph_keccak512_close(&keccakCtx, (void *)&hash3);

	uint32_t hash4[16];
	sph_groestl512_context groestlCtx;
	sph_groestl512_init(&groestlCtx);
	sph_groestl512(&groestlCtx, input, len);
	sph_groestl512(&groestlCtx, hash1, sizeof(hash1));
	sph_groestl512_close(&groestlCtx, (void *)&hash4);

	uint32_t hash5[16];
	sph_blake512_context blakeCtx;
	sph_blake512_init(&blakeCtx);
	sph_blake512(&blakeCtx, input, len);
	sph_blake512(&blakeCtx, (unsigned char *)&hash1, sizeof(hash1));
	sph_blake512_close(&blakeCtx, (void *)&hash5);

	uint32_t *final = (uint32_t *)output;
	combine_hashes(final, (uint32_t *)hash2, hash3, hash4, hash5);
}

int heavycoin_scanhash(unsigned char* output, const unsigned char* input, int len)
{
	DATA_ALIGN64(unsigned char hash1[32]);
	HEFTY1(input, len, hash1);

	DATA_ALIGN64(uint32_t hash5[16]);
	sph_blake512_context blakeCtx;
	sph_blake512_init(&blakeCtx);
	sph_blake512(&blakeCtx, input, len);
	sph_blake512(&blakeCtx, (unsigned char *)&hash1, sizeof(hash1));
	sph_blake512_close(&blakeCtx, (void *)&hash5);
	if ((*((unsigned char *)hash5 + 31) & 0xF0) != 0)
		return 0;

	DATA_ALIGN64(unsigned char hash2[32]);
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, input, len);
	SHA256_Update(&ctx, hash1, sizeof(hash1));
	SHA256_Final(hash2, &ctx);
	if ((*((unsigned char *)hash2 + 31) & 0xF0) != 0)
		return 0;

	DATA_ALIGN64(uint32_t hash3[16]);
	sph_keccak512_context keccakCtx;
	sph_keccak512_init(&keccakCtx);
	sph_keccak512(&keccakCtx, input, len);
	sph_keccak512(&keccakCtx, hash1, sizeof(hash1));
	sph_keccak512_close(&keccakCtx, (void *)&hash3);
	if ((*((unsigned char *)hash3 + 31) & 0xF0) != 0)
		return 0;

	DATA_ALIGN64(uint32_t hash4[16]);
	sph_groestl512_context groestlCtx;
	sph_groestl512_init(&groestlCtx);
	sph_groestl512(&groestlCtx, input, len);
	sph_groestl512(&groestlCtx, hash1, sizeof(hash1));
	sph_groestl512_close(&groestlCtx, (void *)&hash4);
	if ((*((unsigned char *)hash4 + 31) & 0xF0) != 0)
		return 0;

	uint32_t *final = (uint32_t *)output;
	combine_hashes(final, (uint32_t *)hash2, hash3, hash4, hash5);

	return 1;
}

