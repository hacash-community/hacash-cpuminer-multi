// x16rs_hash ported by barrystyle 22072024

#include "miner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sha3/sph_blake.h>
#include <sha3/sph_bmw.h>
#include <sha3/sph_groestl.h>
#include <sha3/sph_jh.h>
#include <sha3/sph_keccak.h>
#include <sha3/sph_skein.h>
#include <sha3/sph_luffa.h>
#include <sha3/sph_cubehash.h>
#include <sha3/sph_shavite.h>
#include <sha3/sph_simd.h>
#include <sha3/sph_echo.h>
#include <sha3/sph_hamsi.h>
#include <sha3/sph_fugue.h>
#include <sha3/sph_shabal.h>
#include <sha3/sph_whirlpool.h>
#include <sha3/sph_sha2.h>
#include <sha3/sph_sha3.h>

enum Algo {
    BLAKE = 0,
    BMW,
    GROESTL,
    JH,
    KECCAK,
    SKEIN,
    LUFFA,
    CUBEHASH,
    SHAVITE,
    SIMD,
    ECHO,
    HAMSI,
    FUGUE,
    SHABAL,
    WHIRLPOOL,
    SHA512,
    HASH_FUNC_COUNT
};

// input length must more than 32
static const size_t x16rs_hash_insize = 32;
void x16rs_hash_inner(const int loopnum, const char* input_hash, char* output_hash)
{
    uint32_t inputoutput[64/4];

    uint32_t *input_hash_ptr32 = (uint32_t *) input_hash;
    inputoutput[0] = input_hash_ptr32[0];
    inputoutput[1] = input_hash_ptr32[1];
    inputoutput[2] = input_hash_ptr32[2];
    inputoutput[3] = input_hash_ptr32[3];
    inputoutput[4] = input_hash_ptr32[4];
    inputoutput[5] = input_hash_ptr32[5];
    inputoutput[6] = input_hash_ptr32[6];
    inputoutput[7] = input_hash_ptr32[7];

    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_skein512_context     ctx_skein;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_luffa512_context     ctx_luffa;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;
    sph_hamsi512_context     ctx_hamsi;
    sph_fugue512_context     ctx_fugue;
    sph_shabal512_context    ctx_shabal;
    sph_whirlpool_context    ctx_whirlpool;
    sph_sha512_context       ctx_sha512;

    int n;
    for(n = 0; n < loopnum; n++){

        uint8_t algo = inputoutput[7] % 16;
        switch (algo)
        {
        case BLAKE:
            sph_blake512_init(&ctx_blake);
            sph_blake512(&ctx_blake, inputoutput, x16rs_hash_insize);
            sph_blake512_close(&ctx_blake, inputoutput);
        break;
        case BMW:
            sph_bmw512_init(&ctx_bmw);
            sph_bmw512(&ctx_bmw, inputoutput, x16rs_hash_insize);
            sph_bmw512_close(&ctx_bmw, inputoutput);
        break;
        case GROESTL:
            sph_groestl512_init(&ctx_groestl);
            sph_groestl512(&ctx_groestl, inputoutput, x16rs_hash_insize);
            sph_groestl512_close(&ctx_groestl, inputoutput);
        break;
        case SKEIN:
            sph_skein512_init(&ctx_skein);
            sph_skein512(&ctx_skein, inputoutput, x16rs_hash_insize);
            sph_skein512_close(&ctx_skein, inputoutput);
        break;
        case JH:
            sph_jh512_init(&ctx_jh);
            sph_jh512(&ctx_jh, inputoutput, x16rs_hash_insize);
            sph_jh512_close(&ctx_jh, inputoutput);
        break;
        case KECCAK:
            sph_keccak512_init(&ctx_keccak);
            sph_keccak512(&ctx_keccak, inputoutput, x16rs_hash_insize);
            sph_keccak512_close(&ctx_keccak, inputoutput);
        break;
        case LUFFA:
            sph_luffa512_init(&ctx_luffa);
            sph_luffa512(&ctx_luffa, inputoutput, x16rs_hash_insize);
            sph_luffa512_close(&ctx_luffa, inputoutput);
        break;
        case CUBEHASH:
            sph_cubehash512_init(&ctx_cubehash);
            sph_cubehash512(&ctx_cubehash, inputoutput, x16rs_hash_insize);
            sph_cubehash512_close(&ctx_cubehash, inputoutput);
        break;
        case SHAVITE:
            sph_shavite512_init(&ctx_shavite);
            sph_shavite512(&ctx_shavite, inputoutput, x16rs_hash_insize);
            sph_shavite512_close(&ctx_shavite, inputoutput);
        break;
        case SIMD:
            sph_simd512_init(&ctx_simd);
            sph_simd512(&ctx_simd, inputoutput, x16rs_hash_insize);
            sph_simd512_close(&ctx_simd, inputoutput);
        break;
        case ECHO:
            sph_echo512_init(&ctx_echo);
            sph_echo512(&ctx_echo, inputoutput, x16rs_hash_insize);
            sph_echo512_close(&ctx_echo, inputoutput);
        break;
        case HAMSI:
            sph_hamsi512_init(&ctx_hamsi);
            sph_hamsi512(&ctx_hamsi, inputoutput, x16rs_hash_insize);
            sph_hamsi512_close(&ctx_hamsi, inputoutput);
        break;
        case FUGUE:
            sph_fugue512_init(&ctx_fugue);
            sph_fugue512(&ctx_fugue, inputoutput, x16rs_hash_insize);
            sph_fugue512_close(&ctx_fugue, inputoutput);
        break;
        case SHABAL:
            sph_shabal512_init(&ctx_shabal);
            sph_shabal512(&ctx_shabal, inputoutput, x16rs_hash_insize);
            sph_shabal512_close(&ctx_shabal, inputoutput);
        break;
        case WHIRLPOOL:
            sph_whirlpool_init(&ctx_whirlpool);
            sph_whirlpool(&ctx_whirlpool, inputoutput, x16rs_hash_insize);
            sph_whirlpool_close(&ctx_whirlpool, inputoutput);
        break;
        case SHA512:
            sph_sha512_init(&ctx_sha512);
            sph_sha512(&ctx_sha512, inputoutput, x16rs_hash_insize);
            sph_sha512_close(&ctx_sha512, inputoutput);
        break;
        }

    }

    uint32_t *output_hash_ptr32 = (uint32_t *) output_hash;
    output_hash_ptr32[0] = inputoutput[0];
    output_hash_ptr32[1] = inputoutput[1];
    output_hash_ptr32[2] = inputoutput[2];
    output_hash_ptr32[3] = inputoutput[3];
    output_hash_ptr32[4] = inputoutput[4];
    output_hash_ptr32[5] = inputoutput[5];
    output_hash_ptr32[6] = inputoutput[6];
    output_hash_ptr32[7] = inputoutput[7];
}

void x16rs_hash(const uint32_t height, const char* input_hash, char* output_hash)
{
	int repeat = (int) (height / 50000 + 1);
	if (repeat > 16)
		repeat = 16;

	uint32_t hash32[8];
	//in_debug(input_hash, 89);
	sha3_256(input_hash, 89, hash32);
	x16rs_hash_inner(repeat, hash32, output_hash);
	//in_debug(output_hash, 32);
}

int scanhash_x16rs(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint8_t endiandata[128];
	uint32_t _ALIGN(128) hash32[8];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	uint32_t *height = work->height;
	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	memcpy(endiandata, work->udata, 89);

	if (opt_benchmark) {
		height = 0xfff;
		ptarget[7] = 0x0cff;
	}

	do {
		memcpy(&endiandata[79], &nonce, 4);
		x16rs_hash(height, endiandata, hash32);

		if (hash32[7] <= Htarg && fulltest(hash32, ptarget)) {
			work_set_target_ratio(work, hash32);
			pdata[19] = nonce;
			*hashes_done = nonce - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;
	*hashes_done = nonce - first_nonce + 1;
	return 0;
}
