#ifndef _BLAKE2_
#define _BLAKE2_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>

#define ROTATE(x, n) (((x) >> (n)) | ((x) << (64-(n))))

//Definisco i tipi a 128 bit
typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;


///////////////////////////////////////////////////////////////////////
//                           CONSTANTS
///////////////////////////////////////////////////////////////////////


//Inizializzazione parametri
// In S[r][i] ho l'indice della word da utilizzare al round r passo Floor(i/2)+1
static const uint32_t S[12][16] = { 
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 } 
};


//Initial Vector
static const uint64_t IV[8] = { 
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179         
};



///////////////////////////////////////////////////////////////////////
//                           FUNCTIONS
///////////////////////////////////////////////////////////////////////


uint64_t * Gb(uint64_t * v, int a, int b, int c, int d, uint64_t x, uint64_t y);
uint64_t * F(uint64_t * h, uint64_t * m, uint128_t t, int flag);
uint8_t * blake2(uint8_t * input, uint128_t in_size, uint32_t hash_len);


#endif