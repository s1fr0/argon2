#ifndef _ARGON2_
#define _ARGON2_

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <inttypes.h>
#include <math.h>

#include "blake2.h"

//Rotate è usata sia da Argon che blake. Ridefinita qui per migliore lettura del codice
#ifndef _BLAKE2_
#define ROTATE(x, n) (((x) >> (n)) | ((x) << (64-(n))))
#endif

///////////////////////////////////////////////////////////////////////
//                             DEFAULTS
///////////////////////////////////////////////////////////////////////

#define ARGON2_PASSWORD_DEFAULT NULL
#define ARGON2_SALT_DEFAULT NULL
#define ARGON2_SK_DEFAULT NULL
#define ARGON2_AD_DEFAULT NULL

#define ARGON2_Y_DEFAULT 1
#define ARGON2_TAU_DEFAULT 32
#define ARGON2_T_DEFAULT 3
#define ARGON2_M_DEFAULT 4096
#define ARGON2_P_DEFAULT 1

#define ARGON2_VERSION 0x13

#define MEM_WARNING 7864320 // ~7.5GB


///////////////////////////////////////////////////////////////////////
//                             STRUCTS
///////////////////////////////////////////////////////////////////////

typedef struct Argon2_ctx {

    uint8_t *out;       /* output array */
    uint32_t outlen;    /* digest length */

    uint8_t *P;         /* password array */
    uint32_t P_len;     /* password length [0,2^32-1] bytes */

    uint8_t *S;         /* salt array */
    uint32_t S_len;     /* salt length [8,2^32-1] bytes */

    uint8_t *K;         /* key array */
    uint32_t K_len;     /* key length [0,32] bytes */

    uint8_t *X;         /* associated data array */
    uint32_t X_len;     /* associated data length [0,2^32-1] bytes */

    uint32_t t;         /* number of iterations */
    uint32_t m;         /* amount of memory requested (KB) */
    uint32_t m1;        /* nearest multiple of 4p to m */
    uint32_t q;         /* number of columns */
    uint32_t segment_length; /*The length of a segment*/
    uint32_t tot_seg;   /* The total number of segments */

    uint32_t p;         /* number of lanes */
    uint32_t tau;       /*tag length [4,2^32-1] bytes*/


    uint32_t v;         /* version number 0x13 */
    uint32_t y;         /* Type of Argon2: 0 for 2d, 1 for 2i */

    uint64_t IV_len;   /* the total lenght of the initial vector */
   
} argon2_ctx;



///////////////////////////////////////////////////////////////////////
//                         GLOBAL VARIABLES
///////////////////////////////////////////////////////////////////////

argon2_ctx ctx;
uint8_t ** B;
uint8_t ** J;
uint8_t * H0;
uint8_t * H1;
uint64_t * next_J;
uint64_t * G2_counter;
uint8_t * tag;


///////////////////////////////////////////////////////////////////////
//                   COMPRESS AND HASH FUNCTIONS
///////////////////////////////////////////////////////////////////////

// H : Argon2 variable length hash function
// Inputs: input, input size and tag length tau
uint8_t * H(uint8_t * input, uint32_t in_size, uint32_t tau);

//extract_entropy: create initial digest from input
uint8_t * extract_entropy(void);

//G: Argon2 G compress function applied to v[a],v[b],v[c],v[d]. Build upon Blake2b's G
//Input: v, a, b, c, d
uint64_t * G(uint64_t * v, int a, int b, int c, int d);

//P: Argon2 permutation P (uses G)
//Input: 1024 bytes long block
uint8_t * P(uint8_t * block);

//compress: Argon2 compress function (uses P)
//Input: 2 blocks of 1024 bytes each
uint8_t * compress(uint8_t * block1, uint8_t * block2);

//compress2: is equivalent to compress(0,compress(0,input))
//Input: 1024 bytes long block
uint8_t * compress2(uint8_t * input);

///////////////////////////////////////////////////////////////////////
//                         BLOCK FUNCTIONS
///////////////////////////////////////////////////////////////////////

//get: used to map the blocks matrix coordinates in a B array position. (t,i,j) -> i*q+j
//Note: the mapping is indipendent from pass t, since blocks are overwritten
//Input: pass t, row i, column j 
int get(int t, int i, int j);

//fillFirstBlocks: fills first two columns at first pass using the initial digest
uint8_t ** fillFirstBlocks(void);

//allocateJandCounters: initialize J, J_next, G2_counter and set their value to 0
void allocateJandCounters(void);

//generateJ: generate a new indexes block for the segment where B[t,i,j] is
//Input: pass t, row i, column j
void generateJ(uint32_t t, uint32_t i, uint32_t j);

//initializeJ: applies generateJ to the first slice of the first pass and set next_J to 2
void initializeJ(void);

//getRefBlock: get the reference block, that is the B[t',i',j'] for pass t, row i, column j
//Input: pass t, row i, column j
uint8_t * getRefBlock(uint32_t t, uint32_t i, uint32_t j);

//xor_blocks: xor the two blocks b1 and b2
//Input: block b1, block b2
uint8_t * xor_blocks(uint8_t * b1, uint8_t * b2);

//fillBlocks: create all the blocks for all the pass
void fillBlocks(void);

//xor_last_column: xor the last column of B at pass t
uint8_t * xor_last_column(void);

//freeBlocksAndCounters: frees all allocated variables
void freeBlocksAndCounters(void);

///////////////////////////////////////////////////////////////////////
//                PRINTF AND INITIALIZATION FUNCTIONS
///////////////////////////////////////////////////////////////////////

//printINFO: print all the parameters passed to the function
void printINFO(void);

//help: print the usage of the program
void help(void);

//initContext: initialize the argon2_ctx struct
//Input: argc, argv
int initContext(int argc, char *argv[]);

//printTag: print the final tag
void printTag(void);

///////////////////////////////////////////////////////////////////////
//                             MAIN
///////////////////////////////////////////////////////////////////////

//main: the main functions. All the functions are called and the hash is generated
//Input: argc, argv
int main(int argc, char *argv[]);

#endif