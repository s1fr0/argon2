#include "blake2.h"

uint64_t * Gb(uint64_t * v, int a, int b, int c, int d, uint64_t x, uint64_t y) {

    v[a] = v[a] + v[b] + x;     
    v[d] = ROTATE(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];             
    v[b] = ROTATE(v[b] ^ v[c], 24); 
    v[a] = v[a] + v[b] + y;         
    v[d] = ROTATE(v[d] ^ v[a], 16); 
    v[c] = v[c] + v[d];             
    v[b] = ROTATE(v[b] ^ v[c], 63); 
 
    return v;
}

uint64_t * F(uint64_t * h, uint64_t * m, uint128_t t, int flag) {

    //Creo in memoria v e lo inizializzo
    uint64_t * v = (uint64_t *)malloc(sizeof(uint64_t)*16);

    for(int i=0;i<8;i++) {
        v[i] = h[i];
        v[i+8] = IV[i];
    }


    //Xoring con il counter t
    v[12] = v[12] ^ ((      t) & 0xFFFFFFFFFFFFFFFF);
    v[13] = v[13] ^ ((t >> 64) & 0xFFFFFFFFFFFFFFFF);


    //Se siamo all'ultimo blocco inverto tutti i bit di v[14]
    if (flag)
        v[14] = ~v[14];


    //Rounds
    for(int curr_round=0; curr_round<12; curr_round++) {
        
        v = Gb(v, 0, 4,  8, 12, m[S[curr_round][ 0]], m[S[curr_round][ 1]]);
        v = Gb(v, 1, 5,  9, 13, m[S[curr_round][ 2]], m[S[curr_round][ 3]]);
        v = Gb(v, 2, 6, 10, 14, m[S[curr_round][ 4]], m[S[curr_round][ 5]]);
        v = Gb(v, 3, 7, 11, 15, m[S[curr_round][ 6]], m[S[curr_round][ 7]]);
        v = Gb(v, 0, 5, 10, 15, m[S[curr_round][ 8]], m[S[curr_round][ 9]]);
        v = Gb(v, 1, 6, 11, 12, m[S[curr_round][10]], m[S[curr_round][11]]);
        v = Gb(v, 2, 7,  8, 13, m[S[curr_round][12]], m[S[curr_round][13]]);
        v = Gb(v, 3, 4,  9, 14, m[S[curr_round][14]], m[S[curr_round][15]]);
    }

    //Xoring con il work vector
    for(int i=0;i<8;i++) {
        h[i] = h[i] ^ v[i] ^ v[i+8];
    }


    free(v);

    //Return del nuovo stato
    return h;
}


//Funzione principale per la generazione dell'hash. 
//TO DO: Da aggiungere la key
uint8_t * blake2(uint8_t * input, uint128_t in_size, uint32_t hash_len) {

    uint64_t * m;


    //-----------------------------------------------------------------------
    //                            KEY MANAGEMENT
    //-----------------------------------------------------------------------
    //----- Di default la chiave non è supportata
    //uint8_t * key = NULL;
    //uint32_t key_len = 0;
    //int keyed_hash = 0; //Porre a 1 se presente la chiave
    //-----------------------------------------------------------------------


    //Vettore di stato e inizializzazione
    uint64_t * h = (uint64_t *)malloc(sizeof(uint64_t)*8);

    for(int i=0; i<8; i++)
        h[i] = IV[i];

    //Parameter block p[0]
    h[0] = h[0] ^ 0x01010000 ^ /*(key_len << 8) ^*/  hash_len ;


    //Se il FILESIZE è positivo procedo all'hashing standard
    if (!in_size /*&& !keyed_hash*/) {

        //Se il messaggio è vuoto, compimo 16 words vuote.
        m = calloc(16,sizeof(uint64_t));
        h = F(h, m, 0, 1);
        free(m);

    }

    else {

        //Calcolo il message_length totale con padding a 0. Può essere al massimo 2^128-1 byte
        uint128_t k = -in_size % 128;
        uint128_t message_length = in_size + k;

        //Conto da quanti blocchi di 128 bytes è composto il mio messaggio (al massimo 2^128/128 -> bastano 31 byte)
        uint128_t num_blocchi = message_length / 128;

        
        //Ciclo sul blocco corrente che sto analizzando fino al penultimo
        uint32_t current_block;
        uint8_t * source = input;


        //Se l'hash ha la chiave, la processo come primo blocco
        //if (keyed_hash) {
        //    m = calloc(16,sizeof(uint64_t));
        //    memcpy(m,key,key_len); 
        //    h = F(h, m, 128, 0);
        //    free(m);
        //}


        for (current_block = 0; current_block < num_blocchi - 1; current_block++) {

            //Salvo le 16 words da 64 bit in m del current_block da 128 byte.
            m = calloc(16,sizeof(uint64_t));

            //Altrimenti copio 128 byte della stringa in ingresso
            memcpy(m,source,16*8);
            source += 128;

            //Compress function F
            h = F(h, m, (uint128_t) (current_block /*+ keyed_hash*/ + 1 )*128, 0);

            //Libero m
            free(m);

        }


        //Last blocco

        //Salvo le 16 words da 64 bit in m del current_block da 128 byte.
        m = calloc(16,sizeof(uint64_t));

        //Altrimenti copio i rimanenti byte della stringa in ingresso     
        memcpy(m,source, in_size % 128);
        
        //Last Compress function F
        h = F(h, m, in_size /*+ keyed_hash*128*/, 1);

        free(m);

    }

    uint8_t *hh = (uint8_t *)malloc(sizeof(uint8_t)*hash_len);

    memcpy(hh,h,hash_len);

    free(h); 

    return (uint8_t *) hh;

}