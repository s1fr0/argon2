#include "argon2.h"

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


uint8_t * H(uint8_t * input, uint32_t in_size, uint32_t tau) {

    uint8_t * res;

    //new_in = tau || input
    uint8_t * new_in = (uint8_t *)calloc((4+in_size),sizeof(uint8_t));
    memcpy(new_in,&tau,4);
    memcpy(new_in+4,input,in_size);

    //If tag size is <=64 then i take the first tau byte from blake2b hash
    if (tau <= 64) {
        res = blake2(new_in,4+in_size,tau);
        free(new_in);
    }
    
    //Else i generate r sub blocks of 32 bytes + 1 of tau-32r
    else {

        res = (uint8_t *)calloc(tau,sizeof(uint8_t));
        uint32_t r = ceil(tau/32) - 2;
        
        uint8_t * V0, * V1;
        V0 = new_in;

        //First block generated from new_in
        V1 = blake2(V0,4+in_size,64);
        memcpy(res,V1,32);
        free(V0);
        V0=V1;
        
        //Other r-1 blocks
        for (int i=0;i<r-1;i++) {
            V1 = blake2(V0,64,64);
            memcpy(res+32*(i+1),V1,32);
            free(V0);
            V0 = V1;
        }

        //Last block
        V1 = blake2(V0,64,tau-32*r);
        memcpy(res+32*r,V1,tau-32*r);
        free(V0);
        free(V1);

    }

    return res;
}


uint8_t * extract_entropy() {

    uint8_t *IV = (uint8_t *)calloc(ctx.IV_len,sizeof(uint8_t));

    memcpy(IV                                          , &ctx.p    , 4);
    memcpy(IV +  4                                     , &ctx.tau  , 4);
    memcpy(IV +  8                                     , &ctx.m    , 4);
    memcpy(IV + 12                                     , &ctx.t    , 4);
    memcpy(IV + 16                                     , &ctx.v    , 4);
    memcpy(IV + 20                                     , &ctx.y    , 4);
    memcpy(IV + 24                                     , &ctx.P_len, 4);
    memcpy(IV + 28 + ctx.P_len                         , &ctx.S_len, 4);
    memcpy(IV + 32 + ctx.P_len +  ctx.S_len            , &ctx.K_len, 4);
    memcpy(IV + 36 + ctx.P_len +  ctx.S_len + ctx.K_len, &ctx.X_len, 4);

    if (ctx.P != NULL)
        memcpy(IV + 28                                     , ctx.P     , ctx.P_len);
    if (ctx.S != NULL)
        memcpy(IV + 32 + ctx.P_len                         , ctx.S     , ctx.S_len);
    if (ctx.K != NULL)
        memcpy(IV + 36 + ctx.P_len +  ctx.S_len            , ctx.K     , ctx.K_len);   
    if (ctx.X != NULL)
        memcpy(IV + 40 + ctx.P_len +  ctx.S_len + ctx.K_len, ctx.X     , ctx.X_len);

    uint8_t * H0 = blake2(IV,ctx.IV_len,64);

    free(IV);

    return H0;

}

uint64_t * G(uint64_t * v, int a, int b, int c, int d) {
    
    v[a] = v[a] + v[b] + 2*(v[a] & 0xFFFFFFFF)*(v[b] & 0xFFFFFFFF);     
    v[d] = ROTATE(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d] + 2*(v[c] & 0xFFFFFFFF)*(v[d] & 0xFFFFFFFF);             
    v[b] = ROTATE(v[b] ^ v[c], 24); 
    v[a] = v[a] + v[b] + 2*(v[a] & 0xFFFFFFFF)*(v[b] & 0xFFFFFFFF);        
    v[d] = ROTATE(v[d] ^ v[a], 16); 
    v[c] = v[c] + v[d] + 2*(v[c] & 0xFFFFFFFF)*(v[d] & 0xFFFFFFFF);             
    v[b] = ROTATE(v[b] ^ v[c], 63); 
 
    return v;
}


uint8_t * P(uint8_t * block) {

    uint8_t * res = (uint8_t *)calloc(128,sizeof(uint8_t));

    //Creo i vettori di stato e copio all'interno il contenuto di input
    uint64_t *v = (uint64_t *)calloc(16,sizeof(uint64_t));

    //Inizializzo i v[i] a partire da block = S0||...||S7, dove Si = (v[2i+1] || v[2i])
    for (int i=0; i<8; i++) {
        memcpy(&v[2*i]  ,&block[16*i]  ,8);
        memcpy(&v[2*i+1],&block[16*i+8],8);
    }

    //Per colonne
    v = G(v, 0,  4,  8, 12);
    v = G(v, 1,  5,  9, 13);
    v = G(v, 2,  6, 10, 14);
    v = G(v, 3,  7, 11, 15);

    //Per diagonali
    v = G(v, 0,  5, 10, 15);
    v = G(v, 1,  6, 11, 12);
    v = G(v, 2,  7,  8, 13);
    v = G(v, 3,  4,  9, 14);

    //Copio i vettori in res
    for (int i=0; i<8; i++) {
        memcpy(&res[16*i]  ,&v[2*i]  ,8);
        memcpy(&res[16*i+8],&v[2*i+1],8);
    }

    free(v);

    return res;
}



uint8_t * compress(uint8_t * block1, uint8_t * block2) {


    uint8_t * R = (uint8_t *)calloc(1024,sizeof(uint8_t));
    uint8_t * rows[8] = {NULL};


    //Initial XOR
    for (int i=0;i<1024;i++)
        R[i] = block1[i] ^ block2[i];


    //Rows compression
    for (int i=0; i<8; i++)
        rows[i] = P(R + 128*i);
    

    //Columns extraction
    uint8_t * c0 = (uint8_t *)calloc(128,sizeof(uint8_t));
    uint8_t * c1 = (uint8_t *)calloc(128,sizeof(uint8_t));
    uint8_t * c2 = (uint8_t *)calloc(128,sizeof(uint8_t));
    uint8_t * c3 = (uint8_t *)calloc(128,sizeof(uint8_t));
    uint8_t * c4 = (uint8_t *)calloc(128,sizeof(uint8_t));
    uint8_t * c5 = (uint8_t *)calloc(128,sizeof(uint8_t));
    uint8_t * c6 = (uint8_t *)calloc(128,sizeof(uint8_t));
    uint8_t * c7 = (uint8_t *)calloc(128,sizeof(uint8_t));

    for (int i=0; i<8; i++) {
        memcpy(c0+16*i, rows[i]+16*0,16);
        memcpy(c1+16*i, rows[i]+16*1,16);
        memcpy(c2+16*i, rows[i]+16*2,16);
        memcpy(c3+16*i, rows[i]+16*3,16);
        memcpy(c4+16*i, rows[i]+16*4,16);
        memcpy(c5+16*i, rows[i]+16*5,16);
        memcpy(c6+16*i, rows[i]+16*6,16);
        memcpy(c7+16*i, rows[i]+16*7,16);
    }


    //Freeing rows
    for (int i=0; i<8; i++)
        free(rows[i]);


    //Z rows compression
    rows[0] = P(c0); rows[1] = P(c1); rows[2] = P(c2); rows[3] = P(c3); 
    rows[4] = P(c4); rows[5] = P(c5); rows[6] = P(c6); rows[7] = P(c7);

   
    //Columns of Z extraction
    for (int i=0; i<8; i++) {
        memcpy(c0+16*i, rows[i]+16*0,16);
        memcpy(c1+16*i, rows[i]+16*1,16);
        memcpy(c2+16*i, rows[i]+16*2,16);
        memcpy(c3+16*i, rows[i]+16*3,16);
        memcpy(c4+16*i, rows[i]+16*4,16);
        memcpy(c5+16*i, rows[i]+16*5,16);
        memcpy(c6+16*i, rows[i]+16*6,16);
        memcpy(c7+16*i, rows[i]+16*7,16);
    }


    //Freeing rows of Z
    for (int i=0; i<8; i++)
        free(rows[i]);


    //Final XOR
    for (int i=0;i<128;i++) {
            R[128*0 + i] = R[128*0 + i] ^ c0[i];
            R[128*1 + i] = R[128*1 + i] ^ c1[i];
            R[128*2 + i] = R[128*2 + i] ^ c2[i];
            R[128*3 + i] = R[128*3 + i] ^ c3[i];
            R[128*4 + i] = R[128*4 + i] ^ c4[i];
            R[128*5 + i] = R[128*5 + i] ^ c5[i];
            R[128*6 + i] = R[128*6 + i] ^ c6[i];
            R[128*7 + i] = R[128*7 + i] ^ c7[i];
    }


    //Freeing Z columns
    free(c0); free(c1); free(c2); free(c3); free(c4); free(c5); free(c6); free(c7);

    return R;

}


uint8_t * compress2(uint8_t * input) {

    uint8_t * zero_block = (uint8_t *)calloc(1024,sizeof(uint8_t));

    uint8_t * R1 = compress(zero_block, input);

    uint8_t * R2 = compress(zero_block, R1);

    free(zero_block);
    free(R1);

    return R2;

}


///////////////////////////////////////////////////////////////////////
//                        BLOCK FUNCTIONS
///////////////////////////////////////////////////////////////////////


int get(int t, int i, int j) {

    //Since at each step, blocks are overwritten, I make the map non dependent
    //from pass t. Is left for a better interpretation of the code
    return ctx.q*i+j; 

}

uint8_t ** fillFirstBlocks() {

    //In B salverò tutti gli indirizzi di tutti i blocchi
    uint32_t maxMapValue = ctx.m1;
    B = (uint8_t **)calloc(maxMapValue,sizeof(uint8_t *));
    
    //Depending on OS if we allocate more than available B can be NULL or not
    if (B != NULL) {
    for (int i=0; i<ctx.p; i++){
        uint8_t * new_in = (uint8_t *)calloc(72,sizeof(uint8_t));
        
        //B[0,i,0] = H'(H0 || 0 || i ) con 0 <= i < p
        memcpy(new_in,H0,64);
        memset(new_in+64,0,1);
        memcpy(new_in+68,&i,4);
        B[get(0,i,0)] = H(new_in,72,1024);

        //B[0,i,1] = H'(H0 || 1 || i ) con 0 <= i < p
        memset(new_in+64,1,1);
        B[get(0,i,1)] = H(new_in,72,1024);

        free(new_in);
    }

    //Ora posso liberare H0
    free(H0);
    }

    return B;
}



void allocateJandCounters() {

    //J conterrà i pointer agli indici di ciascun segmento
    J = (uint8_t **)calloc(ctx.tot_seg,sizeof(uint8_t *));

    //G2_counter[i] memorizzerà l'indice da usare per il segmento i
    G2_counter = (uint64_t *)calloc(ctx.tot_seg,sizeof(uint64_t));

    //next_J[i] memorizzerà l'indice del prossimo J da usare per il segmento i
    next_J = (uint64_t *)calloc(ctx.tot_seg,sizeof(uint64_t));

    //Li inizializzo
    for(int i=0; i<ctx.tot_seg; i++) {
        J[i] = NULL;
        G2_counter[i] = 1;
        next_J[i] = 0;
    }

    return;
}


void generateJ(uint32_t t, uint32_t i, uint32_t j) {

    //We generate the block J only in Argon2i
    if (ctx.y) {
        uint8_t * input = (uint8_t *)calloc(1024,sizeof(uint8_t));

        //The slice number of the current j coordinate
        uint32_t s = (uint32_t)floor(j/ctx.segment_length); 

        //The current segment index
        uint32_t seg_idx = 4*i + s;

        //If the current block is at the beginning of a segment, G2_counter is set back to 1
        if (j % ctx.segment_length == 0) 
            G2_counter[seg_idx] = 1;

        //t,i,s sono tutti a 32 bit. Quindi copio solo 4 byte
        memcpy(input + 8*0, &t, 4);
        memcpy(input + 8*1, &i, 4);
        memcpy(input + 8*2, &s, 4);
        memcpy(input + 8*3, &ctx.m1, 4);
        memcpy(input + 8*4, &ctx.t, 4);
        memcpy(input + 8*5, &ctx.y, 4);
        memcpy(input + 8*6, &G2_counter[seg_idx], 4);

        //Libero i vecchi J, e creo i nuovi J1|J2
        free(J[seg_idx]);
        J[seg_idx] = compress2(input);

        //Azzero il counter dei J da usare
        next_J[seg_idx] = 0;

        //Incremento il counter per J
        G2_counter[seg_idx]++;

        free(input);
    }
        return;
}


void initializeJ(){

    //We initialize the block J only for Argon2i. 
    if (ctx.y) {
        for(int i=0; i<ctx.p; i++){
            generateJ(0,i,0);
            
            //In the first slice we start from the third value J1|J2
            next_J[4*i] = 2;
        }
    }
    return;
}



uint8_t * getRefBlock(uint32_t t, uint32_t i, uint32_t j){

    //The slice number of the current j coordinate
    uint32_t s = (uint32_t)floor(j/ctx.segment_length); 

    //The current segment index
    uint32_t seg_idx = 4*i + s;

    uint64_t * J1 = (uint64_t *)calloc(1,sizeof(uint64_t));
    uint64_t * J2 = (uint64_t *)calloc(1,sizeof(uint64_t));
    
    if (ctx.y) {
        memcpy(J1, J[seg_idx] + 8*next_J[seg_idx]    , 4);
        memcpy(J2, J[seg_idx] + 8*next_J[seg_idx] + 4, 4);
    }
    else {
        if (j != 0) {
            memcpy(J1, B[get(t,i,(j-1))]    , 4);
            memcpy(J2, B[get(t,i,(j-1))] + 4, 4);
        }
        else {
            memcpy(J1, B[get(t,i,ctx.q-1)]    , 4);
            memcpy(J2, B[get(t,i,ctx.q-1)] + 4, 4);
        }

    }

    //The lane number from which the block will be taken
    uint32_t l;

    //If we work with the first slice and the first pass, l is set to the
    //current lane index, else l = J2 mod p
    if ((t==0) && (s==0))
        l = i;
    else
        l = *J2 % ctx.p;


    uint32_t min_j, max_j;

    // Da implementazione: -------------------------------------------------------------------------
    // 
    // Pass 0:
    //      This lane : all already finished segments plus already constructed blocks in this segment
    //      Other lanes : all already finished segments
    // Pass 1+:
    //      This lane : (SYNC_POINTS - 1) last segments plus already constructed blocks in this segment
    //      Other lanes : (SYNC_POINTS - 1) last segments
    // 
    // Da specifica: -------------------------------------------------------------------------------
    //
    // If l is the current lane, then R includes all blocks computed in this lane, 
    // that are not overwritten yet, excluding B[i][j-1]
    //
    // If l is not the current lane, then R includes all blocks in the last S-1 = 3 segments
    // computed and finished in lane l. If B[i][j] is the first block of a segment, then
    // the very last block is excluded

    //Seguo le indicazioni da implementazione:

    if (l == i) {

        //Se sono al primo passo considero tutti i blocchi da zero a j-2
        //-- First pass same lane
        if (t==0) {
            min_j = 0;
            max_j = j-2; 
        }

        //Altrimenti devo prendere tutti i blocchi degli ultimi 3 segmenti e quelli
        //già calcolati del segmento corrente escluso B[i][j-1]
        //-- Pass 1+ same lane
        else {
            min_j = (s+1)*ctx.segment_length; 
            max_j = ctx.q + j-2;
        }
    }

    else {
        
        //-- First pass different lane
        if (t==0) {
            min_j = 0; 
            max_j = s*ctx.segment_length - 1;
        }

        //-- Pass 1+ different lane
        else {
            min_j = (s+1)*ctx.segment_length;
            max_j = ctx.q + s*ctx.segment_length - 1;       
        }

        // Only when different lanes : if the current block is at the beginning of a segment, 
        // B[i][j] is exluded
        if (j % ctx.segment_length == 0) 
            max_j--;

    } 

    //The size of R
    uint64_t R = max_j - min_j + 1;

    //Computation of the block number
    uint64_t x = ((*J1)*(*J1)) >> 32;
    uint64_t z = R - 1 - ((R*x) >> 32);

    //Incremento il contatore J1|J2
    next_J[seg_idx]++;

    //Libero J1, J2
    free(J1); free(J2);

    //Retrieving the pointer to the block 
    return B[get(t, l, (min_j+z) % ctx.q)];
    
}

//Xor_blocks è usata solo per la generazione dei blocchi al passo 1+
//Per questo motivo gli argomenti sono liberati entrambi
uint8_t * xor_blocks(uint8_t * b1, uint8_t * b2) {

    uint8_t * res = (uint8_t *)calloc(1024,sizeof(uint8_t));

    for(int i=0; i<1024; i++)
        res[i]= b1[i] ^ b2[i];

    //b1 è il blocco che sto sovrascrivendo. Quindi lo libero
    free(b1); 

    //b2 è il risultato di una compress, non mi serve
    free(b2);

    return res;
}


void fillBlocks() {

    uint32_t sl = ctx.segment_length; 

    for(int t=0; t<ctx.t; t++) {
        for(int s=0; s<4; s++) {
            #pragma omp parallel for
            for(int i=0; i<ctx.p; i++){
                //j is the relative position inside the segment
                for(int j=(((t==0) && (s==0)) ? 2 : 0); j<sl; j++){

                    //Controllo se devo generare nuovi indici
                    if ( (j % 128) == 0 ) {
                        generateJ(t,i,j+sl*s);
                    }

                    //If we are in the first pass, we start from the second column and we 
                    //have a compression with the reference block
                    if (t==0) {
                        B[get(t,i,j+sl*s)] = compress(B[get(t,i,j+sl*s-1)],getRefBlock(t,i,j+sl*s));
                    }
                    else {
                        //If we are in the first block of a lane we have to take the last block of the lane in compression, else the previous
                        if ((j==0) && (s==0))
                            B[get(t,i,j+sl*s)] = xor_blocks(B[get(t-1,i,j+sl*s)],compress(B[get(t,i,ctx.q -1)],getRefBlock(t,i,j+sl*s)));
                        else 
                            B[get(t,i,j+sl*s)] = xor_blocks(B[get(t-1,i,j+sl*s)],compress(B[get(t,i,j+sl*s-1)],getRefBlock(t,i,j+sl*s)));
                    }
                }
            }
        }
    }

    return;
}

uint8_t * xor_last_column() {

    uint8_t * H = B[get(ctx.t-1,0,ctx.q-1)];
    for(int i=1;i<ctx.p;i++){
        H = xor_blocks(B[get(ctx.t-1,i,ctx.q-1)],H);
    }

    return H;
}


void freeBlocksAndCounters(){
    #pragma omp parallel for
    for(int i=0; i<ctx.p; i++){
        for(int j=0; j<ctx.q-1; j++){
        free(B[get(ctx.t-1,i,j)]);
        }
    }
                
    free(B);

    #pragma omp parallel for
    for(int i=0; i<4*ctx.p; i++)
        free(J[i]);
    
    free(J);
    free(next_J);
    free(G2_counter);

}


///////////////////////////////////////////////////////////////////////
//                PRINTF AND INITIALIZATION FUNCTIONS
///////////////////////////////////////////////////////////////////////

void printINFO() {

uint8_t * p;

    printf("=======================================\n");
    
    if (ctx.y)
        printf("Argon2i version number ");
    else
        printf("Argon2d version number ");

    printf("%d\n",ctx.v);

    printf("=======================================\n");

    printf("Memory: %" PRIu32 " KB (m': %" PRIu32 "), Iterations: %" PRIu32 ", Parallelism: %" PRIu32 " lanes, Tag length: %" PRIu32 " bytes\n\n", ctx.m, ctx.m1, ctx.t, ctx.p, ctx.tau);

    printf("Password[%" PRIu32 "]: ",ctx.P_len);
    p = (uint8_t *) ctx.P;
    for(int i = 0; i < ctx.P_len; i++)
        printf("%02x ", (uint8_t)p[i]);
    printf("\n");

    printf("Salt[%" PRIu32 "]: ",ctx.S_len);
    p = (uint8_t *) ctx.S;
    for(int i = 0; i < ctx.S_len; i++)
        printf("%02x ", (uint8_t)p[i]);
    printf("\n");

    printf("Secret[%" PRIu32 "]: ",ctx.K_len);
    p = (uint8_t *) ctx.K;
    for(int i = 0; i < ctx.K_len; i++)
        printf("%02x ", (uint8_t)p[i]);
    printf("\n");

    printf("Associated data[%" PRIu32 "]: ",ctx.X_len);
    p = (uint8_t *) ctx.X;
    for(int i = 0; i < ctx.X_len; i++)
        printf("%02x ", (uint8_t)p[i]);
    printf("\n");

    printf("Pre-hashing digest: ");
    p = (uint8_t *) H0;
    for(int i = 0; i < 64; i++)
        printf("%02x ", (uint8_t)p[i]);
    printf("\n");

    return;

}


void help() {
    printf("Usage: [-h] [-P password] [-S salt] [-K secret key] [-X associated data] "
           "[-m memory] [-t iterations] "
           "[-p parallelism] [-l hash length] [-i|-d] \n\n");
    printf("Parameters:\n");
    printf("\t-P pass\t\tThe password to hash, from 0 to 2^32-1 characters. (default NULL)\n");
    printf("\t-S salt\t\tThe salt to use, from 8 to 2^32-1 characters.\n");
    printf("\t-K key\t\tThe secret key, from 0 to 2^32-1 characters. (default NULL)\n");
    printf("\t-X data\t\tThe associated data, from 0 to 2^32-1 characters. (default NULL)\n");

    printf("\t-t N\t\tSets the number of iterations to N. From 1 to 2^24-1. (default = %d)\n", ARGON2_T_DEFAULT);
    printf("\t-m N\t\tSets the memory usage to N KB. From 8p to 2^32-1. (default %d)\n", ARGON2_M_DEFAULT);
    printf("\t-p N\t\tSets parallelism to N threads. From 1 to 2^32-1. (default %d)\n", ARGON2_P_DEFAULT);
    printf("\t-l N\t\tSets hash output length to N bytes. From 4 to 2^32-1. (default %d)\n", ARGON2_TAU_DEFAULT);

    printf("\t-i\t\tUse Argon2i (this is the default)\n");
    printf("\t-d\t\tUse Argon2d instead of Argon2i\n");

    printf("\t-h\t\tPrint help\n");
}


int initContext(int argc, char *argv[]) {

    //If no options provided print usage
    if (argc==1) {
        help();
        return 0;
    }

    uint8_t * tmp_P = ARGON2_PASSWORD_DEFAULT,
            * tmp_S = ARGON2_SALT_DEFAULT,
            * tmp_K = ARGON2_SK_DEFAULT,
            * tmp_X = ARGON2_AD_DEFAULT;

    //I use long long to check if values passed are negative or out of bound.
    long long tmp_t = ARGON2_T_DEFAULT,
              tmp_m = ARGON2_M_DEFAULT,
              tmp_p = ARGON2_P_DEFAULT,
              tmp_tau = ARGON2_TAU_DEFAULT,
              tmp_y = ARGON2_Y_DEFAULT;

    size_t tmp_P_len = 0,
           tmp_S_len = 0,
           tmp_K_len = 0,
           tmp_X_len = 0;
             
    int c;
    while ((c = getopt(argc, argv, "ht:m:p:l:diP:S:K:X:")) != -1)
    
        switch (c) {

          case 'P':
            tmp_P = (uint8_t *) optarg;
            tmp_P_len = strlen(optarg);
            break;
          case 'S':        
            tmp_S = (uint8_t *) optarg;
            tmp_S_len = strlen(optarg);
            break;
          case 'K':        
            tmp_K = (uint8_t *) optarg;
            tmp_K_len = strlen(optarg);
            break;
          case 'X':        
            tmp_X = (uint8_t *) optarg;
            tmp_X_len = strlen(optarg);
            break;

          case 't':
            tmp_t = strtoll(optarg,NULL,10);
            break;
          case 'm':
            tmp_m = strtoll(optarg,NULL,10);
            break;
          case 'p':
            tmp_p = strtoll(optarg,NULL,10);
            break;
          case 'l':
            tmp_tau = strtoll(optarg,NULL,10);
            break;
          case 'd':
            tmp_y = 0;
            break;
          case 'i':
            tmp_y = 1;
            break;
          case 'h':
            help();
            return 0;
            break;

          case '?':
            if ((optopt == 't') || (optopt == 'm') || (optopt == 'p') || (optopt == 'l') ||
                (optopt == 'P') || (optopt == 'S') || (optopt == 'K') || (optopt == 'X')  )
              printf("Option -%c requires an argument.\n", optopt);
            else if (isprint(optopt))
              printf("Unknown option `-%c'.\n", optopt);
            else
              printf("Unknown option character `\\x%x'.\n", optopt);
            return 0;

          default:
            return 0;
      }

    //Missing required parameters, negative or zero value
    if ((tmp_S == NULL) || (tmp_t <= 0) || (tmp_m <= 0) || (tmp_p <= 0) || (tmp_tau <= 0) ) {
        printf("Required values missing or negative/zero values provided. Check");
        if (tmp_S == NULL) 
            printf(" -S");
        if (tmp_t <= 0) 
            printf(" -t");
        if (tmp_m <= 0) 
            printf(" -m");
        if (tmp_p <= 0) 
            printf(" -p");
        if (tmp_tau <= 0) 
            printf(" -l");
        printf(".\n");
    

    return 0;
    }
        

    //Out of bound values. 
    if (tmp_P_len > pow(2,32)-1) {
        printf("Password P must have length from 0 to 2^32 - 1 bytes.\n");
        return 0;
    }

    if ((tmp_S_len < 8) || (tmp_S_len > pow(2,32)-1)) {
        printf("Salt S must have length from 8 to 2^32 - 1 bytes.\n");
        return 0;
    }

    if (tmp_K_len > pow(2,32)-1) {
        printf("Secret key K must have length from 0 to 2^32 - 1 bytes.\n");
        return 0;
    }

    if (tmp_X_len > pow(2,32)-1) {
        printf("Assiciated data X must have length from 0 to 2^32 - 1 bytes.\n");
        return 0;
    }

    if (tmp_p > pow(2,24)-1) {
        printf("Degree of parallelism p must take any integer value between 1 to 2^24 - 1 bytes.\n");
        return 0;
    }

    if (tmp_t > pow(2,32)-1) {
        printf("Number of iterations t must take any integer value between 1 to 2^32 - 1 bytes.\n");
        return 0;
    }
    
    if ((tmp_m < 8*tmp_p) || (tmp_m > pow(2,32)-1)) {
        printf("Memory size m must take any integer number of kilobytes between 8p to 2^32 - 1 bytes.\n");
        return 0;
    }

    if ((tmp_tau < 4) || (tmp_tau > pow(2,32)-1)) {
        printf("Hash output length l must take any integer number of bytes between 4 to 2^32 - 1 bytes.\n");
        return 0;
    }


    //Memory warning. If the user tries to allocate more that MEM_WARNING kB
    if (tmp_m >= MEM_WARNING) {
        printf("\nMemory m requested is more than ~%.1fGB. \nDepending on your system, if free available memory is less than requested this program can cause segfault.\nDo you wish to continue? [y/n] ", (double) MEM_WARNING/(1024*1024));
        char ch;
        ch = getchar();
        if (!(( ch == 'y') || ( ch == 'Y')))
            return 0;
    }


    //Available memory test. Depending on OS it can give NULL or not
    //the coefficient 1.2 accounts for the auxiliary data used during hashing.
    uint8_t * test = malloc(floor(tmp_m*1.2*1024)*sizeof(uint8_t));
    if (test == NULL) {
        printf("Free available memory less that requested. Reduce m.\n");
        return 0;
    }
    free(test);

    //Everything here is ok and we can store parameters in context
    ctx.P = tmp_P;
    ctx.S = tmp_S;
    ctx.K = tmp_K;
    ctx.X = tmp_X;

    ctx.P_len = tmp_P_len;
    ctx.S_len = tmp_S_len;
    ctx.K_len = tmp_K_len;
    ctx.X_len = tmp_X_len;

    ctx.t   = (uint32_t)tmp_t;
    ctx.m   = (uint32_t)tmp_m;
    ctx.p   = (uint32_t)tmp_p;
    ctx.tau = (uint32_t)tmp_tau;
    ctx.y   = (uint32_t)tmp_y;


    //Derived parameters
    ctx.q = (uint32_t)floor(ctx.m/(4*ctx.p))*4;
    ctx.m1 = ctx.q*ctx.p;
    ctx.segment_length = (uint32_t)ctx.q/4;
    ctx.tot_seg = 4*ctx.p;
    ctx.v = ARGON2_VERSION;
    ctx.IV_len = 40 + ctx.P_len + ctx.S_len + ctx.K_len + ctx.X_len;


    return 1;
}


void printTag() {

    uint8_t * p = tag;
    printf("\nTag: ");
    for(int j = 0; j < ctx.tau; j++) {
       printf("%02x", (uint8_t)p[j]);
    }
    printf("\n");

}