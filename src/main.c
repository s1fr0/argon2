#include "argon2.h"

int main(int argc, char *argv[]) {

    //Processo l'input e salvo tutto in ctx
    if (!initContext(argc,argv))
        return 0;
    
    //Alloco e inizializzo J, G2_counter, next_J    
    allocateJandCounters();

    //Initial Digest
    H0 = extract_entropy();
    
    //Stampo tutti i valori del ctx e del digest
    printINFO();

    //Riempio i blocchi iniziali
    B = fillFirstBlocks();

    if (B == NULL) {
        printf("Free available memory less that requested. Reduce m.\n");
        return 0;
    }
        
    //Inizializzo i J per ogni segmento
    initializeJ();

    //Riempio tutti i blocchi per ogni passo
    fillBlocks();

    //Xor dei blocchi dell'ultima colonna
    H1 = xor_last_column();

    //Rilascio tutti i blocchi e i contatori
    freeBlocksAndCounters();

    //Calcolo il digest finale
    tag = H(H1,1024,ctx.tau);

    //Stampo il tag
    printTag();

    //Libero la memoria
    free(H1); free(tag);

    return 1;

}