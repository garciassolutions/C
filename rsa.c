/*
04.2016
openssl genrsa -out private.pem 2048 && openssl rsa -in private.pem -outform PEM -pubout -out public.pem
*/
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int padding = RSA_NO_PADDING;

void printLastError(char *msg){
    char *err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
    exit(1);
}

RSA *createRSA(unsigned char * key,int public){
    RSA *rsa = NULL;
    BIO *keybio;
    keybio = BIO_new_mem_buf(key, -1);
    if(keybio == NULL){
        puts("Failed to create key BIO");
        return 0;
    }

    if(public)
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    else
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);

    if(rsa == NULL)
        puts("Failed to create RSA");
    return rsa;
}

RSA *createRSAWithFilename(char *filename, int public){
    FILE *fp = fopen(filename,"rb");
 
    if(fp == NULL){
        printf("Unable to open file %s \n",filename);
        return NULL;    
    }
    RSA *rsa = RSA_new();
 
    if(public)
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
    else
        rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
    return rsa;
}

int private_encrypt(unsigned char *data, int data_len, unsigned char *filename, unsigned char *encrypted){
    RSA *rsa = createRSAWithFilename(filename, 0);
    int result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}

int private_decrypt(unsigned char *enc_data, int data_len, unsigned char *filename, unsigned char *decrypted){
    RSA *rsa = createRSAWithFilename(filename, 0);
    int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

int public_encrypt(unsigned char *data, int data_len, unsigned char *filename, unsigned char *encrypted){
    RSA *rsa = createRSAWithFilename(filename, 1);
    int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
} 

int public_decrypt(unsigned char *enc_data, int data_len, unsigned char *filename, unsigned char *decrypted){
    RSA *rsa = createRSAWithFilename(filename, 1);
    int result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

int main(int argc, char *argv[]){
    if(argc != 4){
        fprintf(stderr, "Usage: %s [e|d] KEY_FILENAME INPUT\n", argv[0]);
        return -1;
    }
    char *key = argv[2];
    char plaintext[2048/8] = {0};
    char encrypted[4096];
    
    if(argv[1][0] == 'e'){
        puts("Public enc.");
        FILE *IN_FILE = fopen(argv[3], "r");
        int OUT_FILE = open("test.enc", O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
        int x = 0;
        while((x=fread(plaintext, 1, 256, IN_FILE))){
            // Put this in a loop for files > plaintext size. append to output with write()
            if(x != 256)
                padding = RSA_PKCS1_PADDING;
            
            int encrypted_length = public_encrypt(plaintext, x, key, encrypted);
            if(encrypted_length == -1)
                printLastError("Error encrypting.");
            write(OUT_FILE, encrypted, encrypted_length);
        }
        if(x != 256)
            write(OUT_FILE, "\xFF", 1);
            
        fclose(IN_FILE);
        close(OUT_FILE);
    }
    
    else if(argv[1][0] == 'd'){
        int OUT_FILE = open("test.dec", O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
        // See if padding was used.
        struct stat fileStat;
        stat("test.enc", &fileStat);
        
        puts("Private decrypt.");
        FILE *IN_FILE = fopen("test.enc", "r");
        int x = 0;
        int ttl_read = 0;
        while((x=fread(plaintext, 1, 256, IN_FILE))){
            if(x == 1)
                break; // Extra byte at the end to signify padding.
            
            ttl_read += x;
            if(ttl_read == fileStat.st_size-1)
                padding = RSA_PKCS1_PADDING;
            
            int dec = private_decrypt(plaintext, x, key, encrypted);
            if(dec == -1)
                printLastError("Error decrypting.");
            if(dec > 0)
                write(OUT_FILE, encrypted, dec);
        }
        fclose(IN_FILE);
        close(OUT_FILE);
    }
    puts("Success.");
    return 0;
}
