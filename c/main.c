/**
  AES encryption/decryption demo program using OpenSSL EVP apis
  gcc -Wall openssl_aes.c -lcrypto

  this is public domain code. 

  Saju Pillai (saju.pillai@gmail.com)
**/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

unsigned char *hex_2_string(const unsigned char* hex, const unsigned int length) {
    unsigned char * result=calloc(length*2+1, 1);
    for (unsigned int i = 0; i < length; ++i) {
	sprintf(result + i*2, "%02x", hex[i]);
    }
    return result;
}

void set_value(char * ptr, int len) {
    if (len > 16)
	for (int i=0; i<len; i++) {
		ptr[i] = 'b';
	}
    else {
        for (int i=0; i<len; i++) {
                ptr[i] = 'a';
        }
	}
}

/**
 * Create a 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *e_ctx, 
             EVP_CIPHER_CTX *d_ctx)
{
  int i, nrounds = 14;
  unsigned char key[32], iv[16];
  
  /*
   * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */
  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), salt, key_data, key_data_len, nrounds, key, iv);
  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }

  //set_value(key, 32);
  set_value(iv, 16);
  printf("pwd size %d, val %s, salt %s\n", key_data_len, key_data, salt);
  printf("key raw %02x, %02x, %02x, %02x\n", key[0], key[1],key[2],key[3]);
  printf("Key size %d, val %s, iv %s\n", i, hex_2_string(key, 32), hex_2_string(iv, 32));



  EVP_CIPHER_CTX_init(e_ctx);
  EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
  EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

  return 0;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  unsigned char *ciphertext = malloc(c_len);

  /* allows reusing of 'e' for multiple encryption cycles */
  EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

  /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
  EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

  /* update ciphertext with the final remaining bytes */
  EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

  *len = c_len + f_len;
  return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  /* plaintext will always be equal to or lesser than length of ciphertext*/
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = malloc(p_len);
  
  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}

int main(int argc, char **argv)
{
  /* "opaque" encryption, decryption ctx structures that libcrypto uses to record
     status of enc/dec operations */
  EVP_CIPHER_CTX* en = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX* de = EVP_CIPHER_CTX_new();

  /* 8 bytes to salt the key_data during key generation. This is an example of
     compiled in salt. We just read the bit pattern created by these two 4 byte 
     integers on the stack as 64 bits of contigous salt material - 
     ofcourse this only works if sizeof(int) >= 4 */
  unsigned char salt[] = {'a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a'};
  unsigned char *key_data;
  int key_data_len, i;
//  char *input[] = {"a", "hello", "this is a test", "this is a bigger test", 
//                   "\nWho are you ?\nI am the 'Doctor'.\n'Doctor' who ?\nPrecisely!",
//                   NULL};

   char *input[] = {"hello"};

  /* the key_data is read from the argument list */
  key_data = (unsigned char *)argv[1];
  key_data_len = strlen(argv[1]);
  
  /* gen key and iv. init the cipher ctx object */
  if (aes_init(key_data, key_data_len, (unsigned char *)&salt, en, de)) {
    printf("Couldn't initialize AES cipher\n");
    return -1;
  }

  /* encrypt and decrypt each input string and compare with the original */
  for (i = 0; input[i]; i++) {
    char *plaintext;
    unsigned char *ciphertext;
    int olen, len;
    
    /* The enc/dec functions deal with binary data and not C strings. strlen() will 
       return length of the string without counting the '\0' string marker. We always
       pass in the marker byte to the encrypt/decrypt functions so that after decryption 
       we end up with a legal C string */
    olen = len = strlen(input[i])+1;
    
    ciphertext = aes_encrypt(en, (unsigned char *)input[i], &len);
    printf("OK: ciphertext: %s\n", hex_2_string(ciphertext, strlen(ciphertext)));
    plaintext = (char *)aes_decrypt(de, ciphertext, &len);

    if (strncmp(plaintext, input[i], olen)) 
      printf("FAIL: enc/dec failed for \"%s\"\n", input[i]);
    else 
      printf("OK: enc/dec ok for \"%s\"\n", plaintext);
    
    free(ciphertext);
    free(plaintext);
  }

  EVP_CIPHER_CTX_free(en);
  EVP_CIPHER_CTX_free(de);

  return 0;
}