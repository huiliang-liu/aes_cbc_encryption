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

void print_hex_2_string(const unsigned char* hex, const unsigned int length, const char* hint) {
  unsigned char *hex_str = hex_2_string(hex, length);
  printf("%s: %s\n", hint, hex_str);
  free(hex_str);
}

void set_value(char * ptr, int len) {
        for (int i=0; i<len; i++) {
          ptr[i] = 'a';
        }
}

#define MAXBLOCKSIZE_PKCS7 128

int pkcs7_pad(char *buff, size_t blocksize, size_t startpoint) {
	char padbyte;
	int  i;

	if((buff == NULL) || (blocksize > MAXBLOCKSIZE_PKCS7)) {
    printf("invalid pad arg!\n");
    return -1;
	}
	padbyte = blocksize - startpoint % blocksize;
	if(padbyte == 0) padbyte = blocksize;

	for(i = 0; i < padbyte; i++) buff[startpoint + i] = padbyte;
	return padbyte;
}

int pkcs7_unpad(char *buff, size_t blocksize, size_t buff_size) {
        if(buff_size < blocksize || (buff == NULL) || (blocksize > MAXBLOCKSIZE_PKCS7)) {
                printf("invalid unpad arg!\n");
                return -1;
        }

        char pad = buff[buff_size-1];
        for(int i = 0; i < pad; i++) buff[buff_size - 1 -i] = 0x0;
        printf("pad = %d, buff = %s\n", pad, buff);
        return pad;
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
  printf("pwd %s, len %d; salt %s, len %d\n", key_data, key_data_len, salt, strlen(salt));
  i = PKCS5_PBKDF2_HMAC(key_data, key_data_len, salt, strlen(salt), nrounds, EVP_sha256(), sizeof(key), key);
  if (i !=1) {
    printf("PKCS5_PBKDF2_HMAC failed, ret  = %d\n", i);
    return -1;
  }

  // set iv as hardcode "aaa.."
  set_value(iv, 16);

  print_hex_2_string(key, 32, "Key");
  print_hex_2_string(iv, 16, "iv");

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

  //printf("c_len = %d, *len= %d, pad_len = %d\n", c_len, *len, pad_len);
  /* allows reusing of 'e' for multiple encryption cycles */
  EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

  /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
  EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

  printf("c_len = %d after encryption\n", c_len);
  /* update ciphertext with the final remaining bytes */
  EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

  *len = c_len + f_len;
  printf("*len = %d after encryption\n", *len);
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

  pkcs7_unpad(plaintext, 16, *len);
  *len = p_len + f_len;
  return plaintext;
}

int main(int argc, char **argv)
{

  if (argc <= 1) {
      printf("Please set key_data as argument!\n");
      return -1;
  }
  /* "opaque" encryption, decryption ctx structures that libcrypto uses to record
     status of enc/dec operations */
  EVP_CIPHER_CTX* en = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX* de = EVP_CIPHER_CTX_new();

  /* 8 bytes to salt the key_data during key generation. This is an example of
     compiled in salt. We just read the bit pattern created by these two 4 byte 
     integers on the stack as 64 bits of contigous salt material - 
     ofcourse this only works if sizeof(int) >= 4 */
  unsigned char salt[] = {'a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a', 0};
  unsigned char *key_data;
  int key_data_len, i;
  char *input[] = {"hello", "test@user:pwddddddddddddddddd","0123456789abcde", "0123456789abcdef", NULL};

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
    olen = len = strlen(input[i]);
    
    ciphertext = aes_encrypt(en, (unsigned char *)input[i], &len);
    print_hex_2_string(ciphertext, strlen(ciphertext), "OK: ciphertext");
    plaintext = (char *)aes_decrypt(de, ciphertext, &len);

    if (strncmp(plaintext, input[i], olen)) 
      printf("FAIL: enc/dec failed for \"%s\", plaintext = \"%s\"\n", input[i], plaintext);
    else 
      printf("OK: enc/dec ok for \"%s\"\n", plaintext);
    
    free(ciphertext);
    free(plaintext);
  }

  EVP_CIPHER_CTX_free(en);
  EVP_CIPHER_CTX_free(de);

  return 0;
}
