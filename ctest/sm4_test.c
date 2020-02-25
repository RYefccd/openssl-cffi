#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

void PrintData(uint8_t* data, uint32_t len)
{
	for (uint32_t i = 0; i < len; i++)
	{
		printf("%02X ", data[i]);
		if ((i % 16) == 15 && (i != (len - 1)))
		{
			puts("");
		}
	}
	puts("");

	for (uint32_t i = 0; i < len; i++)
	{
		printf("%02X", data[i]);
	}

puts("");
}

size_t bin2hex(const unsigned char *bin, size_t len, char *out)
{
	size_t  i;

	if (bin == NULL || len == 0)
		return 0;

	for (i=0; i<len; i++) {
		out[i*2]   = "0123456789ABCDEF"[bin[i] >> 4];
		out[i*2+1] = "0123456789ABCDEF"[bin[i] & 0x0F];
	}
	out[len*2] = '\0';

	return len*2;
}


int encrypt_sm4_cbc(unsigned char * input, int inLen, unsigned char * output,
                unsigned char * key, unsigned char * iv)
{

    int outlen, finallen, final_outlen;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    EVP_CipherInit_ex(ctx, EVP_sms4_cbc(), NULL, key, iv, 1);
    if(!EVP_CipherUpdate(ctx, output, &outlen, input, inLen)) return 0;
    if(!EVP_CipherFinal(ctx, output + outlen, &finallen)) return 0;
    EVP_CIPHER_CTX_free(ctx);
    final_outlen = outlen + finallen;
    return final_outlen;
}

int decrypt_sm4_cbc(unsigned char * input, int inLen, unsigned char * output,
                unsigned char * key, unsigned char * iv)
{
    int outlen, finallen, final_outlen;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_sms4_cbc(), NULL, key, iv, 0);
    if(!EVP_CipherUpdate(ctx, output, &outlen, input, inLen)) return 0;
    if(!EVP_CipherFinal(ctx, output+outlen, &finallen));
    EVP_CIPHER_CTX_free(ctx);
    final_outlen = outlen + finallen;
    output[final_outlen] = '\0';

printf("outlen   : %d \n", outlen);
printf("finallen: %d \n", finallen);
printf("decrypt_sm4_cbc : %s \n", output);
printf("decrypt len: %d \n", final_outlen);
PrintData(output, final_outlen);
    return final_outlen;
}

int main()
{

    unsigned char key[16] = {'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f', 'f'};
    unsigned char iv[16] = {0};
    unsigned char *inStr = "fccdj";   //"this is test string";
    int inLen = strlen(inStr);
    int encLen = 0;
    int outlen = 0;
    unsigned char encData[1024];
    unsigned char encData_hex[1024];

    printf("key: %s\n",key);
    printf("iv: %s\n", iv);
    printf("source: %s\n",inStr);
/*
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    //Encrypt
    EVP_CipherInit_ex(ctx, EVP_sms4_cbc(), NULL, key, iv, 1);
    EVP_CipherUpdate(ctx, encData, &outlen, inStr, inLen);
    encLen = outlen;
    EVP_CipherFinal(ctx, encData+outlen, &outlen);
    encLen += outlen;
    EVP_CIPHER_CTX_free(ctx);

    // print to screen
    size_t enc_hex_len = bin2hex(encData, outlen, encData_hex);
    encData_hex[enc_hex_len] = '\0';
    printf("enc_hex: %s \n", encData_hex);

    //Decrypt
    int decLen = 0;
    outlen = 0;
    unsigned char decData[1024];
    EVP_CIPHER_CTX *ctx2;
    ctx2 = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx2, EVP_sms4_cbc(), NULL, key, iv, 0);
    EVP_CipherUpdate(ctx2, decData, &outlen, encData, encLen);
    decLen = outlen;
    EVP_CipherFinal(ctx2, decData+outlen, &outlen);
    decLen += outlen;
    EVP_CIPHER_CTX_free(ctx2);

    decData[decLen] = '\0';
    printf("decrypt: %s\n",decData);
*/

    // use function
    unsigned char encbuf[1024], txtbuf[1024];
    int enclen = encrypt_sm4_cbc(inStr, inLen, encbuf, key, iv);
 //   printf("memcmp(encbuf, encData):%d\n", memcmp((void*)encbuf, (void*)encData, enclen));

    int txtlen = decrypt_sm4_cbc(encbuf, enclen, txtbuf, key, iv);
    printf("memcmp(txtbuf, inStr):%d\n", memcmp((void*)txtbuf, (void*)inStr, txtlen));
    printf("encrypt info: %s \n", encbuf);
    printf("encrypt len : %d \n", enclen);
    printf("decrypt info: %s \n", txtbuf);
    printf("origin len  : %d \n", txtlen);
}






