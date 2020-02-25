#include <stdio.h>
#include <string.h>
#include <stdlib.h>

# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/evp.h>
# include <openssl/rand.h>
# include <openssl/engine.h>
# include <openssl/sm2.h>


# define VERBOSE 1


// later will remove start

RAND_METHOD fake_rand;
const RAND_METHOD *old_rand;

static const char rnd_seed[] =
	"string to make the random number generator think it has entropy";
static const char *rnd_number = NULL;

static int fbytes(unsigned char *buf, int num)
{
	int ret = 0;
	BIGNUM *bn = NULL;

	if (!BN_hex2bn(&bn, rnd_number)) {
		goto end;
	}
	if (BN_num_bytes(bn) > num) {
		goto end;
	}
	memset(buf, 0, num);
	if (!BN_bn2bin(bn, buf + num - BN_num_bytes(bn))) {
		goto end;
	}
	ret = 1;
end:
	BN_free(bn);
	return ret;
}


static int change_rand(const char *hex)
{
	if (!(old_rand = RAND_get_rand_method())) {
		return 0;
	}

	fake_rand.seed		= old_rand->seed;
	fake_rand.cleanup	= old_rand->cleanup;
	fake_rand.add		= old_rand->add;
	fake_rand.status	= old_rand->status;
	fake_rand.bytes		= fbytes;
	fake_rand.pseudorand	= old_rand->bytes;

	if (!RAND_set_rand_method(&fake_rand)) {
		return 0;
	}

	rnd_number = hex;
	return 1;
}


static int restore_rand(void)
{
	rnd_number = NULL;
	if (!RAND_set_rand_method(old_rand))
		return 0;
	else	return 1;
}


// later will remove end


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


unsigned char* hex2bin(const char* hexstr, size_t* size)
{
    size_t hexstrLen = strlen(hexstr);
    size_t bytesLen = hexstrLen / 2;

    unsigned char* bytes = (unsigned char*) malloc(bytesLen+1);

    int count = 0;
    const char* pos = hexstr;

    for(count = 0; count < bytesLen; count++) {
        sscanf(pos, "%2hhx", &bytes[count]);
        pos += 2;
    }

    if( size != NULL )
        *size = bytesLen;

    return bytes;
}


static EC_KEY *new_ec_key(const EC_GROUP *group,
	const char *sk, const char *xP, const char *yP)
{
	int ok = 0;
	EC_KEY *ec_key = NULL;
	BIGNUM *d = NULL;
	BIGNUM *x = NULL;
	BIGNUM *y = NULL;

	OPENSSL_assert(group);
	OPENSSL_assert(xP);
	OPENSSL_assert(yP);

	if (!(ec_key = EC_KEY_new())) {
		goto end;
	}
	if (!EC_KEY_set_group(ec_key, group)) {
		goto end;
	}

	if (sk) {
		if (!BN_hex2bn(&d, sk)) {
			goto end;
		}
		if (!EC_KEY_set_private_key(ec_key, d)) {
			goto end;
		}
	}

	if (xP && yP) {
		if (!BN_hex2bn(&x, xP)) {
			goto end;
		}
		if (!BN_hex2bn(&y, yP)) {
			goto end;
		}
		if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
                        printf("EC_KEY_set_public_key_affine_coordinates failure  \n");
			goto end;
		}
	}

	ok = 1;
end:
	if (d) BN_free(d);
	if (x) BN_free(x);
	if (y) BN_free(y);
	if (!ok && ec_key) {
		ERR_print_errors_fp(stderr);
		EC_KEY_free(ec_key);
		ec_key = NULL;
	}
	return ec_key;
}



static int sm2_demo_with_recommended(const EC_GROUP *group,
	const char *d, const char *xP, const char *yP,
	const char *M)
{
	int ret = 0;
	EC_KEY *pub_key = NULL;
	EC_KEY *pri_key = NULL;

        unsigned char c_buf[512] = {0};
        size_t c_len;
        unsigned char m_buf[256] = {0};
        size_t m_len;
  
	/* sm2 pub_key */
	if (!(pub_key = new_ec_key(group, NULL, xP, yP))) {
                printf("new_ec_key error \n");
		goto end;
	}
         
	/* sm2 pri_key */
	if (!(pri_key = new_ec_key(group, d, xP, yP))) {
		goto end;
	}

change_rand("4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F");
       //SM2_encrypt_with_recommended(in,inlen,out,outlen,ec_key)
       SM2_encrypt_with_recommended((unsigned char *)M, strlen(M), c_buf, &c_len, pub_key);
       printf("SM2_encrypt_with_recommended:\n");
       printf("encrypt buf len:%zu \n", c_len);
       PrintData(c_buf, c_len);

       //SM2_decrypt_with_recommended(in,inlen,out,outlen,ec_key)
       SM2_decrypt_with_recommended(c_buf, c_len, m_buf, &m_len, pri_key);

       printf("origin  message: %s \n", M);
       printf("decrypt message: %s \n", m_buf);
       ret = 1;

end:
	ERR_print_errors_fp(stderr);
	restore_rand();
	EC_KEY_free(pub_key);
	EC_KEY_free(pri_key);

	return ret;
}




// hex2bin demo
void test_hex2bin_demo()
{
printf("\n--test_hex2bin_demo ---\n");

char *www="6162636465";
size_t dsb_len;
char *dsb = hex2bin(www, &dsb_len);
dsb[dsb_len]='\0';
printf("hex2bin(6162636465):%s \n", dsb);

char *rrr="ab0c";
printf("rrr len:%lu \n", strlen(rrr));
}


int main(int argc, char **argv)
{
	int err = 0;
        EC_GROUP *sm2p256v1 = EC_GROUP_new_by_curve_name(NID_sm2p256v1);


//	RAND_seed(rnd_seed, sizeof(rnd_seed));
	if (!sm2p256v1) {
		err++;
		goto end;
	}



printf("\n-------sm2_demo_with_recommended start-------------\n");
char * MMM="0123456789abcdef";  //"fccdjny";
	if (!sm2_demo_with_recommended(
		sm2p256v1,
                "42c37b287a1c218d76112208cdbc4a5fc17dd0d2ef76ca06df63e652e4e660c6",  //key d
                "bbfbc5430dab854342462de4af7da4daa0b3613552c09c4c8d5b5c9e1eabb298",  //pub xP
                "410bceebd0e9171229621e1f2af59cab715079720009d6190a106aab76386cac",  //pub yP  fccdjny  0123456789abcdef
		MMM)) {
		printf("sm2p256v1 enc failed\n");
		err++;
	} else {
		printf("sm2p256v1 enc passed\n");

	}

end:

        EC_GROUP_free(sm2p256v1);
        exit(err);
}

