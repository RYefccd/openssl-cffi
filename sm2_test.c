#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//#include "../e_os.h"

# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/evp.h>
# include <openssl/rand.h>
# include <openssl/engine.h>
# include <openssl/sm2.h>
# include "sm2_lcl.h"
//# include "../crypto/sm2/sm2_lcl.h"


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


static int sm2_demo_test_guoaihua_message(const EC_GROUP *group, const EVP_MD *md,
	const char *d, const char *xP, const char *yP,
	const char *M)
{

	int ret = 0;
	EC_KEY *pub_key = NULL;
	EC_KEY *pri_key = NULL;
	SM2CiphertextValue *cv = NULL;
	long tlen;
	unsigned char mbuf[128] = {0};
	unsigned char cbuf[sizeof(mbuf) + 256] = {0};
	size_t mlen, clen;
	unsigned char *p;
/*
	if (!(pub_key = new_ec_key(group, NULL, xP, yP))) {
                printf("new_ec_key error \n");
		goto end;
	}
*/
	if (!(pri_key = new_ec_key(group, d, xP, yP))) {
		goto end;
	}


printf("------------test guoaihua message----\n");
//  test gah  message
const unsigned char *c1c2c3 =
"04BCB6E0C13BC6EFA4612D86C6751ACAADB085FDCBCAFB78904467F05E5241EE8B8493DE7E4EA2BBB7F482E169F296E35BFB16512892833C62581A603B073996BDF500F812258A1880EBE64CBDC184F674603305FF853BCBA60C766AE3F8823B881ADD4DB974EF94"; 
//"0453c8ac924d4ef128fdf368c7dd6e887e523dc9752f973c59e064b8517d2f7b1ad4b8148ae27cca146cb9fed81a99a84c092f0bda3ebe2fc39fb177468528d18417823d8334537accc4cbbb1f971ab8107de5a9a5c53f1d568ae632be867066ab8b7f8e7f69ec064f4a678ac662411bf5";
long c1c2c3_len;
size_t my_cv_len;
unsigned char mybuf[128] = {0};


unsigned char *wh_test_buf = OPENSSL_hexstr2buf(c1c2c3, &c1c2c3_len);
const unsigned char **test_buf= (const unsigned char **)&wh_test_buf;
printf("gah cipher buf:%s \n\n", wh_test_buf);
//size_t tttttmp_clen;
char *tttttmp_hexstr = OPENSSL_buf2hexstr(wh_test_buf, c1c2c3_len);
printf("gah cipher hexstr: %s \n", tttttmp_hexstr);

SM2CiphertextValue *my_cv = o2i_SM2CiphertextValue(group, md, NULL, test_buf, c1c2c3_len);
//SM2CiphertextValue *o2i_SM2CiphertextValue(const EC_GROUP *group,
//        const EVP_MD *md, SM2CiphertextValue **pout,
//        const unsigned char **pin, long len)

	if (!SM2_do_decrypt(md, my_cv, NULL, &my_cv_len, pri_key)) {// get decrpt length: mlen
		goto end;
	}

	if (!SM2_do_decrypt(md, my_cv, mybuf, &my_cv_len, pri_key)) {
		goto end;
	}

printf("decrypt gah message: %s \n", mybuf);

SM2CiphertextValue_free(my_cv);

end:
	ERR_print_errors_fp(stderr);
	restore_rand();
	EC_KEY_free(pub_key);
	EC_KEY_free(pri_key);
	SM2CiphertextValue_free(cv);
	return ret;

}


static int sm2_demo_with_do_XXX(const EC_GROUP *group, const EVP_MD *md,
	const char *d, const char *xP, const char *yP,
	const char *M)
{
	int ret = 0;
	EC_KEY *pub_key = NULL;
	EC_KEY *pri_key = NULL;
	SM2CiphertextValue *cv = NULL;
	long tlen;
	unsigned char mbuf[128] = {0};
	unsigned char cbuf[sizeof(mbuf) + 256] = {0};
	size_t mlen, clen;
	unsigned char *p;

        printf("test encrypt \n");
        printf("M    : %s \n", M);
        printf("M len: %zu bytes \n", strlen(M));
	/* test encrypt */
	if (!(pub_key = new_ec_key(group, NULL, xP, yP))) {
                printf("new_ec_key error \n");
		goto end;
	}


//	change_rand("01");
	if (!(cv = SM2_do_encrypt(md, (unsigned char *)M, strlen(M), pub_key))) {
                printf("SM2_do_encrypt error");
		goto end;
	}

        printf("use SM2_do_encrypt \n");

	p = cbuf;
	if ((clen = i2o_SM2CiphertextValue(group, cv, &p)) <= 0) {
		goto end;
	}

        printf("encrypt message length:%zu \n", clen);
        printf("04(1 Byte) C1(64 Byte) C2(%lu Byte) C3(32 Byte) == %zu  \n", strlen(M), clen);
        printf("encrypt message: \n");
        PrintData(cbuf, clen);                                 // print hex(1)
        char *cipher_hexstr = OPENSSL_buf2hexstr(cbuf, clen);  // print hex(2)
        printf("cipher_hexstr: %s \n", cipher_hexstr);
         
	/* test decrypt */
	if (!(pri_key = new_ec_key(group, d, xP, yP))) {
		goto end;
	}

//	mlen = sizeof(mbuf);
	if (!SM2_do_decrypt(md, cv, NULL, &mlen, pri_key)) {// get decrpt length: mlen
		goto end;
	}

	if (!SM2_do_decrypt(md, cv, mbuf, &mlen, pri_key)) {
		goto end;
	}

        printf("origin  message: %s \n", M);
        printf("decrypt message: %s \n", mbuf);
	ret = 1;

end:
	ERR_print_errors_fp(stderr);
	restore_rand();
	EC_KEY_free(pub_key);
	EC_KEY_free(pri_key);
	SM2CiphertextValue_free(cv);
	return ret;
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


//      don't know how to link SM2_ciphertext_size symbols
        int inlen = strlen(M);
        int in_c_len;
	if (!(in_c_len = SM2_ciphertext_size(pub_key, inlen))) {
		SM2err(SM2_F_SM2_ENCRYPT, ERR_R_SM2_LIB);
		return 0;
	}
        printf("origin message len: %d\n", inlen);
        printf("SM2_ciphertext_size len: %d\n\n", in_c_len);

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


int sm2_decrypt(const EC_GROUP *group,
	const char *d, const char *xP, const char *yP,
	const char *CM, size_t CM_len)
{
	int ret = 0;
//	EC_KEY *pub_key = NULL;
	EC_KEY *pri_key = NULL;


       unsigned char m_buf[384] = {0};
       size_t m_len;

	/* sm2 pri_key */
	if (!(pri_key = new_ec_key(group, d, xP, yP))) {
		goto end;
	}

        //SM2_decrypt_with_recommended(in,inlen,out,outlen,ec_key)
        SM2_decrypt_with_recommended(CM, CM_len, m_buf, &m_len, pri_key);

        //printf("origin  message: %s \n", M);
        printf("decrypt message: %s \n", m_buf);
        PrintData(m_buf, m_len);
        ret = 1;
end:
	ERR_print_errors_fp(stderr);
	restore_rand();
	//EC_KEY_free(pub_key);
	EC_KEY_free(pri_key);
	return ret;
}


int sm2_encrypt(const EC_GROUP *group,
	const char *d, const char *xP, const char *yP,
	const char *M)
{
	int ret = 0;
	EC_KEY *pub_key = NULL;
//	EC_KEY *pri_key = NULL;


        unsigned char c_buf[384] = {0};
        size_t c_len;

	/* sm2 pub_key */
	if (!(pub_key = new_ec_key(group, NULL, xP, yP))) {
                printf("new_ec_key error \n");
		goto end;
	}

        //SM2_encrypt_with_recommended(in,inlen,out,outlen,ec_key)
        SM2_encrypt_with_recommended((unsigned char *)M, strlen(M), c_buf, &c_len, pub_key);
        printf("SM2_encrypt_with_recommended:\n");
        printf("encrypt buf len:%zu \n", c_len);
        PrintData(c_buf, c_len);
        ret = 1;
end:
	ERR_print_errors_fp(stderr);
	restore_rand();
	EC_KEY_free(pub_key);
	//EC_KEY_free(pri_key);

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


// test decode demo
void test_decode_not_right(EC_GROUP *sm2p256v1)
{
printf("\n-----front encrypt and decode string not right!----\n\n");

long cjnlen;
unsigned char *cjntmp="3078022053c8ac924d4ef128fdf368c7dd6e887e523dc9752f973c59e064b8517d2f7b1a0220d4b8148ae27cca146cb9fed81a99a84c092f0bda3ebe2fc39fb177468528d18404207de5a9a5c53f1d568ae632be867066ab8b7f8e7f69ec064f4a678ac662411bf5041017823d8334537accc4cbbb1f971ab810";
//"3078022053c8ac924d4ef128fdf368c7dd6e887e523dc9752f973c59e064b8517d2f7b1a0220d4b8148ae27cca146cb9fed81a99a84c092f0bda3ebe2fc39fb177468528d18404207de5a9a5c53f1d568ae632be867066ab8b7f8e7f69ec064f4a678ac662411bf5041017823d8334537accc4cbbb1f971ab810";

unsigned char *test_buf = NULL;

test_buf = OPENSSL_hexstr2buf(cjntmp, &cjnlen);
//test_buf = hex2bin(cjntmp, &cjnlen);

printf("ciphter msg:%s\n", cjntmp);
printf("hex bytes: %li \n\n", cjnlen);
PrintData(test_buf, cjnlen);

sm2_decrypt(
		sm2p256v1,
                "42c37b287a1c218d76112208cdbc4a5fc17dd0d2ef76ca06df63e652e4e660c6",  //key d
                "bbfbc5430dab854342462de4af7da4daa0b3613552c09c4c8d5b5c9e1eabb298",  //pub xP
                "410bceebd0e9171229621e1f2af59cab715079720009d6190a106aab76386cac",  //pub yP
		test_buf, cjnlen);
OPENSSL_free(test_buf);

}

// test demo
void test_decode_right(EC_GROUP *sm2p256v1)
{
printf("\n-----test_decode_right!----\n\n");


long cb_len;

unsigned char *cipher_hexstr=
"30700220"
"8BC7D7F0FE63E64BBF6FD3AADE379EF4052D8520C7A9E504D6BCF7A24747C8DA"
"0223"
"000000C61699D570E5294C21A5B1E586CE79052C6381CD16875774718F8D26BE6F6BE0"
"0420"
"D39660275D7F3322587C6787F8B4748B07E9BBC106D6E58B3E7261B8260972C3"
"0405"
"AD060C48A7";

unsigned char *c_buf = OPENSSL_hexstr2buf(cipher_hexstr, &cb_len);
printf("ciphter msg:%s\n", cipher_hexstr);
printf("hex bytes: %li \n\n", cb_len);
PrintData(c_buf, cb_len);
sm2_decrypt(
		sm2p256v1,
                "42c37b287a1c218d76112208cdbc4a5fc17dd0d2ef76ca06df63e652e4e660c6",  //key d
                "bbfbc5430dab854342462de4af7da4daa0b3613552c09c4c8d5b5c9e1eabb298",  //pub xP
                "410bceebd0e9171229621e1f2af59cab715079720009d6190a106aab76386cac",  //pub yP
		c_buf, cb_len);

OPENSSL_free(c_buf);

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


	if (!sm2_demo_with_do_XXX(
		sm2p256v1, EVP_sm3(),
                "42c37b287a1c218d76112208cdbc4a5fc17dd0d2ef76ca06df63e652e4e660c6",  //key d
                "bbfbc5430dab854342462de4af7da4daa0b3613552c09c4c8d5b5c9e1eabb298",  //pub xP
                "410bceebd0e9171229621e1f2af59cab715079720009d6190a106aab76386cac",  //pub yP
//              "78379E70A2DAF175A088657CE8B8E1D0C6A77A89EB41799FAB25521D79F2BCEE",  //key d
//              "7121B1A3C2AF28055B2B64B4E28C8826CF676EC4B5B68E00CA452DC73DA0B166",  //pub xP
//              "9804A588149E99F820361C81D3F944F3BBAC1722F2B3F78CF9AE0AEC403A2B9D",  //pub yP
		"fccdjny")) {
		printf("sm2p256v1 enc failed\n");
		err++;
	} else {
		printf("sm2p256v1 enc passed\n");
	}



printf("\n-------sm2_demo_with_recommended start-------------\n");
char * MMM="fccdjny";
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

test_decode_not_right(sm2p256v1);

test_decode_right(sm2p256v1);

test_hex2bin_demo();

/*
sm2_demo_test_guoaihua_message(
		sm2p256v1, EVP_sm3(),
                "42c37b287a1c218d76112208cdbc4a5fc17dd0d2ef76ca06df63e652e4e660c6",  //key d
                "bbfbc5430dab854342462de4af7da4daa0b3613552c09c4c8d5b5c9e1eabb298",  //pub xP
                "410bceebd0e9171229621e1f2af59cab715079720009d6190a106aab76386cac",  //pub yP
		"fccdjny");

*/

end:

        EC_GROUP_free(sm2p256v1);
        exit(err);
}

