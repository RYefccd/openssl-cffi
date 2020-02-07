import cffi

_FFI = cffi.FFI()
_FFI.cdef("""

int sm2_encrypt_ffi(
	const char *d, const char *xP, const char *yP,
	const unsigned char *in, char *out);

int sm2_decrypt_ffi(
	const char *d, const char *xP, const char *yP,
	const unsigned char *in, int inlen, char *out);

""")


_C = _FFI.verify("""
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/evp.h>
# include <openssl/rand.h>
# include <openssl/engine.h>
# include <openssl/sm2.h>


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


size_t bin2hex(const unsigned char *bin, size_t len, char *out)
{
	size_t  i;

	if (bin == NULL || len == 0)
		return 0;

	for (i=0; i<len; i++) {
		out[i*2]   = "0123456789ABCDEF"[bin[i] >> 4];
		out[i*2+1] = "0123456789ABCDEF"[bin[i] & 0x0F];
	}
	out[len*2] = '\\0';

	return len*2;
}


size_t gee_str_len(const unsigned char *s)
{
        size_t i = 0;
        while (s[i++]!='\\0');
        return i;
}

int sm2_encrypt_ffi(
	const char *d, const char *xP, const char *yP,
	const unsigned char *in, char *out)
{

	int ret = 0;
	EC_KEY *pub_key = NULL;
        EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
        unsigned char cbuf[256]={0};

        size_t clen, hexlen;
        size_t inlen = gee_str_len(in);

	if (!(pub_key = new_ec_key(group, NULL, xP, yP))) {
		goto end;
	}

       SM2_encrypt_with_recommended(in, inlen, cbuf, &clen, pub_key);

       hexlen = bin2hex(cbuf, clen, out);
       ret = hexlen;
end:
	ERR_print_errors_fp(stderr);
	EC_KEY_free(pub_key);
        EC_GROUP_free(group);
	return ret;
}


int sm2_decrypt_ffi(
	const char *d, const char *xP, const char *yP,
	const unsigned char *in, size_t inlen, char *out)
{

	int ret = 0;
	EC_KEY *pri_key = NULL;
        size_t outlen;
        EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
        long blen;

        unsigned char *bin_buf= NULL;
        bin_buf = OPENSSL_hexstr2buf((const char *)in, &blen);

	if (!(pri_key = new_ec_key(group, d, xP, yP))) {
		goto end;
	}

       SM2_decrypt_with_recommended(bin_buf, blen, (unsigned char *)out, &outlen, pri_key);
       ret = outlen;
end:
	ERR_print_errors_fp(stderr);
	EC_KEY_free(pri_key);
        EC_GROUP_free(group);
        OPENSSL_free(bin_buf);
	return ret;
}

""", 
include_dirs=["/usr/local/include/"],
libraries=["crypto"], 
library_dirs=["/usr/local/lib/"], 
extra_compile_args=['-Wno-deprecated-declarations'])


d = b"42c37b287a1c218d76112208cdbc4a5fc17dd0d2ef76ca06df63e652e4e660c6"
xP= b"bbfbc5430dab854342462de4af7da4daa0b3613552c09c4c8d5b5c9e1eabb298"
yP= b"410bceebd0e9171229621e1f2af59cab715079720009d6190a106aab76386cac" 

d_bytes  = d  # bytes.fromhex(d)
xP_bytes = xP # bytes.fromhex(xP)
yP_bytes = yP # bytes.fromhex(yP)

def sm2_encrypt_cffi(data):
    inbuf = data.encode()
#    key_bytes = key.encode()
    datalen = len(inbuf)
    out = _FFI.new("unsigned char[%s]" % (datalen+256))
    num = _C.sm2_encrypt_ffi(d_bytes, xP_bytes, yP_bytes, inbuf, out)
    print("encrypt buf len:",num)
    ffi_bytes = _FFI.string(out, num)
    #print("ffi_ecb_encrypt:", ffi_bytes)
    return ffi_bytes

def sm2_decrypt_cffi(data):
    datalen = len(data)
    out = _FFI.new("unsigned char[%s]" % (datalen))
    num = _C.sm2_decrypt_ffi(d_bytes, xP_bytes, yP_bytes, data, datalen, out)
    ffi_bytes = _FFI.string(out, num)
    return ffi_bytes



data = "0123456789abcdef"
cb = sm2_encrypt_cffi(data)
print("cipher bytes:", cb)
print(len(cb))
msg = sm2_decrypt_cffi(cb)
print("msg:", msg)
