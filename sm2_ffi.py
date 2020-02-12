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
        return i - 1 ;
//        return strlen((const char *)s);
}

int sm2_encrypt_ffi(
	const char *d, const char *xP, const char *yP,
	const unsigned char *in, char *out)
{

	int ret = 0;
	EC_KEY *pub_key = NULL;
        EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
//      unsigned char cbuf[4096]={0};

        size_t hexlen;
        size_t inlen = gee_str_len(in);
        size_t clen = inlen + 126;
        unsigned char cbuf[clen];

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
    print("datalen:", datalen)
    out = _FFI.new("unsigned char[%s]" % (datalen * 2 + 126 * 2))
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


from sm2_tools import decode_sm2_asn1_ciphter_txt,encode_sm2_asn1_ciphter_txt

data = "0123456789abcdef"
data = "fccdjny"
data = "0123456789abcdef"
cb = sm2_encrypt_cffi(data)
print(len(cb))
msg = sm2_decrypt_cffi(cb)
print("msg:", msg)
print("len(msg):", len(msg))
print("c1c3c2:")
print(decode_sm2_asn1_ciphter_txt(bytes.fromhex(cb.decode("iso-8859-1"))).hex())


print("------------------------------")
print("python gmssl encode bytes:")
cb = b'306f0220dda0ba8c746e48d04c6dedaf896e82382bfc9f70345ac3f5147d9592ac0e27330220e3d1c9c763a1d48a8d8c192b88aa3002649d9c04b458f05031ff4d301c397e9604208a257eb47b84a22c94f5a847d8d25f9b1c9f76fb9b333a6f270cf2f9a5a945420407290d2ddaa7b5bd'
print("cipher bytes:", cb)
print(len(cb))
msg = sm2_decrypt_cffi(cb)
print("msg:", msg)
print("c1c3c2:")
print(decode_sm2_asn1_ciphter_txt(bytes.fromhex(cb.decode("iso-8859-1"))).hex())

print("--------xuwei decode----------------------")
data ="3444363d553e7859a36bd3619156286fef8eea92b65724bcf24ca83b9cfdfa3d9d6e9aaf8b0659b0b549e3d484295c90d0df1a403018104f5d08b73ddd9a6a0b6b0ef0945c55039d967d9ef7d6f10591e33b4bbf08c5e13a2bfda9b2498a3bdc77bb704caf8b6f2af0b11a280f58e2611b0221b348d0fe6b95844d44ace022a6fe8974642a816d69944d846f53c5afb5240f9e58fa04e31d662f3b46816f966f4da218d2bf1f10c446f5fa6ab30cbca687dc1ce2847d23887ff62acfc74219b029f31670551014e040d90fd0d1ef7be17dfd8ea1fa05c60b1873b2b6628e6f8e8feea888eb32b79556d92a55cb1c5ee050eff00deaa50d218793d261251e328a42d2289c516b9a5ec506be5efd1b4a073cf5cfd8433cc25c7c3dd5a294cd095e4f726c38201cf18dd78ff900e45613b8a937eb74720ba91d96ccb9d841fb04ca9caedd1e47becc266376f814a5314a939f7198c78f92de0dc771820bd22ad24335aec65d539ea2d480f52ef7f933f5548155874fe43a6bf0a72179feb1c18aeafb63907f3a5c9fbbeee12e1e4d33c06e635d335588bbc5fb831c3392a6a35b2ab56e67f47b769803233df455fd788f50c9814797522b6aeaed34984c2503bf07eddc66152bc9a1203914f40d637a90cd8931ad4ff3dd85ccc5c71dd701879c6b9f990d3cbc1959cb834e32310c4d0ff09aa48fa3b772eb44376a833ed1e95683"
asrtxt = encode_sm2_asn1_ciphter_txt(data).hex().encode()
print("xw asr txt:", asrtxt)
msg = sm2_decrypt_cffi(asrtxt)
print("xw msg:", msg)



