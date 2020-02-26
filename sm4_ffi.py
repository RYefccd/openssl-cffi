import cffi

_FFI = cffi.FFI()
_FFI.cdef("""
int encrypt_sm4_cbc(unsigned char * input, int inLen, unsigned char * output,
                unsigned char * key, unsigned char * iv);

int decrypt_sm4_cbc(unsigned char * input, int inLen, unsigned char * output,
                unsigned char * key, unsigned char * iv);
""")


_C = _FFI.verify("""
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

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

    return final_outlen;
}

""", 
include_dirs=["/usr/local/include/"],
libraries=["crypto"], 
library_dirs=["/usr/local/lib/", "/usr/local/lib64/"],
extra_link_args=["-Wl,-rpath=/usr/local/lib/", "-Wl,-rpath=/usr/local/lib64/"],
extra_compile_args=["-Wno-deprecated-declarations"])


def sm4_encrypt_cffi(data, key, iv):
    """
    data str or bytes:
    key  bytes:
    iv   bytes:
    return bytes
    """
    if type(data) == str:
        inbuf = data.encode()
    else:
        inbuf = data
    inlen = len(inbuf)
    # sm4 是块加密算法, 加密的长度要比明文长
    out = _FFI.new("char[%s]" % (inlen + 16))  #  _FFI.new("char[%s]" % (inlen + 16 - len(inbuf) % 16))
    num = _C.encrypt_sm4_cbc(inbuf, inlen, out, key, iv)
    enc_bytes = _FFI.unpack(out, num)
    return enc_bytes


def sm4_decrypt_cffi(data, key, iv):
    """
    data bytes:
    key  bytes:
    iv   bytes:
    return bytes
    """
    enclen = len(data)
    out = _FFI.new("char[%s]" % (enclen + 16))
    num = _C.decrypt_sm4_cbc(data, enclen, out, key, iv)
    msg_bytes = _FFI.unpack(out, num)
    return msg_bytes


##### test case 1(gmssl sms4)

key = b'f' * 16
iv  = b'\x00' * 16
data = b"fccdjny" * 3

# data = b"fccdj \x00abc"
enc_bytes = sm4_encrypt_cffi(data, key, iv)
# print("enc_bytes:", enc_bytes)

msg = sm4_decrypt_cffi(enc_bytes, key, iv)

assert msg == data
print("origin  msg:", data)
print("encrypt txt:", enc_bytes)
print("decrypt txt:", msg)

#from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
#crypt_sm4 = CryptSM4()
#crypt_sm4.set_key(key, SM4_DECRYPT)
#python_decrypt_msg = crypt_sm4.crypt_cbc(iv , enc_bytes)
#assert python_decrypt_msg == data, "gmssl encrypt, python sm4 decrypt error!" 
#
#
###### test case 2 (pythom sm4)
#from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
#crypt_sm4 = CryptSM4()
#crypt_sm4.set_key(key, SM4_ENCRYPT)
#encrypt_value = crypt_sm4.crypt_cbc(iv , data)
## print("pythom sm4 enc bytes:", encrypt_value)
#assert encrypt_value == enc_bytes
#crypt_sm4.set_key(key, SM4_DECRYPT)
#decrypt_value = crypt_sm4.crypt_cbc(iv , encrypt_value)
#assert data == decrypt_value




