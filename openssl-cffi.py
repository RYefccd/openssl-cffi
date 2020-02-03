import subprocess
import tempfile

def _encrypt_decrypt_ecb_shell(data, key, decrypt):
    infile = tempfile.mktemp()
    with open(infile, "wb") as f:
        f.write(data)
    outfile = tempfile.mktemp()
    cmd = ['openssl', 'enc']
    if decrypt:
        cmd.append('-d')
    cmd += ['-aes-128-ecb',
            '-nopad',
            '-in', infile,
            '-out', outfile,
            '-K', key.encode().hex()] # key.encode("hex")
    #print(" ".join(cmd))
    subprocess.Popen(cmd).wait()
    with open(outfile, "rb") as f:
        result = f.read()
    return result

def encrypt_ecb_shell(data, key):
    if type(data) == str:
       data = data.encode()
    return _encrypt_decrypt_ecb_shell(data, key, False)  # data is bytes

def decrypt_ecb_shell(data, key):
    if type(data) == str:
       data = data.encode()
    b =_encrypt_decrypt_ecb_shell(data, key, True)   # data is bytes
    return b.decode()

import cffi

_FFI = cffi.FFI()
_FFI.cdef("""
int encrypt_ecb(unsigned char * input, unsigned char * output,
                unsigned char * key, int len);

int decrypt_ecb(unsigned char * input, unsigned char * output,
                unsigned char * key, int len);
""")

# set_source
# verify
_C = _FFI.verify("""
#include <openssl/evp.h>

int encrypt_ecb(unsigned char * input, unsigned char * output,
                unsigned char * key, int len)
{
  int outlen, finallen;
/*
  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);
  EVP_EncryptInit(&ctx, EVP_aes_128_ecb(), key, 0);
  EVP_CIPHER_CTX_set_padding(&ctx, 0);
  if(!EVP_EncryptUpdate(&ctx, output, &outlen, input, len)) return 0;
  if(!EVP_EncryptFinal(&ctx, output + outlen, &finallen)) return 0;
  EVP_CIPHER_CTX_cleanup(&ctx);
*/
  EVP_CIPHER_CTX *ctx;
  ctx=EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);
  EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, 0);
  EVP_CIPHER_CTX_set_padding(ctx, 0);
  if(!EVP_EncryptUpdate(ctx, output, &outlen, input, len)) return 0;
  if(!EVP_EncryptFinal(ctx, output + outlen, &finallen)) return 0;
  EVP_CIPHER_CTX_cleanup(ctx);
  return outlen + finallen;
}

int decrypt_ecb(unsigned char * input, unsigned char * output,
                unsigned char * key, int len)
{
  int outlen, finallen;
/*
  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);
  EVP_DecryptInit(&ctx, EVP_aes_128_ecb(), key, 0);
  EVP_CIPHER_CTX_set_padding(&ctx, 0);
  if(!EVP_DecryptUpdate(&ctx, output, &outlen, input, len)) return 0;
  if(!EVP_DecryptFinal(&ctx, output + outlen, &finallen)) return 0;
  EVP_CIPHER_CTX_cleanup(&ctx);
*/
  EVP_CIPHER_CTX *ctx;
  ctx=EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(ctx);
  EVP_DecryptInit(ctx, EVP_aes_128_ecb(), key, 0);
  EVP_CIPHER_CTX_set_padding(ctx, 0);
  if(!EVP_DecryptUpdate(ctx, output, &outlen, input, len)) return 0;
  if(!EVP_DecryptFinal(ctx, output + outlen, &finallen)) return 0;
  EVP_CIPHER_CTX_cleanup(ctx);

  return outlen + finallen;
}
""", 
include_dirs=["/usr/local/include/"],
libraries=["crypto"], 
library_dirs=["/usr/local/lib/"], 
extra_compile_args=['-Wno-deprecated-declarations'])

def encrypt_ecb_cffi(data, key):
    data = data.encode()
    key_bytes = key.encode()
    datalen = len(data)
    out = _FFI.new("char[%s]" % (datalen))
    num = _C.encrypt_ecb(data, out, key_bytes, datalen)
    ffi_bytes = _FFI.string(out, num)
    #print("ffi_ecb_encrypt:", ffi_bytes)
    return ffi_bytes

def decrypt_ecb_cffi(data, key):
    #print("decrypt data:", data)
    key_bytes = key.encode()
    datalen = len(data)
    out = _FFI.new("char[%s]" % (datalen))
    num = _C.decrypt_ecb(data, out, key_bytes, datalen)
    ffi_bytes = _FFI.string(out, num)
    ffi_str = ffi_bytes.decode()
    #print("ffi_ecb_decrypt:", ffi_str)
    return ffi_str

data = "Some data that has multiple sixteen byte blocks."
key =  "needstobesixteen"

print("Verifying encryption...")
assert(decrypt_ecb_shell(encrypt_ecb_shell(data, key), key) == data)
assert(decrypt_ecb_cffi(encrypt_ecb_cffi(data, key), key) == data)
assert(decrypt_ecb_cffi(encrypt_ecb_shell(data, key), key) == data)
assert(decrypt_ecb_shell(encrypt_ecb_cffi(data, key), key) == data)
print("VERIFIED")

import time

print("Profiling shell version...")

start = time.time()

for i in range(100):
    decrypt_ecb_shell(encrypt_ecb_shell(data, key), key)

shell = time.time() - start
print("SHELL:", shell)

print("Profiling cffi version...")
start = time.time()

for i in range(100):
    decrypt_ecb_cffi(encrypt_ecb_cffi(data, key), key)

cffi = time.time() - start
print("CFFI:", cffi)

print()
print("Using cffi is roughly %dx faster than shelling out." % (shell / cffi))
