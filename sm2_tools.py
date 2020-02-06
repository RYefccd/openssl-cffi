def decode_sm2_asn1_ciphter_txt(cm): # decode to c1c3c2 bytes
    if type(cm) == str: 
        tmp = bytes.fromhex(cm) 
    else: 
        tmp = cm 

    print(tmp)
    print(bytes.fromhex("30"))
    assert tmp[0] == bytes.fromhex("30")[0]  # sequence 
    assert tmp[1] == len(tmp[2:])       # length 

    x_start = 2 
    assert tmp[x_start] == bytes.fromhex("02")[0], "asn.1 C1_x tag error"  # next type is interger asn.1 type hex 02, for C1_x 
    x_len = tmp[x_start+1]
    x_end = x_start + 2 + x_len 
    C1_x = tmp[x_end-x_len:x_end] # next 20(hex, real is 32) bytes is C1_x 
    print("c1_x:",C1_x.hex())

    print("x_end:",x_end)
    y_start = x_end
    print(tmp[y_start:y_start+1]) 
    print(tmp[y_start])
    assert tmp[y_start] == bytes.fromhex("02")[0], "asn.1 C1_y tag error"  # next type is interger asn.1 type hex 02, for C1_y 
    y_len = tmp[y_start+1] 
    y_end = y_start + 2 + y_len 
    C1_y = tmp[y_end-y_len:y_end] 
     
    C3_start = y_end
    assert tmp[C3_start] == bytes.fromhex("04")[0], "asn.1 C3 tag error"  # asn.1 type 04(hex) type is bytes 
    C3_len = tmp[C3_start+1] 
    C3_end = C3_start + 2 + C3_len 
    C3 = tmp[C3_end-C3_len:C3_end] 
     
    C2_start = C3_end
    assert tmp[C2_start] == bytes.fromhex("04")[0], "asn.1 C2 tag error"  # asn.1 type 04(hex) type is bytes, C2 is cipher bytes 
    C2_len = tmp[C2_start+1] 
    C2_end = C2_start + 2 + C2_len 
    C2 = tmp[C2_end-C2_len:C2_end] 
    
    # C1_x, C1_y only get 32 bytes
    c1c3c2 = b''.join([C1_x[-32:], C1_y[-32:], C3, C2]) 
    # c1c3c2 = b''.join([C1_x, C1_y, C3, C2]) 
    return c1c3c2


def encode_sm2_asn1_ciphter_txt(c1c3c2): # c1c3c2 encode to sm2_asn1_ciphter bytes
    if type(c1c3c2) == str: 
        tmp = bytes.fromhex(c1c3c2) 
    else: 
        tmp = c1c3c2

    C1 = tmp[:64]
    C3 = tmp[64:64+32]
    C2 = tmp[64+32:]

    C2_len = len(C2)

    C1_x = C1[:32]
    C1_y = C1[32:]

    
    C1_x_ber = b''.join([bytes.fromhex("02"), bytes([len(C1_x)]), C1_x])
    C1_y_ber = b''.join([bytes.fromhex("02"), bytes([len(C1_y)]), C1_y])

    C3_ber = b''.join([bytes.fromhex("04"), bytes([len(C3)]), C3])

    C2_ber = b''.join([bytes.fromhex("04"), bytes([len(C2)]), C2])

    f_value = b''.join([C1_x_ber, C1_y_ber, C3_ber, C2_ber])
    f_bytes = b''.join([bytes.fromhex("30"), bytes([len(f_value)]), f_value])
    return f_bytes


def c1c2c3_2_c1c3c2(m):
    """
    m is hex string.
    """
    aaa=bytes.fromhex(m)
    C1=aaa[:64]
    C3=aaa[-32:]
    C2=aaa[64:-32]
    b=b''.join([C1, C3, C2]) 
    print(b.hex())
    return b.hex()


def c1c3c2_2_c1c2c3(m):
    """
    m is hex string.
    """
    aaa=bytes.fromhex(m)
    C1=aaa[:64]
    C3=aaa[64:64+32]
    C2=aaa[64+32:]
    b=b''.join([C1, C2, C3]) 
    print(b.hex())
    return b.hex()


"""

ciphertxt1:

306F0221008BC7D7F0FE63E64BBF6FD3AADE379EF4052D8520C7A9E504D6BCF7A24747C8DA022100C61699D570E5294C21A5B1E586CE79052C6381CD16875774718F8D26BE6F6BE00420D39660275D7F3322587C6787F8B4748B07E9BBC106D6E58B3E7261B8260972C30405AD060C48A7

ciphertxt2:
306D022054ED37BC0706BFED031D45E6DB8BF26BD3BDDFB06DB795280D8C085B427585DF022100EF4AA615FDCF683C5F1CBCCDE7B6D7D5513F17738C362011A8DF83D5A0B3B1BE04204DB903B45364D619D0EFFA4A084841BA35BA36FFB7F7E480CAF044266BBF02E7040462E065A8

ASN.1 encoding  to  c1c3c2 cipher txt   

because
022100 

this bytes string start with \x00 byte.


306D022054ED37BC0706BFED031D45E6DB8BF26BD3BDDFB06DB795280D8C085B427585DF022100EF4AA615FDCF683C5F1CBCCDE7B6D7D5513F17738C362011A8DF83D5A0B3B1BE04204DB903B45364D619D0EFFA4A084841BA35BA36FFB7F7E480CAF044266BBF02E7040462E065A8

is equal(remove \x00, and length 21 become 20)
306D022054ED37BC0706BFED031D45E6DB8BF26BD3BDDFB06DB795280D8C085B427585DF0220EF4AA615FDCF683C5F1CBCCDE7B6D7D5513F17738C362011A8DF83D5A0B3B1BE04204DB903B45364D619D0EFFA4A084841BA35BA36FFB7F7E480CAF044266BBF02E7040462E065A8

cipher_txt:  306D022054ED37BC0706BFED031D45E6DB8BF26BD3BDDFB06DB795280D8C085B427585DF022100EF4AA615FDCF683C5F1CBCCDE7B6D7D5513F17738C362011A8DF83D5A0B3B1BE04204DB903B45364D619D0EFFA4A084841BA35BA36FFB7F7E480CAF044266BBF02E7040462E065A8


pub_key:
bbfbc5430dab854342462de4af7da4daa0b3613552c09c4c8d5b5c9e1eabb298
410bceebd0e9171229621e1f2af59cab715079720009d6190a106aab76386cac

priv_key:
42c37b287a1c218d76112208cdbc4a5fc17dd0d2ef76ca06df63e652e4e660c6




"""
