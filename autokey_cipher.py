def autokey_decipher(ciphertext, key):
    def a2i(c):
        return ord(c.upper()) - ord('A')
    
    def i2a(i, is_upper):
        char = chr((i % 26) + ord('A'))
        return char if is_upper else char.lower()
    
    key = ''.join(filter(str.isalpha, key))
     
    tmp = ''
    plaintext = ''
    key_index = 0
    for c in ciphertext:
        if c.isalpha():
            is_upper = c.isupper()
            if key_index < len(key):
                offset = a2i(key[key_index])
            else:
                offset = a2i(tmp[key_index - len(key)])
            
            tmp += i2a(a2i(c) - offset, is_upper)
            plaintext += i2a(a2i(c) - offset, is_upper)
            key_index += 1
        else:
            plaintext += c
    
    return plaintext

print(autokey_decipher("lpqwma{rws_ywpqaauad_rrqfcfkq_wuey_ifwo_xlkvxawjh_pkbgrzf}", "RWLLMUVP"))
