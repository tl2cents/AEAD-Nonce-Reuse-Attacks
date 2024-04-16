from chacha_poly1305_forgery import chachapoly1305_forgery_attack, chachapoly1305_forgery_attack_general
from chacha_poly1305_forgery import poly1305, sage_poly1305, recover_poly1305_key_from_nonce_reuse, chachapoly1305_nonce_reuse_attack, derive_poly1305_key
from sage.all import GF, ZZ, PolynomialRing
from chacha_poly1305_forgery import construct_poly1305_coeffs, forge_poly1305_tag, chachapoly1305_merger, poly1305
import secrets
from Crypto.Cipher import ChaCha20_Poly1305
# from Crypto.Hash import Poly1305
# from Crypto.Hash.Poly1305 import Poly1305_MAC
# from chacha20poly1305 import ChaCha20Poly1305


def test_impl_poly1305():
    # from RFC Example: https://datatracker.ietf.org/doc/html/rfc8439#section-2.5.2
    key = "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b"
    key = bytes.fromhex(key.replace(":", ""))
    assert len(key) == 32
    test_msg = b"Cryptographic Forum Research Group"
    test_tag = "a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9"
    test_tag = bytes.fromhex(test_tag.replace(":", ""))
    assert poly1305(test_msg, key) == test_tag, "impl Test Failed"
    print("[+] Test `poly1305`(pure python) Passed")
    assert sage_poly1305(test_msg, key) == test_tag, "poly Test Failed"
    print("[+] Test `sage_poly1305` Passed")
    
def test_recover_poly1305_key():
    import os
    key = os.urandom(32)
    r = int.from_bytes(key[:16], 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], 'little')
    # msg1 = b"Hello, World! + 1"
    # msg2 = b"Hello, World! + 2"
    msg1 = os.urandom(64)
    msg2 = os.urandom(64)
    tag1 = poly1305(msg1, key)
    tag2 = poly1305(msg2, key)
    possible_keys = recover_poly1305_key_from_nonce_reuse(msg1, tag1, msg2, tag2)
    print(f"[+] r: {r}, s: {s}")
    print(f"[+] Possible Keys: {possible_keys}")
    assert (r,s) in possible_keys, "Test Failed"
    print("[+] Test `recover_poly1305_key_from_nonce_reuse` Passed")
    
def test_derive_poly1305_key():
    # from https://datatracker.ietf.org/doc/html/rfc7539#section-2.6.2
    key = bytes([0x80 + i for i in range(32)])
    nonce = b"\x00" * 5 + bytes([i + 1 for i in range(7)])
    poly_keyhex = "8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71"
    poly_keyhex += "a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46"
    poly_key = bytes.fromhex(poly_keyhex.replace(" ", ""))
    assert derive_poly1305_key(key, nonce) == poly_key, "Test Failed"
    print("[+] Test `derive_poly1305_key` Passed")

def test_chachapoly1305_forgery_attack(general=True):
    # general=False: we can control the diffence between the two plain messages for `chacha-poly1305` with the same nonce and key
    CHACHA_KEY = secrets.token_bytes(32)
    CHACHA_NONCE = secrets.token_bytes(12)

    def chacha_enc(msg:bytes, ad:bytes, key=CHACHA_KEY, nonce=CHACHA_NONCE):
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(ad)
        ct, tag = cipher.encrypt_and_digest(msg)
        return ct, tag, nonce

    def chacha_dec(ct:bytes, ad:bytes, tag:bytes, key=CHACHA_KEY, nonce=CHACHA_NONCE):
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(ad)
        pt = cipher.decrypt_and_verify(ct, tag)
        return pt
    
    if general:
        m1 = secrets.token_bytes(33)
        m2 = secrets.token_bytes(61)
    else:
        # difference in the last block results in minimal poly degree = 2 
        block = secrets.token_bytes(18)
        m1 = block + b"1"*15 + b"\x00"
        m2 = block + b"1"*15 + b"\x01"
    
    a1 = a2 = b""
    target_a = b""
    c1, t1, _ = chacha_enc(m1, a1)
    c2, t2, _ = chacha_enc(m2, a2)
    target_msg = b"Forged Message"
    
    keys = chachapoly1305_nonce_reuse_attack(a1, c1, t1, a2, c2, t2)
    real_keybytes = derive_poly1305_key(CHACHA_KEY, CHACHA_NONCE)
    real_r, real_s = int.from_bytes(real_keybytes[:16], 'little'), int.from_bytes(real_keybytes[16:], 'little') 
    real_r = real_r & 0x0ffffffc0ffffffc0ffffffc0fffffff
    assert (real_r, real_s) in keys, f"Real key {real_r, real_s} is not in possible keys {keys}"
    
    forges = list(chachapoly1305_forgery_attack(a1, c1, t1, 
                                                a2, c2, t2, 
                                                m1, 
                                                target_msg, target_a))
    # check the forgery
    real_ct, real_tag, _ = chacha_enc(target_msg, target_a)
    assert (real_ct, real_tag) in forges, f"the real forgery {real_ct, real_tag} is not in the possible forgeries {forges}"
    print(f"[+] find {len(forges)} possible forgeries")

    # using associated data
    a1 = b"Associated Data 1"
    a2 = b"Associated Data 2"
    c1, t1, _ = chacha_enc(m1, a1)
    c2, t2, _ = chacha_enc(m2, a2)
    target_a = b"Forged Associated Data"
    
    keys = chachapoly1305_nonce_reuse_attack(a1, c1, t1, a2, c2, t2)
    real_keybytes = derive_poly1305_key(CHACHA_KEY, CHACHA_NONCE)
    real_r, real_s = int.from_bytes(real_keybytes[:16], 'little'), int.from_bytes(real_keybytes[16:], 'little') 
    real_r = real_r & 0x0ffffffc0ffffffc0ffffffc0fffffff
    forges = list(chachapoly1305_forgery_attack(a1, c1, t1,
                                                a2, c2, t2,
                                                m1,
                                                target_msg, target_a))
    # check the forgery
    real_ct, real_tag, _ = chacha_enc(target_msg, target_a)
    assert (real_ct, real_tag) in forges, f"the real forgery {real_ct, real_tag} is not in the possible forgeries {forges}"
    print(f"[+] find {len(forges)} possible forgeries")
    print("[+] Test `chachapoly1305_forgery_attack` Passed")    
    
def test_chachapoly1305_forgery_attack_general(sample_num = 3):
    import secrets
    from Crypto.Cipher import ChaCha20_Poly1305
    
    CHACHA_KEY = secrets.token_bytes(32)
    CHACHA_NONCE = secrets.token_bytes(12)

    def chacha_enc(msg:bytes, ad:bytes, key=CHACHA_KEY, nonce=CHACHA_NONCE):
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(ad)
        ct, tag = cipher.encrypt_and_digest(msg)
        return ct, tag, nonce

    def chacha_dec(ct:bytes, ad:bytes, tag:bytes, key=CHACHA_KEY, nonce=CHACHA_NONCE):
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(ad)
        pt = cipher.decrypt_and_verify(ct, tag)
        return pt
    
    ms = [secrets.token_bytes(32) for _ in range(sample_num)]
    ads = [secrets.token_bytes(32) for _ in range(sample_num)]
    Cs = [chacha_enc(m, ad) for m, ad in zip(ms, ads)]
    cts, tags, _ = zip(*Cs)

    target_msg = b"Forged Message"
    target_ad = b"Forged Associated Data"
    known_plaintext1 = ms[0]
    forged_ct, forged_tag = chachapoly1305_forgery_attack_general(ads, cts, tags, 
                                                                known_plaintext1, 
                                                                target_msg, target_ad)
    assert chacha_dec(forged_ct, target_ad, forged_tag) == target_msg, "Test Failed"
    print("[+] Test `chachapoly1305_forgery_attack_general` Passed")


if __name__ == "__main__":
    test_derive_poly1305_key()
    test_impl_poly1305()
    test_recover_poly1305_key()
    for i in range(5):
        test_chachapoly1305_forgery_attack(False)
    for i in range(5):
        test_chachapoly1305_forgery_attack(True)
    for i in range(5):       
        test_chachapoly1305_forgery_attack_general()
    print("[+] All Tests Passed")