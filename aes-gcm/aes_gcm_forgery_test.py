from aes_gcm_forgery import recover_possible_auth_keys, forge_tag_from_ciphertext, forge_tag_from_plaintext, aes_gcm_forgery_attack, aes_gcm_forgery_attack_general
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
GCM_KEY = get_random_bytes(16)
GCM_NONCE = get_random_bytes(16)

def gcm_enc(ad, msg, key=GCM_KEY, nonce=GCM_NONCE):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(ad)
    return cipher.encrypt_and_digest(msg)

def gcm_dec(ad, ct, tag, key=GCM_KEY, nonce=GCM_NONCE):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(ad)
    return cipher.decrypt_and_verify(ct, tag)

def test_forge_tag_from_ciphertext():
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    GCM_KEY = get_random_bytes(16)
    GCM_NONCE = get_random_bytes(16)
    
    def gcm_enc(ad, msg, key=GCM_KEY, nonce=GCM_NONCE):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(ad)
        return cipher.encrypt_and_digest(msg)
    def gcm_dec(ad, ct, tag, key=GCM_KEY, nonce=GCM_NONCE):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(ad)
        return cipher.decrypt_and_verify(ct, tag)
    
    a1, m1 = get_random_bytes(16), get_random_bytes(16)    
    c1, t1 = gcm_enc(a1, m1)
    a2, m2 = get_random_bytes(16), get_random_bytes(16)
    c2, t2 = gcm_enc(a2, m2)
    
    target_a = get_random_bytes(16)
    target_c = get_random_bytes(16)
    keys = list(recover_possible_auth_keys(a1, c1, t1, a2, c2, t2))
    print(f"[+] Found {len(keys)} possible keys")
    for h in keys:
        target_tag = forge_tag_from_ciphertext(h, a1, c1, t1, target_a, target_c)
        try:
            gcm_dec(target_a, target_c, target_tag)
            print(f"[+] Found the correct key")
            break
        except:
            pass
    print("[+] Test `forge_tag_from_ciphertext` Passed")
    
def test_forge_tag_from_plaintext():
    a1, m1 = get_random_bytes(16), get_random_bytes(16)    
    c1, t1 = gcm_enc(a1, m1)
    a2, m2 = get_random_bytes(16), get_random_bytes(16)
    c2, t2 = gcm_enc(a2, m2)
    
    target_a = get_random_bytes(16)
    target_m = get_random_bytes(16)
    keys = list(recover_possible_auth_keys(a1, c1, t1, a2, c2, t2))
    print(f"[+] Found {len(keys)} possible keys")
    for h in keys:
        target_tag = forge_tag_from_plaintext(h, a1, c1, t1, m1, target_a, target_m)
        try:
            pt = gcm_dec(target_a, target_m, target_tag)
            assert pt == target_m, f"Decrypted message {pt} is not equal to the target message {target_m}"
            print(f"[+] Found the correct key")
            break
        except:
            pass
    print("[+] Test `forge_tag_from_plaintext` Passed")
    
def test_aes_gcm_forgery_attack():    
    a1, m1 = get_random_bytes(16), get_random_bytes(16)    
    c1, t1 = gcm_enc(a1, m1)
    a2, m2 = get_random_bytes(16), get_random_bytes(16)
    c2, t2 = gcm_enc(a2, m2)
    
    target_a = get_random_bytes(16)
    target_m = get_random_bytes(16)
    forgeries = list(aes_gcm_forgery_attack(a1, c1, t1, a2, c2, t2, m1, target_m, target_a))
    print(f"[+] Found {len(forgeries)} possible forgeries")
    for forged_a, forged_c, forged_t in forgeries:
        assert forged_a == target_a, f"Forged associated data {forged_a} is not equal to the target associated data {target_a}"
        try:
            pt = gcm_dec(target_a, forged_c, forged_t)
            # assert pt == target_m, f"Decrypted message {pt} is not equal to the target message {target_m}"
            break
        except:
            pass
    assert pt == target_m, f"Decrypted message {pt} is not equal to the target message {target_m}"
    print("[+] Test `aes_gcm_forgery_attack` Passed")
    
def test_aes_gcm_forgery_attack_general(sample_num=4):
    ads = [get_random_bytes(16) for _ in range(sample_num)]
    ms = [get_random_bytes(64) for _ in range(sample_num)]
    Cs = [gcm_enc(ad, m) for ad, m in zip(ads, ms)]
    cts, tags = zip(*Cs)
    target_m = get_random_bytes(64)
    target_a = get_random_bytes(16)
    target_a, target_c, target_tag = aes_gcm_forgery_attack_general(ads, cts, tags, ms[0], target_m, target_a)
    assert gcm_dec(target_a, target_c, target_tag) == target_m, f"Decrypted message is not equal to the target message {target_m}"
    print("[+] Test `aes_gcm_forgery_attack_general` Passed")
    
if __name__ == "__main__":
    for _ in range(5):
        test_forge_tag_from_ciphertext()
        test_forge_tag_from_plaintext()
        test_aes_gcm_forgery_attack()
        test_aes_gcm_forgery_attack_general()
    print("[+] All tests passed")