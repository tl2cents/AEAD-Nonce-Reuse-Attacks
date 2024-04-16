from sage.all import GF, ZZ, PolynomialRing
from Crypto.Cipher.ChaCha20 import ChaCha20Cipher

def _poly1305(msg:bytes, key:bytes, byteorder='little'):
    """ A pure python implementation of the Poly1305 MAC function.
    Not a standard implementation, abandoned
    
    Args:
        msg (bytes): The message to authenticate
        key (bytes): The 32 byte key to use
    Returns:
        bytes: The 16 byte MAC
    """
    p = 2**130 - 5 # the prime number used in Poly1305
    r = int.from_bytes(key[:16], byteorder)
    r = r & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], byteorder)
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i+16] + b'\x01'
        block = int.from_bytes(block, byteorder)
        acc = (acc + block) * r % p
    acc = (acc + s) % p
    acc = int(acc % 2**128)
    return acc.to_bytes(16, byteorder)

# the implementation of the Poly1305 in the standard lib is as follows:
def poly1305(msg:bytes, key:bytes, byteorder='little'):
    """ A pure python implementation of the Poly1305 MAC function
    Reference: https://datatracker.ietf.org/doc/html/rfc7539#section-2.5.1
    Args:
        msg (bytes): The message to authenticate
        key (bytes): The 32 byte key to use
    Returns:
        bytes: The 16 byte MAC
    """
    p = 2**130 - 5 # the prime number used in Poly1305
    r = int.from_bytes(key[:16], byteorder)
    r = r & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], byteorder)
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i+16] + b'\x01'
        block = int.from_bytes(block, byteorder)
        acc = (acc + block) * r % p
    acc = (acc + s) # no more % p here !!!
    acc = int(acc % 2**128)
    return acc.to_bytes(16, byteorder)

def construct_poly1305_coeffs(msg:bytes, byteorder='little'):
    # get coefficients of the polynomial from the message bytes
    coeff = []
    for i in range(0, len(msg), 16):
        block = msg[i:i+16] + b'\x01'
        block = int.from_bytes(block, byteorder)
        coeff.append(block)
    return coeff

def sage_poly1305(msg:bytes, key:bytes, byteorder='little'):
    r = int.from_bytes(key[:16], byteorder)
    r = r & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], byteorder)
    p = 2**130 - 5 # the prime number used in Poly1305
    PolynomialRing_GF = PolynomialRing(GF(p), 'x')
    x = PolynomialRing_GF.gen()
    poly = x * PolynomialRing_GF(construct_poly1305_coeffs(msg, byteorder)[::-1]) + s
    val = int(poly(r))
    return int(val % 2**128).to_bytes(16, byteorder)

def is_valid_r(r):
    # check if r is a valid Poly1305 key
    # from RFC specification: https://datatracker.ietf.org/doc/html/rfc7539#section-2.5
    return (r & 0x0ffffffc0ffffffc0ffffffc0fffffff) == r

def recover_poly1305_key_from_nonce_reuse(msg1:bytes, tag1:bytes, 
                                          msg2:bytes, tag2:bytes,
                                          byteorder='little'):
    """Recover the Poly1305 key when nonce is reused.
    
    Args:
        msg1 (bytes): The first message
        tag1 (bytes): The first tag
        msg2 (bytes): The second message
        tag2 (bytes): The second tag
    Returns:
        list: keys r, s
    """
    p = 2**130 - 5 # the prime number used in Poly1305
    pp = 2**128
    PolynomialRing_GF = PolynomialRing(GF(p), 'x')
    x = PolynomialRing_GF.gen()
    poly1 = x * PolynomialRing_GF(construct_poly1305_coeffs(msg1, byteorder)[::-1])
    a1 = int.from_bytes(tag1, byteorder)
    poly2 = x * PolynomialRing_GF(construct_poly1305_coeffs(msg2, byteorder)[::-1])
    a2 = int.from_bytes(tag2, byteorder)
    # find all possible keys
    roots = []
    print(f"[+] Searching for the key with poly.degree() = {(poly1 - poly2).degree()}")
    # the range is larger than expected
    # since in poly1305 acc + s does not have to be modulo p
    for tag1 in range(a1, p + pp, pp):
        for tag2 in range(a2, p + pp, pp):
            f = (poly1 - poly2) - (tag1 - tag2)
            root = f.roots(multiplicities=False)
            for r in root:
                r = int(r)
                if is_valid_r(r):
                    # print(f"[+] Found a valid key: {r}")
                    # check if the key is valid
                    s = int(a1 - int(poly1(r))) % pp
                    if (int(poly1(r)) + s) % pp == a1 and (int(poly2(r)) + s) % pp == a2:
                        roots.append((r, s))
    return list(set(roots))


def derive_poly1305_key(key:bytes, nonce:bytes):
    assert len(key) == 32 and len(nonce) == 12, "The key should be 32 bytes and the nonce should be 12 bytes"
    chacha20_block = ChaCha20Cipher(key, nonce).encrypt(b'\x00'*64)
    return chacha20_block[:32]
    
def chachapoly1305_merger(ad:bytes, ct:bytes):
    """Merge the associated data and the ciphertext
    
    Args:
        ad (bytes): The associated data
        ct (bytes): The ciphertext
    Returns:
        bytes: The merged data
    """
    def pad(data, block_size=16):
        if len(data) % block_size == 0:
            return data
        return data + b'\x00' * (block_size - len(data) % block_size)
    la = len(ad)
    lc = len(ct)
    out = pad(ad) + pad(ct) + la.to_bytes(8, 'little') + lc.to_bytes(8, 'little')
    return out

def chachapoly1305_nonce_reuse_attack(ad1:bytes, ct1:bytes, tag1:bytes, 
                                      ad2:bytes, ct2:bytes, tag2:bytes):
    """Recover the Chacha-Poly1305 key when nonce is reused.
    
    The two messages are encrypted with the same nonce and the same key.
    Args:
        ad1 (bytes): The first associated data
        ct1 (bytes): The first ciphertext
        tag1 (bytes): The first tag
        ad2 (bytes): The second associated data
        ct2 (bytes): The second ciphertext
        tag2 (bytes): The second tag
    Returns:
        list: keys r, s
    """
    inp1 = chachapoly1305_merger(ad1, ct1)
    inp2 = chachapoly1305_merger(ad2, ct2)
    return recover_poly1305_key_from_nonce_reuse(inp1, tag1, inp2, tag2)

def forge_poly1305_tag(ad:bytes, ct:bytes, r:int, s:int):
    """Forge a Poly1305 tag given the message and the key
    
    Args:
        ad (bytes): The associated data
        ct (bytes): The ciphertext
        r (int): The r key
        s (int): The s key
    """
    key = r.to_bytes(16, 'little') + s.to_bytes(16, 'little')
    msg = chachapoly1305_merger(ad, ct)
    return poly1305(msg, key)

def chachapoly1305_forgery_attack(ad1:bytes, ct1:bytes, tag1:bytes, 
                                  ad2:bytes, ct2:bytes, tag2:bytes,
                                  known_plaintext1:bytes, 
                                  target_plaintext:bytes, target_ad:bytes):
    """Recover the Chacha-Poly1305 key when nonce is reused.
    
    Args:
        ad1 (bytes): The first associated data
        ct1 (bytes): The first ciphertext
        tag1 (bytes): The first tag
        ad2 (bytes): The second associated data
        ct2 (bytes): The second ciphertext
        tag2 (bytes): The second tag
        known_plaintext1 (bytes): The known plaintext of ct1
        target_plaintext (bytes): The target plaintext to forge
        target_ad (bytes): The target associated data to forge
        
    return:
        generator: yields the forged ciphertext and tag
    """
    keys = chachapoly1305_nonce_reuse_attack(ad1, ct1, tag1, ad2, ct2, tag2)
    if len(keys) == 0:
        assert False, "Failed to recover the key for poly1305, probably the nonce is not reused"
    
    assert len(target_plaintext) <= len(known_plaintext1), "The target plaintext should be shorter than the known plaintext"
    keystream = [b1 ^ b2 for b1, b2 in zip(known_plaintext1, ct1)]
    target_ct = bytes([b1 ^ b2 for b1, b2 in zip(keystream, target_plaintext)])
    for r, s in keys:
        target_tag = forge_poly1305_tag(target_ad, target_ct, r, s)
        yield target_ct, target_tag

def chachapoly1305_forgery_attack_general(ads:list[bytes], cts:list[bytes], tags:bytes, 
                                          known_plaintext1:bytes, 
                                          target_plaintext:bytes, target_ad:bytes):
    """Recover the Chacha-Poly1305 key when nonce is reused.
    
    Args:
        ads (list[bytes]): The associated data
        cts (list[bytes]): The ciphertexts
        tags (list[bytes]): The tags
        known_plaintext1 (bytes): The known plaintext of ct1
        target_plaintext (bytes): The target plaintext to forge
        target_ad (bytes): The target associated data to forge
    
    returns:
        target_ct, target_tag : bytes, bytes (if not unique, we simply return the first one)
    """
    assert len(ads) == len(cts) == len(tags) and len(cts) >= 2, "The length of the associated data, ciphertexts, and tags should be the same and at least 2"
    ad1, ct1, tag1 = ads[0], cts[0], tags[0]
    keys = []
    for ad2, ct2, tag2 in zip(ads[1:], cts[1:], tags[1:]):
        if len(keys) == 0:
            keys = chachapoly1305_nonce_reuse_attack(ad1, ct1, tag1, ad2, ct2, tag2)
        else:
            _keys = chachapoly1305_nonce_reuse_attack(ad1, ct1, tag1, ad2, ct2, tag2)
            keys = list(set(keys) & set(_keys))
        if len(keys) == 1:
            break
    if len(keys) == 0:
        assert False, "Failed to recover the key for poly1305, probably the nonce is not reused"
    elif len(keys) > 1:
        print(f"[!] Found multiple keys {len(keys) = }, trying to forge the message, use the first key")
        print("[!] You can use more nonce-reuse messages to find the unique key")    
    
    # anyway, use the first key  
    r, s = keys[0]
    print(f"[+] Using Key {r = }, {s = } {len(keys) = }")
    
    assert len(target_plaintext) <= len(known_plaintext1), "The target plaintext should be shorter than the known plaintext"
    keystream = [b1 ^ b2 for b1, b2 in zip(known_plaintext1, ct1)]
    target_ct = bytes([b1 ^ b2 for b1, b2 in zip(keystream, target_plaintext)])
    target_tag = forge_poly1305_tag(target_ad, target_ct, r, s)
    return target_ct, target_tag