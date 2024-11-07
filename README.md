# Nonce-Reuse-Attacks

Nonce reuse attacks for AEAD ciphers, especially for the the most commonly used `ChaCha20-Poly1305` and `AES-GCM`. 

## ChaCha20-Poly1305

The ChaCha20-Poly1305 cipher is a widely used authenticated encryption algorithm. It is used in the popular TLS 1.3 protocol, mitigating the sidechannel attacks in the cipher suites based on the Advanced Encryption Standard (AES). 

The ChaCha20-Poly1305 AEAD cipher is a combination of the ChaCha20 stream cipher and the `Poly1305` MAC algorithm. The nonce reuse attack destroys the integrity of the encrypted messages and allows the attacker to forge arbitrary messages (known-plaintext case). `Poly1305` MAC algorithm is almost the same as the `GHASH` algorithm used in the AES-GCM cipher.

### Poly1305

Let `msg` be the input message which is in form of `pad(AD) || pad(CT) || len(AD) || len(CT)`. The Poly1305 MAC algorithm is defined as follows:

```python
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
```

Mathematically, the Poly1305 MAC algorithm can be viewed as a polynomial evaluation over the finite field $\mathbb{F}_{2^{130}-5}$. The key `r` is used to evaluate the polynomial and the key `s` is used to add the final value to the result. The message is divided into 16-byte blocks denoted as $m_i$ and each block is padded with a `0x01` byte. The final result is the 16-byte MAC. That is :

$$
\textsf{Poly1305}(m, r, s) = \left( \sum_{i=0}^{} (m_i || 0x01) \cdot r^i \mod (2^{130} - 5) \right) + s \mod 2^{128}
$$

If the key $r, s$ is reused for two different messages $t_1 = \textsf{Poly1305}(m_1, r, s), t_2 = \textsf{Poly1305}(m_2, r, s)$, we can construt equations to recover the key $r, s$, and then forge arbitrary messages. All we need is to find the roots of a univariate polynomial $f(r) = \textsf{Poly1305}(m_1, r, s) - \textsf{Poly1305}(m_2, r, s) - (t_1 - t_2)$ in finite field $\mathbb{F}_{2^{130}-5}$.


## AES-GCM

The AES-GCM cipher is another widely used authenticated encryption algorithm. It uses the AES block cipher in the counter mode (CTR) and the Galois/Counter Mode (GCM) for authentication which is also called as `GHASH`.

`GHASH` uses a polynomial evaluation over the finite field $\mathbb{F}_{2^{128}}$. Except for the finite field, the `GHASH` algorithm is almost the same with the `Poly1305` algorithm. One can refer to the [GCM Wiki](https://en.wikipedia.org/wiki/Galois/Counter_Mode) for more details. Some notations are defined as follows:

- Galois Field: $\mathbb{F}_{2^{128}}$ with modulus $P(x) = x^{128} + x^7 + x^2 + x + 1$.
- MAC key: $H = {\textsf{AES}_{K}}(0) \in {\mathbb{F}_{2^{128}}}$.
- Constant coefficient: $C = {\textsf{AES}_{K}}(\textsf{Nonce||1}) \in {\mathbb{F}_{2^{128}}}$.

```python
# simplified version of the GHASH algorithm
def ghash(hbytes: bytes, padded_data: bytes, const_coeff: bytes = b""):
    h = to_gf2e(int.from_bytes(hbytes, byteorder="big"))
    const_coeff = to_gf2e(int.from_bytes(const_coeff, byteorder="big"))
    poly_coeff = [to_gf2e(int.from_bytes(padded_data[i:i+16], byteorder="big")) for i in range(0, len(padded_data), 16)] + [const_coeff]
    # evaluate the polynomial at h
    return sum([p * h ** i for i, p in enumerate(poly_coeff[::-1])])
```

The merged message `pad(AD) || pad(CT) || len(AD) || len(CT)` denoted as $p = (p_1, \cdots, p_n) \in \mathbb{F}_{2^{128}}^{n}$ consists of the ciphertext and the associated data. The `GHASH` function is a simple polynomial evaluation:

$$
tag = \sum_{i=1}^{n} p_i \cdot H^{i} + C 
$$

If the key $H, C$ is reused for two different messages $(p_1, \cdots, p_n)$ and $q_1, \cdots, q_m$, we can construct equations to recover the key $H, C$, and then forge arbitrary messages. All we need is to find the roots of a univariate polynomial $f(H) = \textsf{GHASH}(p_1, \cdots, p_n, H, C) - \textsf{GHASH}(q_1, \cdots, q_m, H, C) - (t_1 - t_2)$ in finite field $\mathbb{F}_{2^{128}}$ and recover candidate keys $H, C$.

## Implementation

The implementation of the nonce reuse attacks for `ChaCha20-Poly1305` and `AES-GCM`:

- [ChaCha20-Poly1305-Forgery](./chacha-poly1305/chacha_poly1305_forgery.py)
- [AES-GCM-Forgery](./aes-gcm/aes_gcm_forgery.py), modified from [forbidden attack](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/gcm/forbidden_attack.py)

Both implementations are based on the `SageMath` library. You can run the test scripts with sage's built-in python or import the function in sage. 

``` bash
$ sage -python chacha_poly1305_forgery_test.py
```

## Reference

- [GCM Wiki](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
- [The Poly1305-AES message-authentication code](https://cr.yp.to/mac/poly1305-20050329.pdf)
- [RFC 7539: ChaCha20 and Poly1305 for IETF Protocols](https://datatracker.ietf.org/doc/html/rfc7539)

CTF challenges related to the nonce reuse attacks:

- PlaidCTF 2024: DHCPP, [writeup](https://d-xuan.github.io/wednesday/ctf/plaid24/#dhcppp).
- Forbiddden Fruit in [CryptoHack](https://aes.cryptohack.org/forbidden_fruit/).