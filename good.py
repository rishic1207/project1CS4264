#!/usr/bin/env python3
# -*- coding: latin-1 -*-
blob = r"""
AAAN¼G.=W=bêøöo_ÌI(6oÌ‹ú(&9:”8ªV©ðc^o@n²è¿K)¹¬*Ñ×måû¶Xé^î|½FcÇ\Ë˜·+‡ZR_SA–ºrþfîö TÁ×ÅÍYYžÇ1–âmý’¡HÑÏo.x¦®i"nEH¬{^š;7£
"""
from hashlib import sha256

h = sha256(blob.encode("latin-1")).hexdigest()

if h == "46bf14dca6378f42fa071409021f07454bc91be6e93ffa04ee279ff3b5f447c2":
    print("I come in peace.")
else:
    print("Prepare to be destroyed!")
