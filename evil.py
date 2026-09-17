#!/usr/bin/env python3
# -*- coding: latin-1 -*-
blob = r"""
AAAN¼G.=W=bêøöo_ÌI(6ïÌ‹ú(&9:”8ªV©ðc^o@n²è?L)¹¬*Ñ×måû¶Xi^î|½FcÇ\Ë˜·+‡ZR_SA–ºrþæîö TÁ×ÅÍYYžÇ1–âmý’¡HÑÏo®w¦®i"nEH¬{^;7£
"""
from hashlib import sha256

h = sha256(blob.encode("latin-1")).hexdigest()

if h == "46bf14dca6378f42fa071409021f07454bc91be6e93ffa04ee279ff3b5f447c2":
    print("I come in peace.")
else:
    print("Prepare to be destroyed!")
