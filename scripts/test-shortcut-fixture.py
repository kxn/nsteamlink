#!/usr/bin/env python3
import struct
import sys
b=bytearray(20+8192*3)
b[:8]=b'NSLFWD01'
for i,t in enumerate((0,2,1)):
 struct.pack_into('<I',b,8+i*4,8192)
 n=20+i*8192;b[n+0x200:n+0x204]=b'NCA3';b[n+0x205]=t
 struct.pack_into('<QQ',b,n+0x208,8192,0x01004e534c4b1000);b[n+0x404]=1
m=20+16384;sb=m+0x408
struct.pack_into('<II',b,m+0x240,6,16);b[m+0x402]=1;b[m+0x403]=2
struct.pack_into('<I',b,sb+0x20,4096)
for off,value in ((0x30,32),(0x38,512),(0x40,256)):struct.pack_into('<Q',b,sb+off,value)
pfs=m+0xe00;b[pfs:pfs+4]=b'PFS0';struct.pack_into('<II',b,pfs+4,1,24);struct.pack_into('<Q',b,pfs+24,192)
c=pfs+64;struct.pack_into('<Q',b,c,0x01004e534c4b1000);b[c+12]=0x80;b[c+14]=16;b[c+16]=2
struct.pack_into('<Q',b,c+32,0x01004e534c4b1800)
with open(sys.argv[1],'w') as f:
 f.write('#include <stddef.h>\nconst unsigned char sl_shortcut_template[] = {'+','.join(str(v) for v in b)+'};\nconst size_t sl_shortcut_template_size=sizeof(sl_shortcut_template);\n')
