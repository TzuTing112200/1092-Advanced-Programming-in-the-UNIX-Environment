#!/usr/bin/env python3

from pwn import *
import sys
import binascii
from capstone import *

r = remote("up.zoolab.org", 2530)

while True:
    # get quiz and trans hex to byte
    s = str(r.recvuntil('Your answer: '))
    print(s)
    index = s.rfind('>') + 1
    s = s[index:-16]
    z = binascii.a2b_hex(s.strip())

    a = ''

    # disassmbly by capstone
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(z, 0x1000):
        a = a + "{} {}\n".format(i.mnemonic, i.op_str)

    # trans byte to hex
    ans = binascii.b2a_hex(a.encode("ascii")).decode("ascii")
    print("|{}|".format(ans))

    # send ans and get result
    r.sendline(ans)
    print(str(r.recvuntil('\n')))
    print(str(r.recvuntil('\n')))

r.interactive()

# ASM{u_r_r3llY_fa5t_0n_di5as53mb1inG}


# kevin
''' 
r = remote('up.zoolab.org',2530)
p = r.recvuntil('=\n')
print(p.decode())
md = Cs(CS_ARCH_X86, CS_MODE_64)

while r.can_read():
    p = r.recvuntil('>>> ')
    h = r.recvline().decode().strip('\n')

    print(p.decode()+h)

    code = binascii.a2b_hex(h)
    res = ''
    for ins in md.disasm(code,0):
        res = res + '{} {}\n'.format(ins.mnemonic,ins.op_str)

    res = binascii.b2a_hex(res.encode())
    r.sendline(res.decode())
    p = r.recvline()
    print(p.decode())
    p = r.recvline()
    print(p.decode())
r.interactive()
'''
