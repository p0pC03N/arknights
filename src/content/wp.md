# PWN
## Mission Calculator
1. 反汇编一下知道main流程，全部 50 题答对后调用 win() → system("/bin/sh")，给你 shell
2. 写脚本做题
```python
from pwn import *
import re

io = remote("geek.ctfplus.cn", 30716)

# 读到“Press any key to start...”
io.recvuntil(b"Press any key to start...")
io.sendline(b"")   # 按任意键

# 做 50 道题
for i in range(50):
    line = io.recvuntil(b" = ")
    text = line.decode(errors="ignore").strip()
    print("[PROB]", text)

    m = re.search(r"Problem\s+\d+:\s+(\d+)\s*\*\s*(\d+)\s*=", text)
    a = int(m.group(1))
    b = int(m.group(2))
    ans = a * b
    print("[ANS ]", ans)
    io.sendline(str(ans).encode())

# 把成功提示那一行读掉（可要可不要）
io.recvuntil(b"completed all 50 math problems.")
print("[*] All problems done, dropping to shell")

# 现在应该是在 /bin/sh 里了
io.interactive()
```




# REVERSE
## ez_pyyy
**SYC{jtfgdsfda554_a54d8as53}**
1. 反汇编python
2. 写脚本
```python
cipher = [
    48, 55, 57, 50, 53, 55, 53, 50, 52, 50, 48, 55, 101, 52, 53, 50,
    52, 50, 52, 50, 48, 55, 53, 55, 55, 55, 50, 54, 53, 55, 54, 55,
    55, 55, 53, 54, 98, 55, 97, 54, 50, 53, 56, 52, 50, 52, 99, 54,
    50, 50, 52, 50, 50, 54
]

# 步骤1：将cipher转换为data5的十六进制字符串s
s = ''.join(chr(c) for c in cipher)
data5 = bytes.fromhex(s)

# 步骤2：en33的逆操作（循环右移32位）
def de_en33(data, n):
    bit_len = len(data) * 8
    n = n % bit_len
    val = int.from_bytes(data, 'big')
    mask = (1 << bit_len) - 1
    val = (val >> n) | (val << (bit_len - n))
    val &= mask
    return val.to_bytes(len(data), 'big')

data4 = de_en33(data5, 32)

# 步骤3：反转字节顺序得到data3
data3 = data4[::-1]

# 步骤4：en3的逆操作（高低4位互换）
def en3(b):
    return (b << 4 & 240) | (b >> 4 & 15)

data2 = bytes([en3(b) for b in data3])

# 步骤5：与17异或得到data1
data1 = bytes([b ^ 17 for b in data2])

# 步骤6：解码得到flag
flag = data1.decode('utf-8')
print(flag)
```
## QYQSの奇妙冒险
**SYC{I_@m_QyqS_r1GhT?}**
1. 反汇编
2. 写脚本
```python
QYQS = [
    2, 1, 16, 43, 28, 3, 23, 57, 6, 1, 34,
    41, 14, 11, 45, 109, 6, 32, 23, 127, 56
]
key = [81, 89, 81, 83]  # "QYQS"的ASCII码
flag = []
for i in range(21):
    q = QYQS[i]
    k = key[i % 4]
    raw_char = chr((q ^ k) ^ i)
    flag.append(raw_char)
print("Flag:", ''.join(flag))
```
![alt text](mmexport1763992511655.jpg)
## only_flower
**SYC{asdjjasdhjkl2wk12ijkejk}**
1. 关注EB FF，其中EB即短跳转，EB后面跟着一个字节，即跳转的偏移地址，而这个地址为FF，换成char则为-1，即死循环，一直执行这段代码，而面对这种有两种情况，一种是对齐全部nop掉，一种是nop其中一个，全部nop，后面的逻辑存在问题，所以只nop EB，把这种类型的全改后在main那先U，在P
2. 写脚本反推
```python
KEY = [0x47, 0x45, 0x45, 0x4B, 0x32, 0x30, 0x32, 0x35]  # 对应字节：71, 69, 69, 75, 50, 48, 50, 53
CIPHER = [0x0A, 0x84, 0xC2, 0x84,
          0x51, 0x48, 0x5F, 0xF2,
          0x9E, 0x8D, 0xD0, 0x84,
          0x75, 0x67, 0x73, 0x8F,
          0xCA, 0x57, 0xD7, 0xE6,
          0x14, 0x6E, 0x77, 0xE2,
          0x29, 0xFE, 0xDF, 0xCC]

def ror8(a, n):
    """循环右移n位（逆rol8操作）"""
    return (a >> n) | ((a << (8 - n)) & 0xFF)

flag = []
for i in range(28):
    k = KEY[i % 8]
    n = k & 7
    val = CIPHER[i] - i
    ror_val = ror8(val, n)
    in_i = ror_val ^ k
    flag.append(chr(in_i))

print("逆向得到的flag：", ''.join(flag))
```
![alt text](d86191e67ab6144a40eb0b4d4985f7e2.png)
## encode
**SYC{St4nd4rd_Funct10n_N0t_4lw4ys_St4nd4rd}**
IDA反汇编从main一步步分析，发现是TEA变种，每字节再 XOR 0x5A，最后与base64编码，所以把key和base64常量找到就可以写脚本逆向了
```python
import base64
from struct import pack, unpack

KEY_BYTES = b"geek2025reverse!"
TARGET_B64 = "vBzX30Koxl3HpDaYaFJKhyB/1ckuVCnc4wZhrwUWeNuZkAxr+Qn5UaYbpvymmCrk"
DELTA = 0x61C88647

def build_key_words(k):
    return [(k[i]<<24)|(k[i+1]<<16)|(k[i+2]<<8)|k[i+3] for i in range(0,16,4)]

def tea_dec(y, k):
    v0,v1 = unpack(">II", y)
    sum = (0 - DELTA*32) & 0xffffffff
    for _ in range(32):
        v1 = (v1 - (((v0>>5)^(v0<<4))+v0 ^ (sum+k[(sum>>11)&3]))) & 0xffffffff
        sum = (sum + DELTA) & 0xffffffff
        v0 = (v0 - (((v1>>5)^(v1<<4))+v1 ^ (sum+k[sum&3]))) & 0xffffffff
    return pack(">II", v0, v1)

raw = base64.b64decode(TARGET_B64)
cipher = bytes(b ^ 0x5A for b in raw)
key = build_key_words(KEY_BYTES)

out = b''.join(tea_dec(cipher[i:i+8], key) for i in range(0,len(cipher),8))
pt = out[:-out[-1]]
print(pt)
```
## ezRu3t
**SYC{Ohjhhh_y0u_g3t_Ezzzzz3_Ru3t!@}**
依旧IDA反汇编，挨着挨着看函数就是了，先base64编码，之后Base85（Ascii85）（魔改过的），所以把目标 Base85 串找到之后解码就行
```python
import base64

# Base85 字母表（你的程序使用的）
ALPHABET = r"""!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstu"""

def ascii85_decode(s: str) -> bytes:
    """按 Rust 程序使用的 base85 字母表解码"""
    out = bytearray()
    i = 0
    while i < len(s):
        block = s[i:i+5]
        i += 5

        if len(block) < 5:
            # 末尾不足 5 个字符的情况
            pad = 5 - len(block)
            acc = 0
            for ch in block:
                acc = acc * 85 + (ord(ch) - ord('!'))
            acc *= 85 ** pad
            b = acc.to_bytes(4, 'big')
            out.extend(b[:len(block)-1])
            break

        acc = 0
        for ch in block:
            acc = acc * 85 + (ord(ch) - ord('!'))
        out.extend(acc.to_bytes(4, 'big'))

    return bytes(out)

def solve(hexdata: str):
    # 1. hex → ASCII
    b = bytes.fromhex(hexdata)
    ascii85_string = b.decode()

    # 2. base85（Ascii85）→ 原始 base64 字节
    b64_bytes = ascii85_decode(ascii85_string)

    # 3. base64 解码 → 最终 flag
    flag = base64.b64decode(b64_bytes).decode()

    return flag


if __name__ == "__main__":
    # 你给的两行拼起来的 hex
    hexdata = (
        "3c41413b58414d3f2c5f403b545b7240374537373968383b733e276070743d3e3"
        "36336415375484641534f74503c476b665f4134266750416c315d53"
    )

    flag = solve(hexdata)
    print("Flag:", flag)
```
## ezSMC
**SYC{OHhhhhhhh_y0u_Kn0m_SMCCCC@!}**
1. IDA反汇编，发现有一堆加密函数
2. 挨着确认函数
   1. ascii_to_hexbytes和hexstr_to_bytes正反加密，合起来啥都没做
   2. init + encode = RC4
   3. bytes_to_hexstr加密后的 bin → hex 字符串
   4. enc0de() = 完整 Base58 Encode
3. encodee() 是自修改代码（动态解密），要在程序运行后 dump 真实的 encodee 函数（miao_encrypt 先调用 find_miao_section() 得到那段代码地址，调用 miao_xor XOR 解密）
所以在 miao_encrypt() 返回后 / encodee 调用前断点看机器码，发现是Base64 编码
4. 写脚本反推
```python
import base64

cipher = "tHMoSoMX71sm62ARQ8aHF6i88nhkH9Ac2J7CrkQsQgXpiy6efoC8YVkzZu1tMyFxCLbbqvgXZHxtwK5TACVhPi1EE5mK6JG56wPNR4d2GmkELGfJHgtcAEH7"

BASE58_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789"

def b58decode(s: str) -> bytes:
    # 字符映射到数字
    digits = []
    for ch in s:
        idx = BASE58_ALPHABET.find(ch)
        if idx == -1:
            raise ValueError(ch)
        digits.append(idx)

    # Base58 digits -> 大整数
    num = 0
    for d in digits:
        num = num * 58 + d

    # 大整数 -> 字节
    out = bytearray()
    while num > 0:
        num, rem = divmod(num, 256)
        out.append(rem)
    out.reverse()

    # 前导零（'A' == 0）
    n_zeros = 0
    for ch in s:
        if ch == 'A':   # encodee 写死的 0 前导
            n_zeros += 1
        else:
            break

    return b'\x00' * n_zeros + bytes(out)


def rc4_ksa(key: bytes):
    S = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 0xFF
        S[i], S[j] = S[j], S[i]
    return S

def rc4_prga(S, data: bytes) -> bytes:
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) & 0xFF]
        out.append(b ^ k)
    return bytes(out)


def solve():
    # 1) Base58 decode
    en2 = b58decode(cipher)

    # 2) Base64 decode
    en1 = base64.b64decode(en2)

    # 3) hex -> bytes
    enc = bytes.fromhex(en1.decode())

    # 4) RC4 解密（key=0x11）
    key = bytes([0x11])
    S = rc4_ksa(key)
    plain = rc4_prga(S, enc)

    print("FLAG =", plain.decode(errors="ignore"))


if __name__ == "__main__":
    solve()
```
## Gensh1n
**SYC{50_y0u_pl@y_Gensh1n_too}**
1. （顺手调试了一下，居然跳出不准我玩原神的警告！！！）IDA反汇编，main函数没找到加密逻辑，对关键变量global_nodes交叉引用，找到clean up，真正校验flag的地方，对其中未知函数逐一分析，发现是RC4加密，写脚本反推
```python
def rc4(data, key):
    # KSA
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA
    i = 0
    j = 0
    output = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        output.append(byte ^ K)
    return bytes(output)


result = bytes([
    0x52,0x59,0xF3,0x8A,0x00,0x0F,0xE6,0x56,
    0x36,0xE5,0xF0,0x33,0x40,0x6E,0x56,0x81,
    0x5A,0xE5,0x6F,0x87,0x6F,0x9F,0x21,0xC9,
    0xA6,0xBB,0x16,0x51,
])

key = b"geek2025"

plain = rc4(result, key)
print(plain)
```
## Lastone
**SYC{1@St_0nE_THanKs_I_lOvE_y0U!}**
1. 依旧IDA，找到main之后逐句分析，sub_402330是一个小 VM / 混淆器（其中off_40C000对输入的 8 个 4 字节块，依次应用 8 个（可逆的）变换），在call  dword ptr [off_40C000 + ecx*4]断点，动态调试（F9 8次）去看每次调用的哪一个加密函数，以及key值（key_j = (v8 + v6 * v7) ^ (40503 * v9)），最后写脚本反推
(我的脚本运行下来有两三个字符串是错的，懒得找错了小猜了一下得的flag)
（中间有一次的v8值记错了，修脚本修半天都没对，，，）
```python
# 目标常量（v10/v11/v12/v13 拼起来的 32 字节）
target = [
    0x35,0x67,0x05,0x2D, 0x74,0x40,0x53,0x31,
    0x41,0x6F,0x62,0x45, 0x4B,0x1F,0x57,0x36,
    0x5F,0x4B,0x73,0x6E, 0x4F,0x6C,0x5F,0x49,
    0x00,0x7F,0x3F,0x79, 0x28,0xD2,0x69,0x6E,
]
target = bytes(target)

# 你调试出来的 v8/v6/v7/v9（注意 j=0 的 v8 改成 0x9F）
params = [
    # j,   v8,          v6,   v7, v9
    (0, 0x9F,       0x11,    7,  0xD5),
    (1, 0x40000033, 0x22,    9,  0xAE5),
    (2, 0xBB,       0x33, 0x0D,  0x14),
    (3, 0xF2,       0x44, 0x0E,  0x32),
    (4, 0xDF,       0x55,    2,  0xBC),
    (5, 0x4F,       0x66, 0x0A, 0x1BC),
    (6, 0x81,       0x77, 0x0F,  0x35),
    (7, 0x80,       0x88,    5, 0x550),
]

def calc_key(v8, v6, v7, v9):
    # 和程序里一样的公式，按 32bit 环绕
    return ((v8 + v6 * v7) ^ (40503 * v9)) & 0xFFFFFFFF


# =========  根据 j.c 写出的逆操作 =========
# j=0: sub_AD2080  每字节:  b = HIBYTE(a3) ^ (8*b) ^ (a3*b)
def inv_op0(block, key):
    a3 = key & 0xFFFF
    kh = (a3 >> 8) & 0xFF
    res = []
    for bout in block:
        for x in range(256):
            v = (kh ^ ((8 * x) & 0xFF) ^ ((a3 * x) & 0xFF)) & 0xFF
            if v == bout:
                res.append(x)
                break
        else:
            raise ValueError("no solution for byte %02x" % bout)
    return bytes(res)

# j=1 / j=4: sub_AD18A0  交换首尾
def inv_swap_first_last(block, key):
    b = list(block)
    if len(b) >= 2:
        b[0], b[-1] = b[-1], b[0]
    return bytes(b)

# j=2 / j=7: sub_AD15C0  每字节异或 key>>(8*(i%4))
def inv_xor_block(block, key):
    a3 = key & 0xFFFFFFFF
    out = []
    for i, c in enumerate(block):
        out.append(c ^ ((a3 >> (8 * (i % 4))) & 0xFF))
    return bytes(out)

# j=3: sub_AD1FD0  rolling xor:  b ^= a3; a3 = b
def inv_rolling_xor(block, key):
    a3 = key & 0xFF
    y = list(block)
    x = []
    prev = a3
    for i in range(len(y)):
        xi = y[i] ^ prev
        x.append(xi)
        prev = y[i]           # 注意这里用的是“结果” y[i]
    return bytes(x)

# j=5: sub_AD1A40  整个块 reverse
def inv_reverse(block, key):
    return bytes(reversed(block))

# j=6: sub_AD17F0  每字节减 key 字节，这里做加法逆回去
def inv_add_key(block, key):
    a3 = key & 0xFFFFFFFF
    out = []
    for i, c in enumerate(block):
        out.append((c + ((a3 >> (8 * (i % 4))) & 0xFF)) & 0xFF)
    return bytes(out)


# =========  主流程：对 8 个 4 字节块分别做逆运算 =========
flag = bytearray()

for j, v8, v6, v7, v9 in params:
    key = calc_key(v8, v6, v7, v9)
    blk = target[4 * j : 4 * (j + 1)]

    if j == 0:
        dec = inv_op0(blk, key)
    elif j in (1, 4):
        dec = inv_swap_first_last(blk, key)
    elif j in (2, 7):
        dec = inv_xor_block(blk, key)
    elif j == 3:
        dec = inv_rolling_xor(blk, key)
    elif j == 5:
        dec = inv_reverse(blk, key)
    elif j == 6:
        dec = inv_add_key(blk, key)
    else:
        raise RuntimeError("unhandled j = %d" % j)

    flag += dec

print(flag)                    # 原始字节
print(flag.decode("latin1"))   # 直接按单字节编码打印
```
## QYQSの奇妙冒险2
**SYC{M@y_bE_y0u_F1nd?}**
没话说，把汇报语言翻一遍就找到flag了，但听说是打算考花指令的跳转
## obfuscat3
**SYC{Alright_I_sti1l_h0pe_th3t_you_solved_the_chall3nge_by_deobfuscating_them_Geek_is_just_the_first_step_of_your_CTF_journey_Im_glad_I_could_be_part_of_your_growth_Good_luck_for_y0u!}**
1. 先瞪眼法猜出是RC4，索性直接放弃去混淆，分析函数找魔改的地方：cipher = plain + K (mod 256)，RC4 key 是"Samsara"，KSA好像是标准的，写脚本反推就完了
```python
cipher = bytes([... 题目给的那一大串 ...])

def rc4_add_stream(key: bytes, data: bytes, encrypt: bool) -> bytes:
    # KSA
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]

    # PRGA
    out = bytearray()
    i = j = 0
    for c in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) & 0xFF]
        if encrypt:
            out.append((c + k) & 0xFF)
        else:
            out.append((c - k) & 0xFF)
    return bytes(out)

key   = b"Samsara"
plain = rc4_add_stream(key, cipher, encrypt=False)
print(plain.decode())
```
## ez_vm
**SYC{W31c0m3_t0_r3@1_r3verse!}**
1. 先看main函数，发现是vm，用 sub_9e8f7a 真正运行这个 VM 的程序，所以看sub_9e8f7a。通过一系列函数处理，索性直接在sub_9e8f7a之后下断点，这时候:
global_vm 已经初始化；
sub_1a2b3c 跑过一遍 string_process_program；
vm_mem + 0x100 里就是那 29 字节处理结果；
即将被复制到 vm_mem + 0x300
2. 用gdb取出寄存器的值
3. 因为前四个字符一定是SYC{，用dump和SYC{做 XOR，得到全是0x5A，所以所有字节都XOR一次0x5A，转ASC得到flag
## Mission Ghost Signal
**SYC{7h15_1S_4_9r4nD_c0N5p1r@cY.}**
1. 解密encode，一堆函数实现AES-128 + CBC + PKCS#7，key = b"Syclover2025Geek"，写脚本反推出压缩包密码是We_ve_Trapped_in_The_Sink
2. 解压拿到 1nn3r.wav，用SSTV音频转图片，出现一张二维码，扫描下载zip
3. 依旧We_ve_Trapped_in_The_Sink解压缩，得到摩斯密码音频，解码得到十六进制，转ASC码后base64解码得到flag
```python
# -*- coding: utf-8 -*-
#
# 还原 zako.exe 里那套 AES 变种 + CBC 逻辑
# 对应 IDA 里的：
#   sub_4014F6, sub_401496, sub_401546, sub_4015B4, sub_4017B8,
#   sub_4018B6, sub_401929, sub_4019B7, sub_401D41, sub_401DB1,
#   sub_401E72, sub_401EA2, sub_401CA0, sub_402992, sub_402B57
#

# Rcon 常量，对应 byte_407064
byte_407064 = [
    0x8D, 0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36,
]

# 密文常量，对应 byte_406020
byte_406020 = [
    0xB2, 0xB3, 0xDC, 0xB9, 0xF8, 0xD6, 0x93, 0xFF,
    0xB5, 0xA1, 0xCC, 0x2A, 0x6F, 0xDE, 0x27, 0x44,
    0xAF, 0x21, 0x98, 0xDD, 0x00, 0xC1, 0x0D, 0x1C,
    0x53, 0x06, 0x81, 0x3E, 0x16, 0xAB, 0xDF, 0x13,
]


# ----------------- 下面是那堆 sub_401xxx 的还原 -----------------

def sub_401460(a1, a2):
    """int __cdecl sub_401460(unsigned __int8 a1, char a2)
    8bit 左循环位移
    """
    a1 &= 0xFF
    return ((a1 << a2) & 0xFF) | (a1 >> (8 - a2))


def sub_401496(a1, a2):
    """int __cdecl sub_401496(char a1, unsigned __int8 a2)
    GF(2^8) 上的乘法 (与 0x11B 多项式)
    """
    a1 &= 0xFF
    a2 &= 0xFF
    v6 = 0
    while a2:
        if a2 & 1:
            v6 ^= a1
        if a1 & 0x80:
            v2 = 0x1B
        else:
            v2 = 0
        a1 = ((a1 << 1) & 0xFF) ^ v2
        a2 >>= 1
    return v6 & 0xFF


def sub_4014F6(a1):
    """int __cdecl sub_4014F6(unsigned __int8 a1)
    GF(2^8) 求逆：a^(2^8-2) = a^254，这里写成 a^253 * a 之类
    反编译里是 for i in 0..252 v3 = mul(v3, a1)
    """
    a1 &= 0xFF
    if a1 == 0:
        return 0
    v3 = 1
    for _ in range(253):  # 0..252 共 253 次
        v3 = sub_401496(v3, a1)
    return v3 & 0xFF


def sub_401546(a1):
    """int __cdecl sub_401546(unsigned __int8 a1)
    AES S-box 里的仿射变换部分（用 rotate + xor 实现）
    """
    a1 &= 0xFF
    v1 = sub_401460(a1, 1)
    v1 ^= a1
    v2 = sub_401460(a1, 2) ^ v1
    v3 = sub_401460(a1, 3) ^ v2
    return (v3 ^ sub_401460(a1, 4)) & 0xFF


def sub_4015B4(a1_list):
    """int __cdecl sub_4015B4(int a1, int a2)
    a1 是 8 字节，算一个 8x8 矩阵的逆，最后输出到 a2
    这里只是为了还原 sub_4017B8 ，实际上 S-box 生成时并不依赖结果
    """
    v3 = [0] * 24
    # 构造 8 个 16bit 的行
    for i in range(8):
        v14 = 0
        for j in range(8):
            if (a1_list[j] >> i) & 1:
                v14 |= 1 << j
        # 低 8 位是 v14，高 8 位是 1 << (i+8)（相当于记录单位阵）
        v3[2 * i + 8] = v14 | (1 << (i + 8))

    # 高斯消元（GF(2) 上）
    for k in range(8):
        v11 = -1
        for m in range(k, 8):
            if (v3[2 * m + 8] >> k) & 1:
                v11 = m
                break
        if v11 == -1:
            return None
        if v11 != k:
            v4 = v3[2 * v11 + 8]
            v3[2 * v11 + 8] = v3[2 * k + 8]
            v3[2 * k + 8] = v4
        for n in range(8):
            if n != k and ((v3[2 * n + 8] >> k) & 1):
                v3[2 * n + 8] ^= v3[2 * k + 8]

    # 取出逆矩阵
    for ii in range(8):
        val = v3[2 * ii + 8]
        v3[ii] = (val >> 8) & 0xFF

    out = [0] * 8
    for jj in range(8):
        v6 = 0
        for kk in range(8):
            if (v3[kk] >> jj) & 1:
                v6 |= 1 << kk
        out[jj] = v6 & 0xFF
    return out


def sub_4017B8(a1):
    """int __cdecl sub_4017B8(unsigned __int8 a1)
    生成一堆矩阵然后根据 a1 组合成一个字节，返回值在原程序里基本没用
    """
    v4 = [0] * 8
    for i in range(8):
        v1 = sub_401546(1 << i)
        v4[i] = v1 & 0xFF
    v3 = sub_4015B4(v4)
    v6 = 0
    for j in range(8):
        if (a1 >> j) & 1:
            v6 ^= v3[j]
    return v6 & 0xFF


def sub_4018B6(a3):
    """_BYTE *__cdecl sub_4018B6(int a1, int a2, unsigned __int8 a3)
    动态生成 S-box 和 inverse S-box：
        S[x] = a3 ^ sub_401546(inv(x))
    其中 inv(x) 用 sub_4014F6 算；a3 在程序里为 0xA7
    """
    _ = sub_4017B8(a3)   # 返回值没被真正用到
    sbox = [0] * 256
    inv_sbox = [0] * 256
    for i in range(256):
        v5 = sub_4014F6(i)
        v4 = a3 ^ sub_401546(v5)
        v4 &= 0xFF
        sbox[i] = v4
        inv_sbox[v4] = i
    return sbox, inv_sbox


# 生成一次全局 SBOX / INV_SBOX，对应 sub_401929 用到
SBOX, INV_SBOX = sub_4018B6(0xA7)


def sub_401929(a1):
    """int __cdecl sub_401929(unsigned __int8 a1)
    取 S-box
    """
    a1 &= 0xFF
    return SBOX[a1]


def sub_401D41(state):
    """int __cdecl sub_401D41(int a1)
    SubBytes，逐列逐行调用 sub_401929
    state: 长度 16 的 list
    """
    for i in range(4):
        for j in range(4):
            idx = i + 4 * j
            state[idx] = sub_401929(state[idx]) & 0xFF


def sub_401DB1(state):
    """_BYTE *__cdecl sub_401DB1(_BYTE *a1)
    ShiftRows
    state: 长度 16 的 list
    """
    # row1 左移 1
    v2 = state[1]
    state[1] = state[5]
    state[5] = state[9]
    state[9] = state[13]
    state[13] = v2

    # row2 左移 2
    v3 = state[2]
    state[2] = state[10]
    state[10] = v3
    v4 = state[6]
    state[6] = state[14]
    state[14] = v4

    # row3 左移 3（= 右移 1）
    v5 = state[3]
    state[3] = state[15]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = v5


def sub_401E72(a1):
    """int __cdecl sub_401E72(unsigned __int8 a1)
    xtime：乘以 2 的 GF(2^8) 运算
    """
    a1 &= 0xFF
    return ((a1 << 1) & 0xFF) ^ (0x1B * (a1 >> 7))


def sub_401EA2(state):
    """int __cdecl sub_401EA2(int a1)
    MixColumns
    """
    for i in range(4):
        col = 4 * i
        v3 = state[col]
        v2 = state[col + 2] ^ state[col + 1] ^ v3 ^ state[col + 3]
        v2 &= 0xFF
        state[col + 0] = (v2 ^ sub_401E72(v3 ^ state[col + 1]) ^ v3) & 0xFF
        state[col + 1] = (state[col + 1] ^ v2 ^
                          sub_401E72(state[col + 1] ^ state[col + 2])) & 0xFF
        state[col + 2] = (state[col + 2] ^ v2 ^
                          sub_401E72(state[col + 2] ^ state[col + 3])) & 0xFF
        state[col + 3] = (state[col + 3] ^ v2 ^
                          sub_401E72(v3 ^ state[col + 3])) & 0xFF


def sub_4019B7(key_bytes):
    """void __cdecl sub_4019B7(int a1, int a2)
    AES-128 密钥扩展，生成 44 个 word（11 轮 * 4 列）
    key_bytes: 16 字节的 list
    返回 176 字节的 round key 列表
    """
    assert len(key_bytes) == 16
    rk = [0] * (4 * 44)  # 176 bytes

    # 先拷贝原始 key
    for i in range(4):
        rk[4 * i + 0] = key_bytes[4 * i + 0] & 0xFF
        rk[4 * i + 1] = key_bytes[4 * i + 1] & 0xFF
        rk[4 * i + 2] = key_bytes[4 * i + 2] & 0xFF
        rk[4 * i + 3] = key_bytes[4 * i + 3] & 0xFF

    # 扩展到 44 个 word
    for j in range(4, 44):
        idx_prev = 4 * (j - 1)
        v2 = rk[idx_prev]
        v4 = rk[idx_prev + 1]
        v5 = rk[idx_prev + 2]
        v6 = rk[idx_prev + 3]

        if (j & 3) == 0:  # 每 4 个 word 做一次 S 盒 + Rcon
            v8 = rk[idx_prev]
            v3 = sub_401929(v4)
            v4 = sub_401929(v5)
            v5 = sub_401929(v6)
            v6 = sub_401929(v8)
            v2 = v3 ^ byte_407064[j >> 2]

        idx_prev4 = 4 * (j - 4)
        rk[4 * j + 0] = (rk[idx_prev4 + 0] ^ v2) & 0xFF
        rk[4 * j + 1] = (rk[idx_prev4 + 1] ^ v4) & 0xFF
        rk[4 * j + 2] = (rk[idx_prev4 + 2] ^ v5) & 0xFF
        rk[4 * j + 3] = (rk[idx_prev4 + 3] ^ v6) & 0xFF

    return rk


def sub_401CA0(round_idx, state, rk):
    """int __cdecl sub_401CA0(unsigned __int8 a1, int a2, int a3)
    AddRoundKey
    round_idx: 0..10
    state: 16 字节 list
    rk: 176 字节 list
    """
    base = 16 * round_idx
    for i in range(4):
        for j in range(4):
            idx = j + 4 * i
            state[idx] ^= rk[base + 4 * i + j]
            state[idx] &= 0xFF


def sub_402992(block16, rk):
    """int __cdecl sub_402992(_BYTE *a1, int a2)
    AES-128 加密一个 16 字节块（对应 C 里的 10 轮）
    in-place 修改 block16
    """
    # 初始 AddRoundKey
    sub_401CA0(0, block16, rk)

    # 中间 1~9 轮
    for r in range(1, 10):
        sub_401D41(block16)   # SubBytes
        sub_401DB1(block16)   # ShiftRows
        sub_401EA2(block16)   # MixColumns
        sub_401CA0(r, block16, rk)

    # 最后一轮（无 MixColumns）
    sub_401D41(block16)
    sub_401DB1(block16)
    sub_401CA0(10, block16, rk)


def sub_402B57_encrypt(rk, iv_bytes, buf):
    """nt __cdecl sub_402B57(_DWORD *a1, _BYTE *a2, unsigned int a3)
    CBC 模式加密：
        v7 初始指向 IV；
        每块先 XOR v7，再走 sub_402992，然后 v7 指向当前密文。
    rk: 176 字节 round key
    iv_bytes: 16 字节 list
    buf: 明文 list，长度是 16 的倍数
    返回密文 list
    """
    assert len(iv_bytes) == 16
    assert len(buf) % 16 == 0
    prev = iv_bytes[:]
    out = buf[:]

    for off in range(0, len(out), 16):
        block = out[off:off + 16]

        # sub_402B11: block ^= prev
        for i in range(16):
            block[i] ^= prev[i]
            block[i] &= 0xFF

        # AES 一块
        sub_402992(block, rk)

        # 写回并更新 CBC 链
        out[off:off + 16] = block
        prev = block[:]

    return out


# ----------------- 额外：反向（解密）部分，方便反推 buffer -----------------

def inv_sub_bytes(state):
    for i in range(16):
        state[i] = INV_SBOX[state[i] & 0xFF] & 0xFF


def inv_shift_rows(state):
    # 直接调用正向 shift_rows 三次 = 逆向
    for _ in range(3):
        sub_401DB1(state)


def inv_mix_columns(state):
    # 使用 GF(2^8) 乘法实现逆 MixColumns
    for i in range(4):
        col = 4 * i
        s0, s1, s2, s3 = [state[col + j] & 0xFF for j in range(4)]
        state[col + 0] = (sub_401496(s0, 14) ^ sub_401496(s1, 11) ^
                          sub_401496(s2, 13) ^ sub_401496(s3, 9)) & 0xFF
        state[col + 1] = (sub_401496(s0, 9) ^ sub_401496(s1, 14) ^
                          sub_401496(s2, 11) ^ sub_401496(s3, 13)) & 0xFF
        state[col + 2] = (sub_401496(s0, 13) ^ sub_401496(s1, 9) ^
                          sub_401496(s2, 14) ^ sub_401496(s3, 11)) & 0xFF
        state[col + 3] = (sub_401496(s0, 11) ^ sub_401496(s1, 13) ^
                          sub_401496(s2, 9) ^ sub_401496(s3, 14)) & 0xFF


def decrypt_block(block16, rk):
    """AES-128 单块解密，对应加密的逆过程"""
    # 先和最后一轮 round key 异或
    sub_401CA0(10, block16, rk)
    inv_shift_rows(block16)
    inv_sub_bytes(block16)

    # 9..1 轮
    for r in range(9, 0, -1):
        sub_401CA0(r, block16, rk)
        inv_mix_columns(block16)
        inv_shift_rows(block16)
        inv_sub_bytes(block16)

    # 最初轮的 AddRoundKey
    sub_401CA0(0, block16, rk)


def cbc_decrypt(rk, iv_bytes, cipher):
    """CBC 解密，用来从 byte_406020 反推出明文"""
    assert len(cipher) % 16 == 0
    prev = iv_bytes[:]
    out = []

    for off in range(0, len(cipher), 16):
        block = cipher[off:off + 16]
        tmp = block[:]   # 当前密文备份，后面当下一块的 prev

        decrypt_block(block, rk)
        for i in range(16):
            block[i] ^= prev[i]
            block[i] &= 0xFF

        out.extend(block)
        prev = tmp

    return out


# ----------------- demo：验证加密 == 常量 & 反推明文 -----------------

def demo():
    key = b"Syclover2025Geek"         # 你给的 key
    iv = b"1145141145144332"          # 程序里 qmemcpy 的 IV

    # 1) 按程序逻辑加密我们猜出的明文，验证是否等于 byte_406020
    flag_plain = b"We_ve_Trapped_in_The_Sink"  # 25 字节
    padded = list(flag_plain + b"\x07" * 7)    # PKCS#7：补 7 个 0x07

    round_keys = sub_4019B7(list(key))
    cipher = sub_402B57_encrypt(round_keys, list(iv), padded)

    print("cipher:", [hex(x) for x in cipher])
    print("cipher == byte_406020 ?", cipher == byte_406020)

    # 2) 从 byte_406020 反推明文（CBC 解密）
    plain_full = cbc_decrypt(round_keys, list(iv), byte_406020[:])
    print("plain (with padding):", bytes(plain_full))
    pad_len = plain_full[-1]
    print("plain (strip padding):", bytes(plain_full[:-pad_len]))


if __name__ == "__main__":
    demo()
```
## GeekBinder
**SYC{An@Iyz1ng_Th3_proc3ss3s_B3Tween_File3_1s_contr@ry_To_n0rm@l_pr@ctic3_1n_Re_eng1neer1ng}k3+1**
我没有docker环境，配置的时候又出来一堆问题，一气之下把bin的client文件丢进HxD扫一遍SYC，发现一些明显异常的字符：

/workspace/syc_source/ptrace/geek/src/server/service_attr.c�attr_xor_cipher�����dlsym(attr_xor_cipher) å¤±è´¥: %s�attr_get_hidden_cipher��������dlsym(attr_get_hidden_cipher) å¤±è´¥: %s�æˆåŠŸåŠ è½½ %s�E�W�I�D�?�[%02d:%02d:%02d][%s][%s:%d] �[--:--:--][%s][%s:%d] ������������������ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/

不难猜出是XOR + Base64 的某种加密，（IDA里反汇编也有这些字符）
受到鼓励把server和libattr.so也丢进HxD了，出现了geek2025和一堆字符，前后都是00，试着用 "geek2025" 去 XOR 这段密文的前 8 字节，结果对应的ASC码正好是SYC{An@I，所有都处理一遍得到flag
```python
data_hex = """
67 65 65 6B 32 30 32 35 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 34 3C 26 10 73 5E 72 7C 1E 1F 54 05 55 6F 66 5D
54 3A 15 19 5D 53 01 46 14 56 16 34 70 03 66 42 02 00 0B 34 74 59 5E 50
54 3A 54 18 6D 53 5D 5B 13 17 25 19 4B 6F 66 5A 38 0B 55 19 5F 70 5E 6A
17 17 25 08 46 59 51 06 38 54 0B 34 60 55 6D 50 09 02 54 05 57 55 40 04
09 02 18 00 01 1B 03 3B ...
""".replace("\n", " ").strip()

bs = bytes(int(x, 16) for x in data_hex.split())

key = b"geek2025"
cipher = bs[0x20:0x80]                 # 从偏移 0x20 开始的 0x60 字节
plain = bytes(c ^ key[i % len(key)] for i, c in enumerate(cipher))

print(plain.decode("latin1"))
```

# CRYPTO
## ez_xor
**syc{we1c0me_t190_ge1k_your_code_is_v1ey_de1psrc!}**
1. 这是一个四素数RSA：N = p·q·r·s
额外给了：
n = p*q
gift = p ^ q（只知道 p 和 q 的异或）
gift1 = s & r
gift2 = s ^ r
2. 只针对模 r*s 做“局部 RSA 解密”：
先计算：
φ_sr = (r-1)(s-1)
d1 ≡ e^{-1} (mod φ_sr)
然后计算：
m_sr = c^{d1} mod (r*s)
因为 0 ≤ m < r*s，所以
m_sr ≡ m (mod r*s) 其实就是 m 本身。
3. exp
```python
from Crypto.Util.number import *
import math

N = 12114282140129030221139165720039766369206816602912543911543781978648770300084428613171061953060266384429841484428732215252368009811130875276347534941874714457297474025227060487490713853301440917877280771734998220874195868270983517296552761924477514745040473578887509936945790259245154138347432294762694643113545451605193155323886625417458980089197202274810691448592725400564114850712497863770625334209249566232989992606497076063348029665644680946906322428277225178838518025623254240893146791821359089473224900379808514993113560101567320224162858217031176854613011276425771708406954417610317789259885040739954642374667
n = 91891351711379799931394178123406137903027189477005569059936904007248535049052097057222486024223574959494899324706948906013350601442586596023020519058250868888847562977333671773188012014902448961387215600156932673504112816058893268362611211565216592933077956777032650164332488098756557422740070442941348084921
c = 3231265723829112665640925095346482445691074656152495613367006320791218303024667683148786980985160622882017055128261102169256263170652774489339801477001275058585666508737704987192764426162573977263344192886400249198007892940084066468570229353879431384001463041292940472308358540532108957894938586227682908251475990882169979412586767210087025064295224506676379057986353004282550774815876093769770845018817117647615011444989401149674886486770646765454314760906436659162076044268401041579090930954919862146749470426101754009562077505810024012143379326028465156444246440949112724465484939452061684185387430755268355807999
gift1 = 10475668758451987289276918780968515546700284023143612685496241510488708701498972819305540608876501965534227236009502810417525671358108167575178008316645429
gift2 = 2089035701361172996472331829521141923363322027241591404259262848963755908765054555529259508147866255819680957406084877552079796025933552021516283158425474
e = 65537

# 1. 还原 s、r
SR = N // n              # = s * r
S_sr = gift2 + 2 * gift1 # = s + r

disc = S_sr*S_sr - 4*SR
sqrt_disc = math.isqrt(disc)
assert sqrt_disc * sqrt_disc == disc

s = (S_sr + sqrt_disc) // 2
r = (S_sr - sqrt_disc) // 2
assert s * r == SR

# 2. 只对模 s*r 做 RSA 解密
phi_sr = (s-1)*(r-1)
d1 = inverse(e, phi_sr)

m = pow(c, d1, SR)
flag = long_to_bytes(m)
print(flag)
```
## baby_rabin
**syc{th1s_so_1z_mum_never_ca1r_mytstu1d}**
flag 很短（几十字节），作为整数 𝑚时远远小于 512 bit 的素数,在模𝑟下不会绕圈，𝑚本身就是模 𝑟的代表元。只需要在模𝑟上解方程找到的 8 次方根中，小于𝑟且能正常解码为 ASCII 字符串的那个，就是明文。
```python
from math import gcd

C = 451731346880007131332999430306985234187530419447859396067624968918101700861978676040615622417464916959678829732066195225132545956101693588984833424213755513877236702139360270137668415610295492436471366218119012903840729628449361663941761372974624789549775182866112541811446267811259781269568865266459437049508062916974638523947634702667929562107001830919422408810565410106056693018550877651160930860996772712877149329227066558481842344525735406568814917991752005
n = 491917847075013900815069309520768928274976990404751846981543204333198666419468384809286945880906855848713238459489821614928060098982194326560178675579884014989600009897895019721278191710357177079087876324831068589971763176646200619528739550876421709762258644696629617862167991346900122049024287039400659899610706153110527311944790794239992462632602379626260229348762760395449238458507745619804388510205772573967935937419407673995019892908904432789586779953769907
hint = 66035251530240295423188999524554429498804416520951289016547753908652377333150838269168825344004730830028024338415783274479674378412532765763584271087554367024433779628323692638506285635583547190049386810983085033061336995321777237180762044362497604095831885258146390576684671783882528186837336673907983527353

# 1. 求 r
r = n // hint

def tonelli_3mod4(a, p):
    # p ≡ 3 mod 4 时的平方根
    return pow(a, (p + 1) // 4, p)

Cr = C % r

# 连续三次开平方（8 次方根）
y1 = tonelli_3mod4(Cr, r)
cands1 = [y1, (-y1) % r]

cands2 = []
for y in cands1:
    z = tonelli_3mod4(y, r)
    cands2 += [z, (-z) % r]

cands3 = []
for z in cands2:
    x = tonelli_3mod4(z, r)
    cands3 += [x, (-x) % r]

roots = []
for x in set(cands3):
    if pow(x, 8, r) == Cr:
        roots.append(x)

def long_to_bytes(x: int) -> bytes:
    h = hex(x)[2:]
    if len(h) % 2:
        h = "0" + h
    return bytes.fromhex(h)

for x in roots:
    b = long_to_bytes(x)
    try:
        s = b.decode()
        print(s)
    except UnicodeDecodeError:
        pass
```
## ez_ecc
从 challenge.json 里读出曲线参数 p, A, B 和两点坐标 P, Q。在 Sage 中构造椭圆曲线 E: y² = x³ + Ax + B (mod p)，并把点 P、Q 放到曲线上。使用 Sage 自带的离散对数函数得到整数 k 后，用 long_to_bytes(k) 转成字节串，就是原始 flag。
```python
p  = 0xfba8cae6451eb4c413b60b892ee2d517dfdb17a52451776a68efa34485619411
A  = 0x1ef1e93d0f9acda1b7c0172f27d28f3a7d0f2d9343513a3aac191e12f6e51123
B  = 0xcad65954bbe0fb8f2f9c22b5cae1aa42306fd58e8394652818e781e5f808e17a

P_x = 0x708c0cf66f132122f3fcd1f75c6f22d4a90d34650dd81fb3a57b75dad98d35e7
P_y = 0xcfb017daf37cbba3c6a5c6e7c4327692595c16b47e4bfa1ad400bffe5b500fba

Q_x = 97490713033364940809544067604441149095210096571946998449251275861394744757515
Q_y = 32198694245056943922016695558131047889851279706531342583322750112905104448879

F = GF(p)
E = EllipticCurve(F, [A, B])

P = E(P_x, P_y)
Q = E(Q_x, Q_y)

# 求 k : Q = k * P
k = Q.log(P)
print("k =", int(k))

# k -> flag
n = int(k)
L = (n.bit_length() + 7) // 8
flag = n.to_bytes(L, "big")
print("flag =", flag)
```
## eazy_RSA?
**SYC{y0u_sh0u1d_learn_a_l0t_a0bout_LLL}**
利用给出的 LWE 形式，先得到 inner = 44972，枚举小的𝑘和 error，解方程，题目给了用每个候选 
𝑚计算 𝑝再算gcd。用给出的 c_inner 和我们算出的 inner = 44972 得到c,再 long_to_bytes(m_flag) 就得到最终的 flag 字符串.
```python
from Crypto.Util.number import inverse, long_to_bytes
from math import gcd

# ===================== 题目给的参数（抄进去即可） =====================

# LWE 部分参数
q1 = 65537
p1 = 257
delta = round(q1 / p1)           # = 255
error_bound = int((q1 / p1) // 2)

# 向量维度（题里是 64）
n1 = 64

# 下面这几个都从题目里复制完整数字
b = 2764

# A, S 是模 q1 的 64 维向量（题目里有完整一行）
A = [
    16147, 54417, 37346, 48225, 25834, 16202, 9615, 504, 54090,
    # ... 这里继续把 64 个数抄完 ...
]
S = [
    34790, 60770, 29429, 54388, 22694, 50136, 13438, 7932, 466,
    # ... 这里继续把 64 个数抄完 ...
]

# RSA 部分参数
n = int("122559396923126188518673248748225863862082328215893788075556"
        "..."  # 把 n 的完整十进制字符串贴上来
        "9011550620881300518596006433001049004445597176250937388576661809")

e = 65537

c_inner = int("833994314729991946902167056151690363064639588877950070"
              "..."  # c_inner 完整十进制
              "9785202880542117272251300802452717688849566335597550131883378114")

p_m = int("12332486510964011158671675941288876941680648099414795378886"
          "..."  # p_m 完整十进制
          "0330241399720401327967071598143881618549530749656312652927809332")

Q = int("176099484942541970018670625193112600772119842931516675489004"
        "..."  # Q 完整十进制
        "9812056921940398538003527621201520818008358558845582594247420459")

P = int("206528871909572392846311753400039023151262119381810930642072"
        "..."  # P 完整十进制
        "0420842104873391074567329742472001229790402635829640092130822763")

# ===================== 1. 先算 inner = A · S (mod q1) =====================

inner = sum(a * s for a, s in zip(A, S)) % q1
print("[+] inner = A·S mod q1 =", inner)

# ===================== 2. 解一元 LWE，求 m =====================
# 已知： b ≡ A·S + m*delta + error (mod q1), |error| <= error_bound
# 设 t = (b - inner) mod q1 = m*delta + error (mod q1)

t = (b - inner) % q1
print("[+] t =", t)

candidates = []
# k 控制 “模 q1 的回绕次数”，一般很小（这里 ±5 足够）
for k in range(-5, 6):
    for err in range(-error_bound, error_bound + 1):
        num = t + k * q1 - err
        if num % delta != 0:
            continue
        m = num // delta
        if m >= 0:
            candidates.append(m)

candidates = sorted(set(candidates))
print("[+] candidate m list:", candidates)

# ===================== 3. 用 gcd(N, p_m + m) 选出真正的 m 和 p =====================

real_m = None
real_p = None

for m in candidates:
    p = p_m + m
    g = gcd(p, n)
    if 1 < g < n:
        real_m = m
        real_p = g
        break

if real_m is None:
    raise ValueError("[-] 没找到合适的 m，检查 A/S/b/p_m/n 是否抄错")

print("[+] real m =", real_m)
print("[+] p =", real_p)

p = real_p
q = n // p
print("[+] q =", q)

# ===================== 4. 恢复真正的 c 并 RSA 解密 =====================

phi = (p - 1) * (q - 1)
d = inverse(e, phi)

# 题目里打印的是 c_inner = c - inner，所以 c = c_inner + inner
c = c_inner + inner

m_flag = pow(c, d, n)
flag = long_to_bytes(m_flag)

print("[+] raw flag bytes:", flag)
print("[+] flag string   :", flag.decode(errors="ignore"))
```
## pem
**SYC{PEM_1s_n0t_only_S5l}**
用文本编辑器 / cat 看一下 key.pem,可以看到典型的 RSA 私钥头,说明这是标准 RSA 私钥,用私钥对 enc 做一次 RSA 解密，看明文.
## Caesar Slot Machine
**SYC{you_found_the_fixed_point}**
构造不动点,服务端迭代的其实是线性同余变换,只要 x 是 T 的不动点即可,因为 P 是大素数，a ∈ [2, P-1]，所以 (a-1) 一定与 P 互素，存在逆元,于是我们每一轮只要算出这个 x，提交即可保证.
```python
#!/usr/bin/env python3
import socket
import re
import sys

HOST = "geek.ctfplus.cn"
PORT = 30164

# 匹配一段里出现的三组数字 a, b, P
# 形式类似于 "... 123 ... 456 ... 1000000007 ..."
NUM_PATTERN = re.compile(rb"(\d+)\D+(\d+)\D+(\d+)")


def modinv(a, m):
    """计算 a 在 mod m 下的乘法逆元"""
    a %= m
    if a == 0:
        raise ValueError("no inverse for 0")

    # 扩展欧几里得算法
    r0, r1 = m, a
    s0, s1 = 1, 0
    t0, t1 = 0, 1

    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        s0, s1 = s1, s0 - q * s1
        t0, t1 = t1, t0 - q * t1

    if r0 != 1:
        raise ValueError("a and m are not coprime")

    return t1 % m


def inv_mod(a, m):
    """优先用 pow，兼容老版本再用扩展欧几里得"""
    try:
        return pow(a, -1, m)
    except TypeError:
        return modinv(a, m)


def main():
    try:
        s = socket.create_connection((HOST, PORT))
    except Exception as e:
        print(f"[-] 无法连接 {HOST}:{PORT} -> {e}")
        sys.exit(1)

    s.settimeout(10.0)
    buf = b""

    print(f"[+] Connected to {HOST}:{PORT}")

    # 先尝试读一波欢迎信息
    try:
        first = s.recv(4096)
        if first:
            buf += first
            print("[*] welcome / banner:")
            print(first.decode(errors="ignore"))
    except socket.timeout:
        pass

    try:
        for round_idx in range(1, 31):
            # 一直读，直到缓冲区里能解析出 a,b,P
            while True:
                m = NUM_PATTERN.search(buf)
                if m:
                    a = int(m.group(1))
                    b = int(m.group(2))
                    P = int(m.group(3))

                    print(f"\n===== Round {round_idx} =====")
                    print(f"[*] parsed a={a}, b={b}, P={P}")

                    # 把已经用掉的部分从 buf 里裁掉
                    buf = buf[m.end():]
                    break

                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    print("[-] 等待 a,b,P 超时，服务器没回数据")
                    return

                if not chunk:
                    print("[-] 连接被服务器关闭（还没拿到 a,b,P 就断了）")
                    return

                buf += chunk

            # 解线性同余：(a - 1) * x ≡ -b (mod P)
            inv = inv_mod(a - 1, P)
            x = (-b * inv) % P

            print(f"[*] Round {round_idx} 发送 x = {x}")
            s.sendall(str(x).encode() + b"\n")

            # 读一点回应放进 buf，方便下一轮一起解析
            try:
                resp = s.recv(4096)
                if resp:
                    buf += resp
                    print("[*] server resp snippet:")
                    print(resp.decode(errors="ignore"))
            except socket.timeout:
                print("[*] 本轮响应读取超时，继续下一轮（数据会在后面一并读到）")

        # 30 轮都发完后，把剩余数据都读出来
        all_data = buf
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                all_data += chunk
        except socket.timeout:
            pass

        text = all_data.decode(errors="ignore")

    except Exception as e:
        print("[-] 过程中出现异常：", e)
        s.close()
        return

    s.close()

    print("\n[+] 收到的全部文本：\n")
    print(text)

    # 尝试从文本中自动提取 Flag
    m = re.search(r"Flag:\s*([^\s]+)", text, re.IGNORECASE)
    if m:
        print("\n[+] FLAG =", m.group(1))
    else:
        print("\n[!] 没能自动提取到 Flag，请在上面的输出里手动找一下 `Flag:` 那行")


if __name__ == "__main__":
    main()
```
⁡
## xor_revenge
**SYC{hahaha_th1_factor_is_N0t_ha16}**
第 1 关只检查能否整除,这里只判断 n % p == 0，没有要求 p 是素数，也没有要求 1 < p < n。
因此我们可以直接令：p = n,因为 n % n == 0 恒成立，第一关直接通过。
第 2 关无论对错都会发 flag
```python
from pwn import *

HOST = "geek.ctfplus.cn"
PORT = 31026

def main():
    io = remote(HOST, PORT)

    print(io.recvline().decode().strip())  # welcome...
    io.sendline(b"hi")                     # 任意回复
    print(io.recvline().decode().strip())  # wel_come...
    print(io.recvline().decode().strip())  # I can give you

    n_line = io.recvline().decode().strip()    # n=...
    gift1_line = io.recvline().decode().strip()# gift1=...
    print(n_line)
    print(gift1_line)

    n = int(n_line.split("=", 1)[1].strip())

    # 第一关直接发 n 本人
    io.sendline(str(n).encode())
    print(io.recvline().decode().strip())      # wow,you find p...

    # 读取第二关提示，直到 r= 那一行即可
    for _ in range(6):
        line = io.recvline().decode().strip()
        print(line)
        if line.startswith("r="):
            break

    # 第二关随便发一个数
    io.sendline(b"1")

    # 收剩余输出，其中包含 flag
    rest = io.recvall(timeout=2).decode(errors="ignore")
    print(rest)

if __name__ == "__main__":
    main()
```
## S_box
**SYC{SS_B0xx_I1s_ver1y_Differe1c999c}**
AES 使用的 key = long_to_bytes(key1)，而 key1、Cipher、IV 都被明文发给了我们，所以直接本地按同样参数做 AES-CBC 解密就能恢复原始 flag。
```python
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
import ast

HOST = "geek.ctfplus.cn"
PORT = 31450

io = remote(HOST, PORT)

key1_int = int(io.recvline().strip())

cipher_line = io.recvline().strip().decode()
cipher_bytes = ast.literal_eval(cipher_line.split("Cipher=")[1])

iv_line = io.recvline().strip().decode()
iv_bytes = ast.literal_eval(iv_line.split("IV=")[1])

key_bytes = long_to_bytes(key1_int)
cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
plaintext_padded = cipher.decrypt(cipher_bytes)
flag = unpad(plaintext_padded, AES.block_size)

print("flag =", flag.decode())
io.close()
```
## dp_spill
**SYC{644684707c540998d760975fb98a816a469ec567abe5c8004164d3ce887c6a8e}**
p, q 是 512 bit 素数；GCD(p-1, q-1) == 2，说明 (p-1), (q-1) 只共享一个 2 的因子；随机选了一个 20 bit 的 d_p（即 d mod (p-1) 比较小），再随机选 d_q，用 CRT 拼成全局私钥 d，然后才算出 e。这是一个 RSA 题，要分解 n。
（还没等我开算，丢给ai一下就把答案甩过来了，奇怪，应该是dp暴力出素因子）
```python
from Crypto.Util.number import inverse, getPrime, GCD
from sympy.ntheory.modular import solve_congruence
import random, hashlib

def CRT(a, m, b, n):
    val, mod = solve_congruence((a, m), (b, n))
    return val

def gen_key():
    while True:
        p = getPrime(512)
        q = getPrime(512)
        if GCD(p-1, q-1) == 2:
            return p, q

def get_e(p, q, BITS):
    while True:
        d_p = random.randint(1, 1 << BITS)    # 只给了 d_p 20bit
        d_q = random.randint(1, q - 1)
        if d_p % 2 == d_q % 2:
            d = CRT(d_p, p - 1, d_q, q - 1)   # 用 d_p, d_q 拼出全局 d
            e = inverse(d, (p - 1) * (q - 1)) # e = d^{-1} mod φ(n)
            return e

BITS = 20
p, q = gen_key()
n = p * q
e = get_e(p, q, BITS)
s = str(p + q).encode()
flag_hash = hashlib.sha256(s).hexdigest()
flag = f"SYC{{{flag_hash}}}"
```


# MISC
## 🗃️🗃️
**SYC{北京市_天坛公园}**(天坛还是景山我忘了)
1. foremost提取一下，找到经纬度去搜
![alt text](image.png)
2. AI也可以直接识别出来地点
## Blockchain SignIn
**SYC{w3b3_g4m3_st4rt}**
Etherscan的Sepolia搜索题目交易，Input Data用UTF-8查看
## 1Z_Sign
**SYC{0.99%}**
搜索题目给的txhash，在 Logs 中查看池子的 fee

   
