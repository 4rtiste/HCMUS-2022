# HCMUS-2022
## Chall 1

Đây là monoalphabetic cipher, đưa đoạn văn bản lên [dcode.fr](https://www.dcode.fr/) để decrypt.
## Chall 2
Vẫn là monoalphabetic cipher nhưng ở đây mỗi 5 ký tự sẽ được filter cùng 1 offset. Tạo một table offset rồi decrypt filter. Sau đó vẫn đưa lên [dcode.fr](https://www.dcode.fr/) để decrypt.
## Chall 3
Ở đây đề bài cho 665 số đầu của hàm randrange(), và có một công cụ là `randcrack` để dự đoán số tiếp theo, và với độ lớn của các số sinh ra, ta chỉ cần input 624 số cuối.
## Chall 4
Để ý thấy thì mỗi n với phi có 1 đoạn đầu giống nhau, ý tưởng là tính số high bit giống nhau giữa n và phi, sau đó lấy bit_length của n chia cho số đó, kết quả chính là số primes tạo thành n. Kết quả không đúng 100% nên bỏ vào vòng while đến khi nào đúng hết 60 states.
```python
from Crypto.Util.number import *
from pwn import *
from factordb.factordb import FactorDB
import math

def div_gen(n):
    z = []
    for i in range(4,20):
        if n % i == 0:
            z.append(i)
    if len(z) ==0:
        n = n-1
    for i in range(4,20):
        if n % i == 0:
            z.append(i)
    if len(z) ==0:
        n = n-1
    for i in range(4,20):
        if n % i == 0:
            z.append(i)
    
    return z
while True:
    flag = b''
    r = remote("103.245.250.31", 30521)
    for abcd in range(60):
        print(abcd)
        r.recvuntil(b'This is public key: ')
        n = int(r.recvline())
        r.recvuntil(b'Here is a little hint phi(N): ')
        phi = int(r.recvline())
        dont_know = 0
        len_n = (bin(n)[2:])
        len_phi = (bin(phi)[2:])
        for i in range(len(len_n)):
            if len_n[i]==len_phi[i]:
                dont_know+=1
            else:
                break
        r.recvuntil(b'How many primes factors does N have: ')
        r.sendline(str(len(len_n)//dont_know).encode())
        text =r.recvline()
        print(text)
        if b'Great job. Here is your flag:' in text:
            flag = text
            break
        if text == b'Wrong numbers of prime factors. Lucky next time\n':
            r.close()
            break
    if(flag):
        print(flag)
        break
 ```
 ## Chall 5
 Sign chuỗi `b'\x00` thì ta sẽ được k[0] * 0 , sau đó server filter `k = k + 1` sẽ được k = 1 và r lúc này sẽ = g, còn s sẽ = h - (g * x), với dữ kiện đó ta tính ngược lại x rồi sau đó dùng x tự sign cho mình chuỗi mà server yêu cầu.
