---
title: "Write-ups REV CTF"
author: "thunebae"
date: 2021-10-06T12:00:06+09:00
description: "Some write-ups of CTF contests that I solved before"
tags:
- write-up
- CTF
- RE
- rev
series:
- Write-ups CTF
categories:
- Write-ups CTF
libraries:
- Write-ups CTF
image: "images/feature1/mathbook.png"
---
# ImaginaryCTF-Write-up
## 1. stings
Đầu tiên, ta phải kiểm tra định dạng file.

{{< img src="/images/CTF/stings/fileStings.jpg" title="Hình 1" caption="File stings" alt="fileStings" >}}

Như ta thấy trong hình trên, stings là file ELF 64-bit LSB pie excutetable, x86-64 => sử dụng IDApro 64-bit

Chạy thử trên máy ảo xem có gì trong trỏng.

{{< img src="/images/CTF/stings/runStings.PNG" title="Hình 2" caption="Chạy demo" alt="Chạy demo" >}}

File này hoá ra là một con ong thích chơi trò mật mã. Nếu bạn đoán đúng mật khẩu thì không bị chích. Còn đoán sai thì chetcondime bạn rồi.

Giờ mới xài IDApro 64-bit phân tích file.

Nhìn qua một nùi hàm thì chỉ có hàm main là hàm sẽ giúp chúng ta không bị ong chích. Xem mã giả của hàm main.

Hàm main khai báo nguyên một nùi biến local. Để tránh quan tâm những thành phần không cần thiết, ta tìm chỗ nào có liên quan đến password trước. Đó là dòng 64 đến 79 trong mã giả.

{{< img src="/images/CTF/stings/idapro.PNG" title="Hình 3" caption="IDAPro64" alt="IDAPro64" >}}

v13 chính là chuỗi mà chúng ta nhập vào ở dòng 64. Dựa vào vòng lặp for từ dòng 65, ta đoán được rằng password có 35 ký tự. Dòng 67-71 cho ta biết rằng password có các ký tự liên tiếp có mã ascii bằng các byte liên tiếp tương ứng trừ đi 1 tính từ byte đầu tiên của v14 (dòng 67) trên stack của hàm main (Nếu không thoả sẽ in ra dòng chữ "I'm disappointed. *stings you*" và bị ong cắn). Vậy nên, chúng ta cần quan sát các khai báo biến local của hàm main để xem thứ tự các biến trong stack như nào.

{{< img src="/images/CTF/stings/localvar.PNG" title="Hình 4" caption="Biến cục bộ" alt="Biến cục bộ" >}}

Như vậy, tính từ đỉnh stack theo chiều từ dưới lên trên, kể từ v14, ta có thức tự các biến như sau v14->v15->v16->v17->v18. May thay mấy biến này đều đã được gán giá trị lại còn đủ 35 bytes và mấy nùi code rối rắm còn lại không gây ảnh hưởng đến các giá trị này và khi tới dòng 67-71 chỉ cần lấy chúng ra và quất.

{{< img src="/images/CTF/stings/valueVar.PNG" title="Hình 5" caption="Code assembly" alt="Code assembly" >}}

*Chú ý*: little-endian, lưu mảng bytes từ dưới lên trên stack.

v14 = 0x7375747C6775646A

v15 = 0x3473356074686F32

v16 = 0x346565326960756F

v17 = 0x623233633832606F

v18 = 0x7E3A37

{{< highlight python "linenos=table,linenostart=0" >}}
def hexToAscii(hexx):
    ascii = ""
    for i in range(0, len(hexx), 2):
        part = hexx[i: i+2]
        ascii += chr(int(part, 16) - 1)
    return ascii[::-1]

v14 = "7375747C6775646A"
v15 = "3473356074686F32"
v16 = "346565326960756F"
v17 = "623233633832606F"
v18 = "7E3A37"
print(hexToAscii(v14) + hexToAscii(v15) + hexToAscii(v16) + hexToAscii(v17) + hexToAscii(v18))
{{< / highlight >}}

{{< img src="/images/CTF/stings/result.PNG" title="Hình 6" caption="Kết quả" alt="Kết quả" >}}

{{% alert theme="info" %}}**FLAG:** ictf{str1ngs_4r3nt_h1dd3n_17b21a69}{{% /alert %}}

# UIUCTF
## 1. hvhpgs{synt}
Sau khi sử dụng IDApro, ta thấy chuỗi s nhập vào được lưu vào v3 (dòng 22). Sau đó qua một nùi code hong làm thay đổi v3 thì tới dòng 30 - 36, các ký tự của chuỗi nhập vào được chuyển qua 2 hàm lần lượt là rot và shift, nếu chuỗi thay đổi bằng "azeupqd_ftq_cgqefuaz_omz_ymotuzqe_ftuzwu_bdabaeq_fa_o" thì ta sẽ được flag.

{{< img src="/images/CTF/hvhpgs{synt}/IDApro.PNG" title="Hình 6" caption="Mã giả" alt="Mã giả" >}}


Vì vậy, chúng ta lấy cái chuỗi dài dài kia xong shift, rot. Hàm shift, rot cũng phải được viết ngược lại.

{{< highlight python "linenos=table,linenostart=0" >}}
def generate():
    list_2495 = [2]
    i = 1
    v3 = 3
    while i <= 1337:
        a = 1
        for j in range (i):
            if not (v3 % list_2495[j]):
                a = 0
        if a:
            list_2495.append(v3)
            i = i + 1
        v3 = v3 + 2
    return list_2495

def rot(a1, a2):
    for i in range(len(a1)):
        v3 = a1[i]
        if v3 != 95:
            v3 = (v3 - 97 + a2) % 26 + 97
        a1[i] = v3
        
def shift(a3, a4):
    for i in range(len(a3)):
        v11 = (i + a4) % len(a3)
        a3[i] = a3[v11]


res = generate()
v18 = "azeupqd_ftq_cgqefuaz_omz_ymotuzqe_ftuzwu_bdabaeq_fa_o"

for i in range(1337):
    a = ""
    for j in range(len(v18)):
        v11 = ((j - res[1336 - i]) % len(v18) + len(v18)) % len(v18)
        a += v18[v11]
    v18 = a    
    
    a = ""
    for j in range(len(v18)):
        if ord(v18[j]) != 95:
            v3 = (((ord(v18[j]) - 97 - res[1336 - i]) % 26) + 26) % 26 + 97 
            a += chr(v3)
        else:
            a += v18[j]
    v18 = a          
        

print(v18)
{{< / highlight >}}

{{% alert theme="success" %}}**FLAG:** uiuctf{ i_propose_to_consider_the_question_can_machines_think} {{% /alert %}}

## 2. Tedious
Trong mã giả ta thấy các ký tự của chuỗi nhập vào trải qua một mùi vòng for để thay đổi từng ký tự. Nếu sau trầm luân như vậy mà các ký tự này vẫn bằng 1 byte (lưu ý là 1 byte) của mỗi phần tử của mảng v26 (mỗi phần tử 4 bytes) được liệt kê ra thì ta được flag.

Cũng giống bài trước, ta làm ngược lại quá trình bằng cách lấy các phần tử trong mảng v26 rồi cho qua các vòng for theo thứ tự ngược lại. Khi đã có các phần tử cuối cùng, xor mỗi phần tử với 0xFF để lấy 1 bytes.

{{< highlight python "linenos=table,linenostart=0" >}}
s = [77, 185, 77, 11, 212, 102, 227, 41, 184, 77, 223, 102, 184, 77, 14, 196, 223, 212, 20, 59, 223, 102, 44, 20, 71, 223, 183, 184, 183, 223, 71, 77, 164, 223, 50, 184, 234, 245, 146]
flag = ""
for i in range(39):
    s[i] = (s[i] ^ 0x6B) - 117
    s[i] = (s[i] ^ 0xF0) + 43
    s[i] = (s[i] ^ 0x1B) - 99
    s[i] = (s[i] ^ 0xAB) - 10
    s[i] = (s[i] ^ 0x64) + 115
    s[i] = (s[i] ^ 0x6B) + 75
    s[i] = (s[i] ^ 0x6B) - 22
    s[i] = (s[i] ^ 0xFA) - 118
    s[i] = (s[i] ^ 0x6B) + 38
    s[i] = (s[i] ^ 0x6B) + 66
    s[i] = (s[i] ^ 0x22) - 69
    s[i] = (s[i] ^ 0xED) + 31
    s[i] = (s[i] ^ 0xBD) - 11
    s[i] = (s[i] ^ 0x5A) + 72
    s[i] = (s[i] ^ 0xCD) - 10
    s[i] = (s[i] ^ 0xA0) + 68
    s[i] = (s[i] ^ 0x79) - 12
    s[i] = (s[i] ^ 0x68) - 19
    s[i] = (s[i] ^ 0x50) - 4
    s[i] = (s[i] ^ 0xFD) - 18
    s[i] = (s[i] ^ 0x38) - 59
    s[i] = s[i] & 0xFF
    flag += chr(s[i])

print(flag)
{{< / highlight >}}

{{% alert theme="warning" %}}**FLAG:** uiuctf{y0u_f0unD_t43_fl4g_w0w_gud_j0b}{{% /alert %}}

## 3. Prime Extravaganza
Bài này thì đơn giản mà sao không hiểu cái đề lừa người quá. 

{{< img src="/images/CTF/PrimeExtravaganza/Capture.PNG" title="Hình 7" caption="IDAPro" alt="IDAPro" >}}

Code bảo phải nhập 5 số lớn hơn 0 và nhỏ hơn 1 000 000. Nếu như các số này chia hết cho v9 = 19753*(j + 1) (0<=j<4). Ở đây, 19753 là 1 số nguyên tố lớn. Do đó, ta lấy luôn các giá trị v9 ở mỗi vòng for lần lượt là các số cần nhập vào là đã pass. 

Tiếp theo, đề yêu cẩu lấy tổng các số vừa nhập xong md5 nó => flag

{{< highlight python "linenos=table,linenostart=0" >}}
import hashlib
s = 0
for i in range(0,5,1):
    s += 19753*(i+1)

print(hashlib.md5(str(s).encode()).hexdigest())
{{< / highlight >}}

{{% alert theme="danger" %}}**FLAG** uiuctf{627360eb8aa0da45ff04a514dab40e54}{{% /alert %}}


*Xem thêm và tải file đề bài tại* {{< color "#0000ff" >}}<a href="https://github.com/thunebae/Write-up-RE" title="Github">Github</a>
{{< /color >}}
