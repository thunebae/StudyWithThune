---
title: "Release 1"
author: "thunebae"
date: 2021-10-08T12:00:06+09:00
description: "Waiting...It's not complete 📑 "
tags:
- write-up
- release1
- CTF
- RE
- rev
series:
- Write-ups CTF
categories:
- Write-ups CTF
libraries:
- Write-ups CTF
image: "images/feature1/workflow.png"
---


## 1. ES crack
File: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, with debug_info, not stripped

Sử dụng IDA pro 32-bit, tập trung vào đoạn code sau:

{{< img src="/images/CTF/Release1/ES_crack/IDApro.PNG" title="Hình 1" caption="Mã assembly" alt="Mã assembly" >}}

Ta thấy rằng chỉ cần thêm vào chuỗi có các ký tự đầu bằng với password (0x35353450) thì khúc sau các ký tự có là gì cũng không quan trọng.

>FLAG: P445x (với x là chuỗi ký tự tự do)

{{< img src="/images/CTF/Release1/ES_crack/Result.PNG" title="Hình 2" caption="Kết quả" alt="Kết quả" >}}

## 2. Lucky
File:  ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, with debug_info, not stripped

File yêu cầu nhập vào 2 chữ số và chữ này lần lượt lưu tại byte_804A024 và byte_804A025.

{{< img src="/images/CTF/Release1/Lucky/IDAPro.PNG" title="Hình 3" caption="Mã assembly" alt="Mã assembly" >}}

Trong đoạn code assembly trên, ta thấy byte_804A024 được chuyển từ ký tự thành số thông qua trừ cho 0x30 và lưu tại thanh ghi al. Còn byte_804A024 cũng được chuyển từ ký tự sang số và lưu tại thanh ghi bl. Sau đó, al = al + bl qua câu lệnh adc và được so sánh với 0x16. Mà bl + 0x30 = 0x38

Suy ra: bl = 8 => al = 8

>FLAG: 88

{{< img src="/images/CTF/Release1/Lucky/Result.PNG" title="Hình 4" caption="Kết quả" alt="Kết quả" >}}

## 3. CrackMe_ASM
File: CrackMe_ASM: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, not stripped

Yêu cầu nhập vào giá trị cho biến var. Các byte của biến flag lần lược được gán giá trị rồi so sánh với chuỗi trong biến var vừa nhập. Nếu bằng nhau thì thành công mà không bằng nhau thì không thành công.

{{< img src="/images/CTF/Release1/CrackMe_ASM/IDA1.PNG" title="Hình 5" caption="Mã assembly 1" alt="Mã assembly 1" >}}
{{< img src="/images/CTF/Release1/CrackMe_ASM/IDA2.PNG" title="Hình 6" caption="Mã assembly 2" alt="Mã assembly 2" >}}


>FLAG: S3CrE+Fl4G!

{{< img src="/images/CTF/Release1/CrackMe_ASM/Result.PNG" title="Hình 7" caption="Kết quả" alt="Kết quả" >}}

## 4. hello
File: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped

{{< img src="/images/CTF/Release1/hello/IDA1.PNG" title="Hình 8" caption="Mã assembly 1" alt="Mã assembly 1"  >}}

Đầu tiên, chúng ta nhập chuỗi username, sau đó chuỗi welcome bằng "Hello " + username. Password nhập vào lưu trong buf.

{{< img src="/images/CTF/Release1/hello/IDA2.PNG" title="Hình 9" caption="Mã assembly 2" alt="Mã assembly 2"  >}}

Ở đây, chúng ta thấy welcome[v4 + 5] + 5 == byte_402073[v4]. Chúng ta xem thử byte_402073 rốt cuộc là cái qq gì.

{{< img src="/images/CTF/Release1/hello/IDA3.PNG" title="Hình 10" caption="Mã assembly 3" alt="Mã assembly 3"  >}}

Nếu như byte_402073 ở vị trí 0x402073 thì chuỗi buf đang lưu password ở vị trí 0x402074. Suy ra v4 = 1 sẽ là byte đầu tiên của chuỗi buf. Và password ở đây cũng chỉ có 1 ký tự dựa vào dòng lệnh if (!--v4).

Vậy welcome[6] + 5 = buf[0] => ký tự đầu tiên của username + 5 bằng password. Nhập username là thune => password: y

>USERNAME: thune FLAG: y

{{< img src="/images/CTF/Release1/hello/Result.PNG" title="Hình 11" caption="Kết quả" alt="Kết quả" >}}

## 5. nasm
File: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped

{{< img src="/images/CTF/Release1/nasm/IDA1.PNG" title="Hình 12" caption="Mã assembly 1" alt="Mã assembly 1">}}

Flag được nhập vào sẽ được lưu tại địa chỉ 0x402031 sau đó đem đi so sánh 0xB ký tự đầu với chuỗi passwd. Chuỗi passwd bao gồm các ký tự sau:

{{< img src="/images/CTF/Release1/nasm/IDA2.PNG" title="Hình 13" caption="Mã assembly 2" alt="Mã assembly 2">}}

passwd = supersecret

> FLAG: supersecretx, với x là 1 chuỗi ngẫu nhiên

{{< img src="/images/CTF/Release1/nasm/Result.PNG" title="Hình 14" caption="Kết quả" alt="Kết quả" >}}

## 6. Clone
File: PE32 executable (GUI) Intel 80386, for MS Window

{{< img src="/images/CTF/Release1/clone/image.PNG" title="Hình 15" caption="Chạy thử" alt="Chạy thử" >}}

Đầu tiên, chúng ta kiểm tra thử list strings của bài này:

{{< img src="/images/CTF/Release1/clone/strings.PNG" title="Hình 16" caption="Liệt kê string" alt="Liệt kê string" >}}

Chúng ta để ý có các chuỗi "Well done! Now make good tutorial :)", "Bravo!" có thể là các chuỗi thông báo đã nhập đúng User và Serial.

Tiếp theo chúng ta xem thử các chuỗi này nằm ở hàm nào và hàm đó liên quan tới những hàm nào.

{{< img src="/images/CTF/Release1/clone/graph.PNG" title="Hình 17" caption="Flow graph" alt="Flow graph" >}}

Hàm start là hàm khởi đầu gọi hàm sub_40101D để load các control (textbox, label, button) cho window form. Các control có số hiệu nhận dạng là 101, 102, 104 được lưu ở các biến v4, v2, v1. Sau đó, hàm sub_40101D gọi hàm sub_401180 để làm hành động cho các control này.

{{< img src="/images/CTF/Release1/clone/sub_40101D.PNG" title="Hình 18" caption="Hàm sub_40101D" alt="Hàm sub_40101D" >}}

Để pass, chúng ta cần xem xét kỹ hàm sub_401180.

{{< img src="/images/CTF/Release1/clone/sub_401180(1).PNG" title="Hình 19" caption="Hàm sub_401180 (1)" alt="Hàm sub_401180 (1)" >}}

Câu lệnh này chứa hàm GetDlgItemTextA() là hàm cho đầu ra là số lượng ký tự của string nhập vào, từ đó chúng ta suy ra trong 2 control mang số nhận dạng 101 hoặc 102, 1 cái là User nhập vào, 1 cái là Serial nhập vào. Nếu là control 101 thì string được lưu ở byte_40307C có số ký tự phải lớn hơn 5, còn 102 thì lưu ở String có số ký tự bằng 8.

Để xác định đâu là User, đâu là Serial, ta đặt break point trong hàm sub_401180 tại câu lệnh:

{{< img src="/images/CTF/Release1/clone/breakpoint1.PNG" title="Hình 20" caption="Vị trí đặt breakpoint" alt="Vị trí đặt breakpoint" >}}

Sau đó debug, nhập "11111" vào User, "22222" vào Serial và xem kết quả tại biến byte_40307C và String, ta được kết quả như sau:

{{< img src="/images/CTF/Release1/clone/debug1.PNG" title="Hình 21" caption="Debug" alt="Debug" >}}

Như vậy, Serial được lưu trong String, User được lưu trong biến byte_40307C

Đoạn code từ dòng 29-57 không làm thay đổi giá trị byte_40307C và cũng không so sánh điều kiện để thoả chương trình nên chúng ta không cần quan tâm đến nó. Chúng ta kiểm tra đoạn code chứa dòng lệnh hiện messageBox thông báo bypass chương trình như sau.

{{< img src="/images/CTF/Release1/clone/sub_401180(2).PNG" title="Hình 22" caption="Hàm sub_401180 (2)" alt="Hàm sub_401180 (2)" >}}

Như vậy, có 2 vấn đề chúng ta quan tâm ở đây là giá trị của biến dword_4030C8 và giá trị biểu thức bên trái dấu bằng có liên quan hàng loạt đến mảng byte_4030B8. Hai giá trị này phải bằng. Đầu tiên, giá trị của biến dword_4030C8 có liên quan đến byte_40307C (User) qua một nùi code sau:

{{< img src="/images/CTF/Release1/clone/User.PNG" title="Hình 23" caption="Mã giả" alt="Mã giả" >}}

dword_4030C8 được tính toán dựa trên User và ở đây không có kiểm tra bất kỳ điều kiện thêm nào giành cho User. Do đó, với một User bất kỳ nhập vào, ta luôn tính được giá trị của biến này tương ứng.

Còn mảng byte_4030B8 liên quan đến đoạn code sau:

{{< img src="/images/CTF/Release1/clone/Serial.PNG" title="Hình 24" caption="Mã giả" alt="Mã giả" >}}

Đoạn code này có chức năng chuyển các ký tự trong chuỗi String thành các số. Nếu là ký tự số như "1" thì được trừ cho 48 chuyển thành số 0x1. Nếu là kí tự in hoa từ vị trí 0x41 đến 0x46 trong bảng mã ASCII, ví dụ như "A" thì được trừ cho 55 (65-55 = 10 = 0xa). Các trường hợp còn lại không phải ký tự thuộc mã hex thì không hợp lệ. Tóm lại, nếu nhập chuỗi "aabbcc" thì mảng byte_4030B8 sẽ gồm {0xa, 0xa, 0xb, 0xb, 0xc, 0xc}. Từ đó, ta biết được chuỗi nhập vào String phải gồm 8 ký tự, các ký tự in hoa và là một mã hex.

Điều kiện phải được thoả trong câu lệnh if như sau:

dword_4030C8 = _ byteswap_ulong((((byte_4030B8[7] + 16 * byte_4030B8[6]) ^ 0xCD) - 17) 
                              + (((((byte_4030B8[5] + 16 * byte_4030B8[4]) ^ 0x90) - 85)
                               + (((((byte_4030B8[3] + 16 * byte_4030B8[2]) ^ 0x56) + 120)
                                 + ((((byte_4030B8[1] + 16 * byte_4030B8[0]) ^ 0x12) + 52) << 8)) << 8)) << 8)))
                                 
Do mỗi phần tử của mảng byte_4030B8 có 4 bits nên khi lấy byte_4030B8[i] * 16 + byte_4030B8[i+1] sẽ thành một byte. _ byteswap_ulong là hàm có đầu ra là một số viết theo little-endian. Tóm lại là như sau:

s[0] ^ 0x12 + 52 = dword_4030C8[3]

s[1] ^ 0x56 + 120 = dword_4030C8[2]

s[2] ^ 0x90 - 85 = dword_4030C8[1]

s[3] ^ 0xCD - 17 = dword_4030C8[0]

Với s[i] là byte do 4 bit của phần tử byte_4030B8[i] và phần tử byte_4030B8[i+1] tạo thành.

Để tìm được dword_4030C8, ta kiểm tra xem biến này được tính giá trị đặt trong thanh ghi nào rồi đặt breakpoint tại thời điểm giá trị được tính ra để nhìn thấy kết quả. Lưu ý phải nhập Serial với chuỗi bất kỳ 8 ký tự để có thể bypass điều kiện, User chọn ngẫu nhiên ở đây là "thune1".

{{< img src="/images/CTF/Release1/clone/value1.PNG" title="Hình 25" caption="Mã assembly" alt="Mã assembly" >}}

Ta thấy rằng giá trị của dword_4030C8 được lưu ở thanh ghi ebx nên ta debug và kiểm tra giá trị ebx.

{{< img src="/images/CTF/Release1/clone/value2.PNG" title="Hình 26" caption="Thanh ghi ebx" alt="Thanh ghi ebx" >}}

s[0] ^ 0x12 + 0x34 = 0x0f

s[1] ^ 0x56 + 0x78 = 0xc6

s[2] ^ 0x90 + 0xab = 0x5c

s[3] ^ 0xcd + 0xef = 0x8b

Dựa vào mã assembly của các phép tính này để suy ngược lại ra s[i].

{{< img src="/images/CTF/Release1/clone/value3.PNG" title="Hình 27" caption="Mã assembly" alt="Mã assembly" >}}

1 byte s[0] sẽ được lưu trong ebx, sau đó ta chỉ lấy thanh ghi bl (8 bits của thanh ghi ebx) xor với 0x12, rồi cộng với 0x34. Lúc này giá trị có thể quá lớn và vượt qua 8 bit nên and với 0xff để lấy chỉ 8 bit. Ta suy ngược lại cách tính s[0] như sau: (0x0f - 0x34)^0x12. Nhưng vì các phép tính + hoặc trừ có thể sinh ra số âm nên ta phải cộng thêm với 256, đồng thời do chỉ cộng thanh ghi bl với 0x34, tức chỉ lấy 8 bit cộng với 0x34, nên khi suy ngược lại phải thêm and 0xff để lấy chỉ 8 bit. 

Cuối cùng,

s[0] = ((0x0f - 0x34 + 256)&0xff)^0x12

s[1] = ((0xc6 - 0x78 + 256)&0xff)^0x56

s[2] = ((0x5c - 0xab + 256)&0xff)^0x90

s[3] = ((0x8b - 0xef + 256)&0xff)^0xcd

> Ta được Serial = C9182151 với User = "thune1"

{{< img src="/images/CTF/Release1/clone/done.PNG" title="Hình 27" caption="Done" alt="Done" >}}

## 7. crack_001
File: PE32 executable (GUI) Intel 80386, for MS Windows

Kiểm tra các chuỗi có trong chương trình, thấy có chuỗi "Register complite!!!", xem thử các hàm liên quan đến chuỗi này.

{{< img src="/images/CTF/Release1/crack_001/Graph.PNG" title="Hình 28" caption="Flow graph" alt="Flow graph" >}}

Ở hàm DialogFunc tại dòng 20, 21 có 2 câu lệnh để lấy độ dài chuỗi nhập vào lưu tại String và byte_403014. Tương tử câu trên, đặt breakpoint và debug sẽ biết được String là PASS, byte_403014 là NAME. v6 là độ dài của NAME và 3 <= v6, v6 = dword_403025.

{{< img src="/images/CTF/Release1/crack_001/DialogFunc.PNG" title="Hình 29" caption="Dialog function" alt="Dialog function" >}}

Ở hàm sub_4010FE, mỗi ký tự của NAME, nếu không phải thuộc {Z,z,9} sẽ được cộng với 1 và trở thành byte cuối của v1 (v1 có 2 bytes), còn nếu thuộc {Z,z,9} thì sẽ trừ 1 rồi cộng 1 trực tiếp trở thành byte cuối của v1. Còn byte đầu của v1 sẽ được cộng với 97 + v0. 

{{< img src="/images/CTF/Release1/crack_001/value.PNG" title="Hình 30" caption="Mã giả" alt="Mã giả" >}}

Xét điều kiện if ở câu lệnh 22, giá trị v1 ở mỗi vòng lặp sẽ được so sánh với 2 bytes của PASS[2* v0]. Do giá trị HIBYTE(v1) ở mỗi vòng lặp luôn bằng 0x00. Do đó, ở mỗi vòng giá trị của HIBYTE(v1) chính là giá trị của v0 + 97 => được các byte cuối trong 2 byte của PASS[2* v0] là 97, 98, 99,... với v0 thuộc {0, 1, 2,...}. Còn LOBYTE(v1) phải bằng byte cuối của PASS[v0* 2] trừ đi 1, với v0 thuộc {0, 1, 2,...}, nếu kết quả {Y,y,8} thì được cộng thêm 1.

Giả sử NAME = "gm0". Ở vòng lặp 1, v1 = 0x0067, HIBYTE(v1) = 0x00 + 0x97 = 0x97, LOBYTE(v1) = v1 + 1 = 0x67 + 1 = 0x68. Tương tự, ta sẽ được PASS tương ứng.

> NAME = "gm0", PASS = "hanb1c"

{{< img src="/images/CTF/Release1/crack_001/Result.PNG" title="Hình 31" caption="Kết quả" alt="Kết quả" >}}

## 8.get_the_password
File: PE32 executable (console) Intel 80386, for MS Windows

Chuỗi password được lưu tại unk_402010 và được gán cho biến v2. 

{{< img src="/images/CTF/Release1/get_the_password/IDA(1).PNG" title="Hình 32" caption="Mã giả" alt="Mã giả" >}}

Tất cả các dòng lệnh sau đó đều sẽ kiểm tra từng phần tử nếu thoả câu lệnh if trong khi case = v0 (v0 giữ vai trò là chỉ số của phần tử trong chuỗi) thì giảm v1 xuống 1 đơn vị, nếu không thoả thì tăng lên. Có tổng cộng 10 lần cộng 1 đơn vị nếu các phần tử của chuỗi không thoả tất cả các câu lệnh if đặt ra. Mà sau khi tăng hoặc giảm v1 qua 10 lần, nếu giá trị v1 = 10 thì nhập password thành công. Do đó, ở tất cả các lần kiểm tra các câu lệnh if kiểm tra phần tử của chuỗi nhập vào đều phải không thoả.

{{< img src="/images/CTF/Release1/get_the_password/IDA(2).PNG" title="Hình 33" caption="Mã giả" alt="Mã giả" >}}

```
password[1] > 0x47

password[2] < 109

password[3] = 86

password[4] >= 0x66

password[5] <= 0x33

password[6] > 0x79

password[7] >= 56

password[8] < 78

password[9] != 82

password[10] = 50
```

Nhập chuỗi password = "PaVi0z9I32" có các kí tự thoả các điều kiện trên.

{{< img src="/images/CTF/Release1/get_the_password/Result.PNG" title="Hình 34" caption="Kết quả" alt="Kết quả" >}}

{{< color "#ffff33" >}}*To be continute....*{{< /color >}}
 
*Read more and download file at* {{< color "#0000ff" >}}<a href="https://github.com/thunebae/Release_1" title="Github">Github</a>
{{< /color >}}
