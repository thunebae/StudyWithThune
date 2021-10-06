+++
author = "thunebae"
title = "Write-up Reverse Engineering CTF"
date = 2021-10-05T12:00:06+09:00
description = "Some write-ups of CTF contests before."
featured_image = "markdown.png"
tags = [
    "ctf",
    "reverse engineering",
    "RE",
    "rev",
]
categories = [
    "posts",
    "write-up",
]
series = ["CTF write-ups"]
+++


# ImaginaryCTF-Write-up
## 1. stings
File đính kèm: [stings](https://github.com/thune-work/ImaginaryCTF-Write-up/tree/main/stings)

Đầu tiên, ta phải kiểm tra định dạng file.

![checkStings](https://github.com/thune-work/Write-up-RE/blob/main/Image/stings/fileStings.PNG)

Như ta thấy trong hình trên, stings là file ELF 64-bit LSB pie excutetable, x86-64 => sử dụng IDApro 64-bit

Chạy thử trên máy ảo xem có gì trong trỏng.

![runStings](https://github.com/thune-work/ImaginaryCTF-Write-up/blob/main/Image/stings/runStings.PNG)

File này hoá ra là một con ong thích chơi trò mật mã. Nếu bạn đoán đúng mật khẩu thì không bị chích. Còn đoán sai thì chetcondime bạn rồi.

Giờ mới xài IDApro 64-bit phân tích file.

Nhìn qua một nùi hàm thì chỉ có hàm main là hàm sẽ giúp chúng ta không bị ong chích. Xem mã giả của hàm main.

Hàm main khai báo nguyên một nùi biến local. Để tránh quan tâm những thành phần không cần thiết, ta tìm chỗ nào có liên quan đến password trước. Đó là dòng 64 đến 79 trong mã giả.

![idaproStings](https://github.com/thune-work/ImaginaryCTF-Write-up/blob/main/Image/stings/idapro.PNG)

v13 chính là chuỗi mà chúng ta nhập vào ở dòng 64. Dựa vào vòng lặp for từ dòng 65, ta đoán được rằng password có 35 ký tự. Dòng 67-71 cho ta biết rằng password có các ký tự liên tiếp có mã ascii bằng các byte liên tiếp tương ứng trừ đi 1 tính từ byte đầu tiên của v14 (dòng 67) trên stack của hàm main (Nếu không thoả sẽ in ra dòng chữ "I'm disappointed. *stings you*" và bị ong cắn). Vậy nên, chúng ta cần quan sát các khai báo biến local của hàm main để xem thứ tự các biến trong stack như nào.

![localVar](https://github.com/thune-work/ImaginaryCTF-Write-up/blob/main/Image/stings/localvar.PNG)

Như vậy, tính từ đỉnh stack theo chiều từ dưới lên trên, kể từ v14, ta có thức tự các biến như sau v14->v15->v16->v17->v18. May thay mấy biến này đều đã được gán giá trị lại còn đủ 35 bytes và mấy nùi code rối rắm còn lại không gây ảnh hưởng đến các giá trị này và khi tới dòng 67-71 chỉ cần lấy chúng ra và quất.

![valueVar](https://github.com/thune-work/ImaginaryCTF-Write-up/blob/main/Image/stings/valueVar.PNG)

*Chú ý*: little-endian, lưu mảng bytes từ dưới lên trên stack.

v14 = 0x7375747C6775646A

v15 = 0x3473356074686F32

v16 = 0x346565326960756F

v17 = 0x623233633832606F

v18 = 0x7E3A37

*Code viết theo little-endian và chuyển sang ký tự ascii: [stings_solve.py](https://github.com/thune-work/Write-up-RE/blob/main/File%20solve/stings/stings_solve.py)

![result](https://github.com/thune-work/ImaginaryCTF-Write-up/blob/main/Image/stings/result.PNG)

> FLAG: ictf{str1ngs_4r3nt_h1dd3n_17b21a69}

# UIUCTF
## 1. hvhpgs{synt}
Sau khi sử dụng IDApro, ta thấy chuỗi s nhập vào được lưu vào v3 (dòng 22). Sau đó qua một nùi code hong làm thay đổi v3 thì tới dòng 30 - 36, các ký tự của chuỗi nhập vào được chuyển qua 2 hàm lần lượt là rot và shift, nếu chuỗi thay đổi bằng "azeupqd_ftq_cgqefuaz_omz_ymotuzqe_ftuzwu_bdabaeq_fa_o" thì ta sẽ được flag.

![main](https://github.com/thune-work/Write-up-RE/blob/main/Image/hvhpgs%7Bsynt%7D/IDApro.PNG)

Vì vậy, chúng ta lấy cái chuỗi dài dài kia xong shift, rot. Hàm shift, rot cũng phải được viết ngược lại => File [solve.py](https://github.com/thune-work/Write-up-RE/blob/main/File%20solve/hvhpgs%7Bsynt%7D/solve.py)

>FLAG: uiuctf{i_propose_to_consider_the_question_can_machines_think}
>
## 2. Tedious
Trong mã giả ta thấy các ký tự của chuỗi nhập vào trải qua một mùi vòng for để thay đổi từng ký tự. Nếu sau trầm luân như vậy mà các ký tự này vẫn bằng 1 byte (lưu ý là 1 byte) của mỗi phần tử của mảng v26 (mỗi phần tử 4 bytes) được liệt kê ra thì ta được flag.

Cũng giống bài trước, ta làm ngược lại quá trình bằng cách lấy các phần tử trong mảng v26 rồi cho qua các vòng for theo thứ tự ngược lại. Khi đã có các phần tử cuối cùng, xor mỗi phần tử với 0xFF để lấy 1 bytes.

File [solve.py](https://github.com/thune-work/Write-up-RE/blob/main/File%20solve/Tedious/solve.py)

> FLAG: uiuctf{y0u_f0unD_t43_fl4g_w0w_gud_j0b}

## 3. Prime Extravaganza
Bài này thì đơn giản mà sao không hiểu cái đề lừa người quá. 

![idapro](https://github.com/thune-work/Write-up-RE/blob/main/Image/Prime%20Extravaganza/Capture.PNG)

Code bảo phải nhập 5 số lớn hơn 0 và nhỏ hơn 1 000 000. Nếu như các số này chia hết cho v9 = 19753*(j + 1) (0<=j<4). Ở đây, 19753 là 1 số nguyên tố lớn. Do đó, ta lấy luôn các giá trị v9 ở mỗi vòng for lần lượt là các số cần nhập vào là đã pass. 

Tiếp theo, đề yêu cẩu lấy tổng các số vừa nhập xong md5 nó => flag

File [solve.py](https://github.com/thune-work/Write-up-RE/blob/main/File%20solve/Prime%20Extravaganza/solve.py)

>FLAG: uiuctf{627360eb8aa0da45ff04a514dab40e54}

