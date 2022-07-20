---
title: "ECC Aplication"
author: "thunebae"
date: 2022-07-19T12:00:06+09:00
description: "When ECC meets AES-128-CBC 😃"
tags:
- thunebae
- project
series:
- Project
categories:
- Project
libraries:
- Project
image: "/images/project/ecc/post.png"
---

### Framework: Python with PyQt5-tools

### Idea
It's application just for demo (without communication through internet). For the purpose of preventing scores from leaking at server, we use AES-128 mode CBC to encrypt the data of the database and the AES key will be encrypted and exchanged by ECC.

### Implement
{{< img src="/images/project/ecc/graph.png" title="Hình 1" caption="UEIIS project graph" alt="UEIIS project graph" >}}

- When a teacher or student logs in, the public key will be downloaded from the server and use for decrypting ciphertext to score table.

- When the teacher adds, deletes, edits grades, the program will automatically generate a new key pair including private-key and public-key respectively to encrypt the edited data.

- Ciphertext stored on the server makes it easy for the server to encrypt or decrypt the transcript data (encrypted with AES) after verifying the user's identity with the private-key.

{{< img src="/images/project/ecc/demo.png" title="Hình 2" caption="Teacher UI" alt="Teacher UI" >}}

*Source code project at* {{< color "#0000ff" >}}<a href="https://github.com/thunebae/CarePlus" title="Github">Github</a>
{{< /color >}}