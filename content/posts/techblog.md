---
title: "TechBlog"
author: "thunebae"
date: 2022-07-19T12:00:06+09:00
description: "A website too but it has some security method."
tags:
- thunebae
- project
series:
- Project
categories:
- Project
libraries:
- Project
image: "/images/project/techblog/tech-logo.png"
---

### Introduction
Umh...TechBlog is Technology plus Blog, so everybody can write and share their knowledges in this website

- Server: Linux​

- LAMP stack: Apache2, PHP, Mysql​

- MVC Framework​

- Program languages: PHP, HTML

### Feature

- Register, log in, log out, update profile

- Create, update, delete, view posts, pagination

- Comment, count views

- Upload images

{{< img src="/images/project/techblog/home.png" title="Hình 1" caption="Home UI" alt="Home UI" >}}

### Security method

- Prepared statement: prevent SQL injection

- SANITIZE INPUT PHP: prevent XSS

- Mode_rewrite: protect resources, prevent directory traversal

- Safe upload file: limit size of upload images, check MIME type

- ModSec firewall: use OWASP's rules that can prevent TOP 10 OWASP

{{< img src="/images/project/techblog/sec.png" title="Hình 2" caption="Security method used for TechBlog" alt="Security method used for TechBlog" >}}

*Source code project at* {{< color "#0000ff" >}}<a href="https://github.com/thunebae/TechBlog" title="Github">Github</a>
{{< /color >}}