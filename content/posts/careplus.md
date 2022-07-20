---
title: "CarePlus"
author: "thunebae"
date: 2022-07-19T12:00:06+09:00
description: "A website for F0 patient management at Home 🏥"
tags:
- thunebae
- project
series:
- Project
categories:
- Project
libraries:
- Project
image: "/images/project/careplus/logo.svg"
---
### Framework: Django with python 
### Idea: 
Create a website to manage F0 patient at home (This project  was created when my team must study at home because of Social distancing during covid epidemic)
### Feature:
{{% alert theme="warning" %}}**:warning:WARNING:** CarePlus has many bugs, omissions, incomplete functions. But my team has too lazy to fix and complete it {{% /alert %}}

- **For all users**: sign in, log out, edit profile (edit picture profile), health declaration
{{< img src="/images/project/careplus/profile.png" title="Hình 1" caption="Update profile" alt="Update profile" >}}

- **Only for doctor**: add patient by identity card number (it's only show in patient profile and only doctor knows it), classify patient (warning level: blue (it's fine. Patient can be take care at home), yellow, red(they must let patient go to hospital emergently)), symptom monitoring online by updates of patient or patient's relative and write prescriptions for specific patients.
{{< img src="/images/project/careplus/doctor.png" title="Hình 2" caption="Patient management" alt="Patient management" >}}

- **Only for patient**: symptom update, edit medical records (background disease, date of illness, place of travel), view today's prescription
{{< img src="/images/project/careplus/patient.png" title="Hình 3" caption="Only for patient" alt="Only for patient" >}}

- **Only for admin**: take an normal user account became doctor account by edit `type_account`
{{< img src="/images/project/careplus/admin.png" title="Hình 4" caption="Only for admin" alt="Only for admin" >}}

- **Some feature by my teammate do**: forum, covid statistics, news, notifications
{{< img src="/images/project/careplus/other.png" title="Hình 5" caption="Others" alt="Others" >}}

*Source code project at* {{< color "#0000ff" >}}<a href="https://github.com/thunebae/CarePlus" title="Github">Github</a>
{{< /color >}}