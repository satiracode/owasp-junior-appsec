# Mastering AppSec
# Intro to Application Security

In the face of increasing cyberattacks, application security is becoming critical, requiring developers to integrate robust measures and best practices to build secure applications.

But what exactly does the term "secure application" mean?
Let's shortly take a look on some notable hacking incidents in history:

#### T-Mobile data leak
In January 2023 T-Mobile was attacked by a group of hackers. The attack was done using the vulnerability in the API,
in a result of which data of 23 million clients was compromised.

It allowed hackers to access **confidential** information of users, such as names, emails and phone numbers.

#### Industrial Control Systems Attack
In 2019, russian hacking group named "Turla" attacked an industrial facility in Europe.
After gaining access to industrial control systems, the group started manipulating data from sensors, such as temperature
and pressure.

The main target of attackers was to break the **integrity** of data, in order to
cause incorrect operational decisions and lead to incidents.

#### Attack on Bandwidth.com
Bandwidth.com was DDoS attacked by a group of hackers in October 2021.
The attack compromised **availability** of service, that made its services inaccessible to users

Due to interruption of services, the company got big financial impact, estimated around 9-12 million of dollars.

___
Each of this hacking incidents broke one of the core principles of information security: **confidentiality**, **integrity** and **availability**.
These 3 principles are called **CIA Triad**:

**C** - Confidentiality\
Only authorized entities have access to specified resource or information and no one else.

**I** - Integrity\
Data saves its accuracy and consistency during its entire lifecycle, being protected from unauthorized alteration or destruction.

**A** - Availability\
Even in the event of failures or attacks, data and services are continuously available to authorized users.

So, ensuring these principles allows our application to be **secure**. This is an ongoing process that begins with planning and continues through to the maintenance of the application.
And goal of **AppSec** is to **ensure security on every stage of software development lifecycle (SDLC)**.

### Software Development Lifecycle (SDLC)
The software development lifecycle is a step-by-step process used to create software in a systematic and efficient way.
It consists from 6 phases:

![](assets/sdlc.png)

**Requirements**\
Setting goals, defining project's scope and understanding what the users need from software

**Design**\
Planning the structure and layout of the system, ensuring it meets all requirements

**Development**\
Writing the actual code to build the software.

**Testing**\
Checking the software to ensure it works correctly and is free of bugs.

**Deployment**\
Releasing the software for users to access and use.

**Maintenance**\
Updating and fixing the software as needed after it is in use.

Our goal is to implement security at each phase, because  earlier vulnerabilities are detected, the lower the cost and effort required to fix them,
preventing expensive and complex issues later.


We can illustrate approximate comparison of cost in a following way:

![](assets/cost.png)
___
AppSec engineer is one of the most important stakeholders responsible for security.\
He should know methodologies applicable at the application layer to detect and mitigate malicious traffic in order to build systems, where potential threats are recognized and mitigated before they can cause harm.

In addition to prevention measures, AppSec engineers play a big role in incident response.
They collaborate with incident response teams and provide expertise on application-specific security concerns.
AppSec engineer's involvement is essential for detection, mitigation and post-incident analysis, helping to develop strategies to prevent incidents in future.

In this series of articles we will focus on best security practices at each phase of SDLC, explore such techniques as JA3, JA4+, HTTP/2 fingerprinting and cover fundamentals of incident response.

# Roadmap
**Please note, that roadmap may be changed**
- [Introduction to Application Security]() (you are here)
- [Security in building requirements](secure_requirements.md)
- Secure Design principles
- Secure Coding Principles
- Security in Testing
- Secure deployment & maintenance
- Application layer fingerprinting
- Fundamentals of incident response]
