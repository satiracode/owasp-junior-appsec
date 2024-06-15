# Security in Requirements phase
Building requirements is one of the first steps in the SDLC, where we define goals and objectives of our future application.
Usually at this phase we collect relevant **stakeholders** and start discussing their needs and expectations.
We talk to people who will use the application, those who will manage it, and anyone else who might be affected by it 
to understand what they want the application to do and how it should work.

During requirements engineering, we need to separate **functional** and **security** requirements.
While **functional** requirements show what application **should do**, **security** requirements show what an application
**shouldn't do**.

It's important to carefully think through building **security requirements**, because a large part of the system's security
depends on them. Good security requirement follows **SMART** principle:

![](assets/smart.png)

Usually stakeholders involved into security requirements engineering are:
* Developers
* Security experts
* Project Managers/Architects

All of them can participate in one of the ways to build security requirements: **Security** and **Abuser** stories.

### Security Stories
*As a [role], I want [security feature], so that [benefit]*

Security stories are a special type of user stories, that focus on the security of the system.
You should look at the application from a perspective of **users and stakeholders who need protection**.

**Examples**:
1. As a developer, I want to ensure that all passwords are stored with strong hashing algorithm so that even if the database is compromised, the passwords remain secure.
2. As a system administrator, I want to log all access to sensitive data so that we can audit and identify any unauthorized access.

### Abuser Stories
*As a [bad guy], I want to [do something bad]*

Abuser stories are the opposite of security stories. Here you need to think like an **attacker**, finding the ways
you can **exploit** an application.

**Examples**:
1. As an attacker, I want to perform a brute force attack on the login page to gain access to user accounts.
2. As an attacker, I want to intercept data transmitted over the network to steal sensitive information.

___
So, security and abuser stories allow us to look at the application from both points of view: user's and attacker's.
It is a **proactive** approach, that provides us a detailed and scenario-based understanding of security requirements.

Now we need a comprehensive way to ensure our critical assets and potential risks are managed.
For this we can use **FAIR** model:

## Factor analysis of information risk (FAIR)
**FAIR** is a methodology, that helps to **assess** and manage **informational risk** in a **financial** terms.
It includes following core steps:

1. **Threat** and **Critical Asset** identification - defining valuable assets of application and identifying related threats for them.
2. **Contact Frequency (СF)** assessment - calculating how frequent the vulnerability interacts with critical asset
3. Calculating **Probability of Action (PoA)** - finding the probability that asset would be attacked
4. **Threat Event Frequency (TEF)** assessment - multiplication of **CF** and **POA**
5. **Vulnerability (Vuln)** assessment - probability, that the attack on the asset would be successful
6. **Loss Event Frequency (LEF)** assessment - multiplication of **TEF** x **Vuln**
7. Defining **Loss Magnitude (LM)** - calculating **Primary Losses** (actual damage in a result of the attack)
and **Secondary Losses** (reputation, litigation losses)
8. Calculating **Overall** risk - multiplication of **LEF** x **LM**

Sounds a bit hard, right? As **FAIR** is just **methodology**, not **framework**, there are no concrete ways of **how** you
should calculate risks.\
But using simple **Threat Modeling** techniques such as **STRIDE** and **DREAD** we can cover most of these steps:

### STRIDE & DREAD
Threat modeling includes its **identification** and **rating**.
Identifying threats helps us understand which security aspects are at risk, while rating them ensures we prioritize our efforts in a right way.

To properly identify threat we will use **STRIDE** framework:

![](assets/stride.png)

Now we can calculate the risk by using **DREAD** framework. Each category in the model is scored from 0 to 10.
The sum of the scores in all categories is **total risk score**. Maximum risk score is **50**.

![](assets/dread.png)

Let's create a STRIDE and DREAD analysis for **SQL Injection** as an example:

![](assets/sqli.png)
___
After this, we can use **Security & Abuser** stories, **STRIDE** and **DREAD** framework
to structure our approach with **FAIR** methodology:

#### › Threat and Critical Asset identification
Using **Security & Abuser** stories, we can find critical assets.
For instance, if we talk about **SQL Injection**, it means that **user database** is our critical asset.
To identify the influence vectors of the threat, we will use **STRIDE**.

#### › Contact Frequency (СF) assessment
This criteria fully depends on the functional requirements.\
For instance, if our critical asset is database and vulnerability relates to it,
the frequency is actually how often will user interact with the database.

#### › Calculating Probability of Action (PoA)
We can use **Reproducibility** and **Exploitability** scores from **DREAD** framework.
For instance, for SQL Injection **Reproducibility** is **9**, for **Exploitability** is **10**.

Then our **PoA** would be *(9 + 10) / 20* = **0.95**

#### › Threat Event Frequency (TEF)
As mentioned before, **TEF** = **CF** x **PoA**.
For example, if there are 100 user-side interactions with database, then for SQL Injection:\
**TEF** = *100 x 0.95* = **95** threat events per day.

#### › Vulnerability (Vuln) assessment
For final **Vulnerability** assessment we can use final **DREAD** score.\
**SQL Injection**'s DREAD score is *9 + 8 + 10 + 10 + 8* = 45/50, or **0.99**.

#### › Loss Event Frequency (LEF)
**LEF** = **TEF** x **Vuln**\
Then for our scenario, **LEF** = *95 x 0.99* = **94** loss events per day.

#### › Loss Magnitude (LM)
Loss Magnitude is calculated by summing potential **primary** and **secondary** losses.\
At this step we don't use any thread modeling approaches, cause it requires more specific analysis.

For instance, let's calculate imaginary **SQL Injection**'s Loss Magnitude:

- **Primary Losses**:\
Potential cost of stolen data: *50.000$*\
Cost of restoration works: *30.000$*\
System downtime: *10.000$*\
Total : **90.000$**


- **Secondary Losses**:\
Legal and regulatory losses: *60.000$*\
Increased security costs: *20.000$*\
Total: **80.000$**

Thus, Total Loss Magnitude is *90.000$ + 80.000$* = **170.000$**

#### › Overall Risk
*Potential Overall Risk = LEF(94) x LM(90.000)* = **8.460.000$ per day**
___
By using **STRIDE**, **DREAD**, **Security & Abuser Stories**, and **FAIR**, we learnt how to develop strong security requirements.\
The great thing about **FAIR** is that in the end it translates these risks into **financial** terms, making it much easier for **management** to understand the importance of each security measure. This is especially helpful since it's often **challenging** to convey the significance of security risks to **top executives**.

Now that we have our security requirements and know their financial impacts, we can ensure we don't miss anything by using a **Secure Requirements Traceability Matrix (SRTM)**.

## Security Requirements Traceability Matrix (SRTM)
**SRTM** is a detailed document that links security requirements to their implementation and testing.
It makes sure that all security needs are handled during development, showing a clear path from the start to the final tests.

![](assets/srtm-def.png)

Let's imagine that after using the FAIR framework with Security & Abuser Stories, 
we identified the following security requirements:

* Implement 2FA to follow PCI-DSS
* Using input validation to prevent XSS Injection
* Logging access to sensitive assets 

In this case, our matrix will look like this:

![](assets/srtm-sample.png)

For building requirements traceability matrix you will use such tools like **YouTrack** or **Jira**.
___
# Summary
In this article, we learned how important it is to build security requirements early in the SDLC.\
By talking to stakeholders and using methods like **Security & Abuser Stories**, 
we can spot critical assets and potential threats from both user and attacker perspectives.

We used **STRIDE** to identify threats, **DREAD** to assess them, and **FAIR** to make sure we didn't miss anything.\
**FAIR** also allowed us to look at these threats from **all angles** and translate their impact into **financial terms**, 
making it easier for management to understand their **importance**.

Finally, we talked about the Secure Requirements Traceability Matrix (SRTM), which helps us **track** security requirements from start to finish.\
This ensures that **nothing is missed** and all security needs are properly addressed.

Finding and fixing security issues during the requirements phase can **save millions of dollars** later on.
It’s **much cheaper** to address these problems early rather than after the application is built or later SDLC steps.