# Secure and Resilient Design
In the previous article we learnt how to develop security requirements using techniques such as Security & Abuser stories,
learned how to model risks using STRIDE and DREAD, and structured the FAIR model using these techniques.

Now in the design phase, our goal is to define the **security principles** that will be used in our system,
based on the security requirements we've gathered.

In this article, we will look at not only some of the most important design principles, but also how to ensure the overall **resilience** of the security system and architecture.

## 1. Secure Design Principles
### Principle of least privilege

Let's imagine the office of a small company. We have an accountant, a marketer, an IT specialist and an HR manager.
Everyone is doing their own thing, communicating with each other and interacting with the system through their personal account.

The company did not conduct **cyber hygiene** courses for its employees and a virus got on the HR manager's computer after opening an infectious CV file. The virus stole the login and password of the personal account, and an attacker could now connect to the company's system on behalf of this team member.

But because the company did not share the rights, in addition to the information that is in the HR manager's area of responsibility, the attacker got hold of **all departments**' information, which significantly increased the impact due to the HR manager's oversight.

Obviously, the impact would have been much less if initially each role on the team only had access to the information and actions they really needed.

The same goes for the services that work in our system. They should have exactly as many rights as they really need.
Let's look at the following simplified architecture as an example:

We'll imagine our application has 5 services:
- **Auth Service** - Manages user logins
- **User Service** - Manages user profiles
- **Payment Service** - Responsible for payment processing.
- **Notification Service** - Sends notifications to users
- **Analytics Service** - Analyses data for reporting purposes.

According to the principle of least privilege, in the aspect of data access, it should be restricted as follows:
- **Auth Service** has access to user accounts only
- **User Service** can only operate on user profiles
- **Payment Service** can only access payment data
- **Notification Service** - only has access to contact details for sending notifications
- **Analytics Service** - only has access to anonymised user data.

In this case, even if a vulnerability is discovered in one of the services, an attacker will only be able to get access to the data related to that service.
By analogy, this principle should be observed at **every** layer of the system, from user rights of the server itself to entities inside our services.

### Zero Trust Principle
The **Zero Trust** principle fits very well with the previous one. The basic idea is that our system should not trust users or services by default, even if they are within the corporate network.

To make it easier to understand, let's go back to our office example. If some person is on the territory of the office, he is not necessarily a member of the team that works there, right? If he walks up to an accountant and asks for certain statements, the accountant has to first find out **who** he is, and whether he has the **right** to get those statements.

This is exactly the same with our system. If, within the network, the first service **A** contacts the second service **B**, then our service **B** must first **authenticate** the request to identify the sender, and then **authorise** him by checking whether he has sufficient rights to do so.

To better understand how to build Zero Trust architecture for services, let's take a real-world example. To do this, let's use tools from [HashiCorp](https://www.hashicorp.com/):

- [Consul](https://www.consul.io/) - To set up secure network communication via mTLS, service location and certificate issuance
- [Vault](https://www.vaultproject.io/) - For service authentication and key management.

Inside **Consul** create roles (e.g. service-a, service-b) and configure the root certificate. It will be used to issue TLS certificates to our services by their ACL token. In **Vault** set the same roles for our services and specify policies for them. Policies can be any value, for example you can specify service rights.

Finally, import the Consul root certificate into Vault and set **TLS Auth Method** as the authentication method. Now our service authentication and authorisation process will look like this:

Let's imagine service **A** wants to contact service **B**, for example to request user information. For service **A** in Vault, we have added the `com.myapp.users.access` policy.
1. On initialisation, service A retrieves its certificate from **Consul**
2. Using its certificate, it authenticates to **Vault** and gets its temporary **access token**
3. Service **A** specifies this token in the headers and sends a request to service **B**
4. Service **B** checks the token through **Vault**. It looks to see if the service has a `com.myapp.users.access` policy and relative to that it skips or blocks the request.

As you can see, we are not only authenticating and authorising our services automatically here, but also following the previous principle of minimum privilege, which is an integral part of the zero trust architecture.

### Fail Securely
No one is 100% safe from system failure. Failure can be caused by **software errors**, **hardware failures**,
**configuration problems**, and **external attacks**.

It is very important to us that the system, in the event of a failure, instead of going into an erroneous state, can either handle it correctly, or remain in a state where it **will not give out information** about its internals.
Attackers often try to cause a system to fail just to get technical details about it. Gathering information about the system is the very first step in illegitimate actions against the infrastructure.

Improper error handling often results in an error stacktrace being returned back in the response, and this, depending on the context, can give away information about:
- The framework on which the application is developed
- The server on which the application is based
- The internal structure of the application
- The database structure (if the error is related to it)

As you can see, this can lead to revealing important information about the structure of the entire system.
A failure can be called safe if, as a result:

- No technical details about the system have been released
- The integrity and confidentiality of data in the system was not compromised
- The system continued to operate smoothly
- All information about it was logged for further analysis

We will cover practices for secure error handling in detail in the **Secure Coding Principles** article.

### Defence in Depth
Agree, it would look strange if the system was protected by one thing. A system cannot be secure if we have designed and coded the application correctly, but the security of the environment in which it runs is lame.
Similarly, and vice versa, what good is a secure environment if we have a leaky application?

A system is considered secure if it provides security at **each** layer of the network, correctly identifies intrusion attempts, and responds to **incidents** in a timely manner.
This principle implies that defences should be layered and security professionals should develop measures appropriate to their expertise.

For example, a network security specialist (**NetSec**) should provide **network segmentation**, raise and configure **IDS** and **IPS** to filter and block malicious traffic, and install firewalls (**Firewall**).
The **AppSec** must develop defence techniques at the application level, including the application of secure programming principles.

Thus, if an intruder bypasses one layer of protection, it is up to the next layer to prevent unauthorised access.

### Audit and Logging
Remember the office we described at the beginning? Usually offices have all visits, exits entered into the system and have surveillance systems installed.
Now imagine that the office has decided not to record people's entrances and exits, the cameras are not working, and valuable items have gone missing from the office.

Of course we know that the things were stolen, but why should we know about the fact of the theft if we can't find out who did it or how it was done. Now it's important that we don't allow this to happen in our system.

Failure to properly audit and log actions in systems violates one of the principles of information security - **non-repudiation**. It implies that a party cannot deny the fact of its participation in an action. Also their absence doesn't allow us to notice a problem in the system in time.

For effective auditing and logging, the following concepts should be introduced into our system as a minimum:

#### Security Events
This type of event will include all activities that relate to system security, including

* Successful/unsuccessful authentication attempts
* Attempts to access a protected resource
* Any abnormal activity (e.g. account access attempts exceeded)
* Changes in user access rights
* Access to critical files/systems
* Any information from security systems on different layers of the network (e.g. IDS and IPS).

To manage these events, we need to have an appropriate system called **SIEM** (Security Information and Event Management).
One of the best open-source solutions is [Wazuh](https://wazuh.com/).

#### Error Events
The name speaks for itself. These are error events that occur in our system and in the services of this system.
It includes:

- Connection failures (e.g. to databases)
- Network errors like connection failure
- Performance problems (e.g. timeouts)
- Failed attempts to send/receive messages

And any other internal application errors/exceptions.
Often, especially in small teams, instead of centralised error event handlers, they use a conditional `logs` folder where they store event logs by day.

This is really convenient if you are only testing 1 service locally and want to quickly see what's going on. But if you're already testing the whole system, or going into production mode, it's much preferable to use centralised error trackers.
Our favourite is [Sentry](https://sentry.io).

It is much more convenient to have all the information about errors of different services in the system, all the information about performance problems in one place, isn't it?
### Principles of simplified and open security
We have determined that a system is secure if the right preventative measures are in place at every layer.
But when implementing security systems, there are 3 basic principles to keep in mind:

#### Secure by Default
Systems and applications should be built from the ground up to be secure out of the box without additional configuration.
This principle is needed first and foremost to avoid human error.

You can see an example of how this principle is implemented in your browser. For example, popular browsers with no additional configuration include features that block pop-up windows, have protection against pop-up windows.
pop-ups, have phishing protection, and use **HTTPS** by default.

#### Open Design
Never base your security system on the principle of **security through obscurity**. Knowing the security architecture in our system should not give an attacker the ability to
to compromise it.

This is the same principle we apply in cryptography and is known as the **Kerckhoffs's Principle**. It sounds as follows:

*The security of a cryptographic system should not depend on the secrecy of the algorithm, but on the secrecy of the key.*

#### KISS
*(Keep It Simple Stupid)* is a principle that states that a system and its components should be as simple and easy to understand as possible.
Simpler systems are easier to understand and defend. Indeed, by implementing complex and incomprehensible systems, you are more likely to hinder yourself, and you will not be able to protect it effectively.

The same principle should be applied not only in our software architecture, but also in our application code. This will make it much easier for us to maintain it.

For example, if we have one big monolithic application, it is better to use the principle of *"Divide and Conquer"* and divide it into microservices.
___
## 2. Cyber-resilient security systems
Understanding security design principles helps us build systems that are secure against many attack vectors, including both external and internal threats.

But beyond security, we need to make sure that our security system is **resilient**. To understand how to make it resilient, let's look at the **Strategic** and **Structural** principles of security system resilience:

### Strategic Principles
Under strategic principles, we refer to those principles that guide the overall security and resilience strategy of a system. Among these, 5 main principles stand out:

#### Focus on shared critical resources
Remember in the previous article we described Security & Abuser stories? With their help, we were able to identify which resources are critical in the first place.
Organisational and software resources are often limited (or rather almost always), accordingly they should be focused on those resources first, where they will bring the most value.

#### Support flexibility and architect for adaptability
Security is not something you can just implement according to a conditional checklist and forget about. It is an iterative process and our system must always be ready to be modified in response to new threats and changes in the technology environment. Our goal is to design the system from the beginning so that the cost of change is minimised.

To follow this principle, try to take a **modular** approach. Divide the system into modules, and try to minimise the dependencies between them. The **KISS** principle described before will help a lot with this.

#### Reducing attack surfaces
Attack surfaces are the places in the system through which an attacker will try to penetrate our system. These can be not only services that go out to the network, but also **human resources**. After all, an attacker can exploit vulnerabilities not only in the systems aspect, but also by attacking specific people who may have access to the system.

Our goal in this case is to minimise the places an attacker can approach and focus on layering their protection.
Our best friends are the principles of minimum privilege, defence in depth and Zero Trust.

#### Any resource can be compromised
When designing systems, we shouldn't assume anything is 100% secure. We should always approach component security from the back end, and design everything so that the damage due to potential compromise is minimised.

Furthermore, systems must remain capable of meeting performance and quality requirements even if some of their components are compromised.
Strategies for recovery in the event of compromise must be developed in advance.

#### Attackers evolve
Cybercriminals are constantly evolving their attack methods and approaches. And they often do so faster than the level of overall security is increasing. When designing your security measures, try to ask the question *"how can this be bypassed?"* in addition to analysing "what does this protect against?".

To avoid falling prey to attackers, we need to design security measures several steps ahead and analyse new potential attack vectors when we introduce changes to our system. Moreover, **cyber-intelligence** is a very good practice to stay up to date with the latest security trends and attack methods.

### Structural Principles
The strategic principles described before drive the structural principles we apply to the system. We will describe **9** key principles that will ensure that our architecture and the security mechanisms within it are resilient.

#### Limit the need for trust
Trust in the components of a system means that we rely on them to perform important tasks. The fewer components that need to be trusted, the better for system security.

In the context of services, **Zero Trust** and the principle of least privilege will help us maintain it. But even when implementing even a Zero Trust architecture, we have already encountered one of its trusted components,
when we described how to use HashiCorp Vault and Consul to make a Zero Trust architecture.

In that case our trust component was a **identity token** and the shorter is its expiry date, the more secure it is for us.

#### Control visibility and usage
This principle aims to prevent an attacker to explore the system both outside and inside.
Here we can define 3 conditions under which we should apply it:

1. When the data must be protected from unauthorised access:\
   We encrypt this data for storage and transmission, or tokenise and obfuscate it.
2. When it is necessary to complicate the analysis of network traffic:\
   Here we use a technique known as "Chaffing & Winnowing", simply talking, we add noise to the traffic and to the transmitted data.
3. When it is necessary to protect the development process and supply chain:\
   This is in the area of **OPSEC** competence. But as a rule of thumb, the principles we know such as the **Minimum Privilege Principle** and encryption of transmitted data are applied.

#### Contain and exclude behaviours
This principle helps to control and restrict the behaviour of systems and their components to prevent undesirable actions and minimise the harm caused by them. Roughly speaking, our goal is to control the actions of attackers, even if they were able to penetrate the system. We must
limit **what** they can do and **where** they can get to:

1. **Exclude unacceptable behaviour**:\
   We can define the kinds of behaviours that **should not** happen. Let's take a trivial example from the CRM of a typical shop. If the shop's opening hours are from 08:00-18:00, then logically, we should prohibit any logins to the panel outside of this period.

2. **Content of suspicious behaviour**:\
   The principle is insanely simple. If any suspicious behaviour is detected, we should create an isolated environment where we can analyse it. For example, if a suspicious file is downloaded, we can run it in a separate sandbox to analyse it.

3. **Dynamic Segmentation and Isolation**:\
   Let's imagine that suspicious traffic is detected. The system needs to redirect this traffic to an isolated environment where we can safely analyse it in order to exclude potential harm.

In order to properly study behavioural patterns and automatic detection of suspicious activity, it is good practice to raise a separate isolated environment known as a **Honeypots**. In this environment, we will be able to analyse what the attacker wants to do and understand their train of thought.

#### Plan and manage diversity
I've described the importance of the **KISS** principle in architecture and security systems before, but there are cases where intentional complexity has benefits. One example describes this principle - namely the danger of **homogeneous** systems. It's important to strike a balance here:

Diversity helps protect the system from attacks that might be successful against homogeneous systems. Using a variety of technologies and methods reduces the likelihood that one vulnerability will compromise the entire system.

For example, critical services can use different operating systems on which they run so that a single vulnerability cannot be exploited on both. This is especially relevant if **Buffer Overflow** style vulnerabilities are suddenly discovered, where the success of instruction execution is highly dependent on the architecture on which the application and OS are running.
Different OS and architectures may handle memory differently, making it difficult to exploit the same vulnerability on different systems.

Also, you can use different Cloud providers so that if one is unavailable, some of the services are still available when deployed in another provider.

#### Maintain redundancy
Remember the third principle of the CIA triad - **availability** that we talked about in the first article? That's the principle - redundancy helps avoid system failures and malfunctions. If one component fails, another component can take over its functions, ensuring system continuity.

We often apply redundancy when we want to **balance** activity on a server. Designing a component of the system to support **horizontal scaling** will simply allow a second such component to be started if one component fails, or is disabled due to failure.

#### Manage resources adaptively
We want our system to be flexible, don't we? If so, then the environment in which it operates should **adapt** to real-time changes. It should react quickly to changes and minimise the effects of disruptions including failures.

For example, in the case of threat detection, firewall and security rules can change in response to intrusions. Or let's not go too far, by taking the example of trivial authorisation - if it is noticed that a user tries to log in from an unknown location, even if the login password is correct, we need to authenticate him additionally (e.g. via email).

#### Determine current reliability
Do not rely on the stability of components over time, but rather check their current reliability on a regular basis. This includes periodic verification, continuous monitoring to detect and remediate potentially malicious behaviour in time.

It's also good practice to pen-test your system regularly to make sure it's secure over time. One of our favourites for pentesting is **OWASP ZAP**. We'll learn how to pen-test systems effectively in the **Security in Testing** article.

#### Modify or disrupt the attack surface
In the case where an attacker uses an attack surface (conventionally attacking one of our services), we can think of ways to make it harder for them to succeed.

This includes:
1. Dynamic change of system configurations (e.g. change of system IP addresses).
2. Moving important data and services between different physical or virtual locations.
3. Creating false targets, such as honeypots.

As an example, let's imagine that an attacker has launched a DDoS attack. One of the most effective methodologies that I believe is not just filtering traffic, but using the **IP Hopper** mechanism.
According to this methodology, all legitimate traffic should be redirected to a server that is not under attack, while illegitimate traffic literally attacks *emptiness*.

#### Make the effects of deception and unpredictability transparent to the user
Finally the last structural principle for building resilient systems. Throughout this article, we have learnt many security mechanisms that can be designed and applied.

The idea behind this principle is that it is the attackers who should be challenged by our security mechanisms. Mechanisms should not interrupt the continuity of our system for legitimate users.
___
## Conclusion
In this article, we have reviewed key principles of secure design and methods for ensuring its resilience.

We walked through the eight principles of secure design:
1. Principle of least privilege - Systems and its components should have as many rights as they need and no more.
2. Zero Trust Principle - Don't trust services and users, even if they are inside the corporate network.
3. Fail Securely - Handle failures in such a way that they do not give away internal system information.
4. Defence in Depth - Security cannot be built from a single layer.
5. Auditing and Logging - Auditing, logging of security events, and real-time error tracking.
6. Secure by Default - Systems should not require additional configuration to be secure.
7. Open Design - The security of the system should not depend on the secrecy of its implementation.
8. KISS - Don't overcomplicate the system, that way we will only complicate our lives rather than improve security.

Learned strategic principles of sustainability:

1. Focus on shared critical resources
2. Support flexibility and adaptability
3. Reducing attack surfaces
4. Assumption of resource compromise
5. Accounting for the evolution of attack methods

And we deconstructed the structural principles of resilience:

1. Limiting the need for trust
2. Control of visibility and utilisation
3. Containing and excluding undesirable behaviours
4. Diversity planning and management
5. Maintaining redundancy
6. Adaptive resource management
7. Determining current reliability
8. Modifying or breaking the attack surface
9. Transparency of the effects of deception and unpredictability on users

Thus, by following secure design principles and system resilience principles, we can design a truly secure architecture that is ready to provide protection in the aggressive external world.