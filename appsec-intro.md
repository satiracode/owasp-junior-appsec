# AppSec PlayBook

# Article 1: Introduction to AppSec
~ 1000 words
* Equifax data breach. 3 broken principles.
* CIA Triad
* Role of AppSec. SDLC.
* Comparison of cost on different SDLC cycles.

# Article 2: Security in Requirements
~ 1500 words
* SMART principle
* Abuser & Security stories. Examples.
* Security requirements traceability matrix (SRTM). Examples.

# Article 3: Security in Design:
~ 2000 words
* Least privilege principle
* Zero Trust
* Secure by Default
* Defense in Depth
* Auditing & Logging
* Threat Modeling
    * STRIDE
    * DREAD

# Article 4: Security in Development:
~ 3000 words
* Don't believe user input. Threats and mitigation:
    * SQL Injection
    * XSS Injection
    * Path Traversal
* Access Control:
  * MAC and DAC
  * RBAC with Spring Security
  * Session Management. Protecting from Session attacks.
  * Token Authentication: JWT & OAuth2
* Error handling. Spring Security.
* Strong cryptography:
  * Encrypt the traffic. MITM.
  * Password hashing.
  * Properly store sensitive data. OWASP Memory.
  * TLS. Secure cipher-suites.
* Keep It Simple Stupid (KISS)
* Intro to SAST:
  * SonarQube and IntelliJ Idea
  * Checkmarx.

# Article 5: Security in Testing
~ 1500 words
* Penetration Testing. Intro to DAST.
* Intro to Burp Suite.
* Intro to OWASP ZAP

# Article 6: Security in Deployment and Maintenance
~ 2000 words
* Deployment:
  * Sign and check integrity of packages.
  * Properly store secrets:
    * HashiCorp Vault
    * AWS Secrets Manager
* Maintaining:
  * Vulnerability management.
  * Patching.

# Article 7: Know your enemy by sight. App layer fingerprinting.
~ 3000 words
* Intro to Netty and Spring Boot Reactive.
* JA3 Fingerprinting
* JA4 and JA4H Fingerprinting
* HTTP/2 Akamai Suggested fingerprinting

# Article 8: Incident Response for AppSec
~ 2000 words
* Overview of NIST SP 800-61
* Developing Incident Response Plan
* Connecting relevant Stakeholders
* Intro to SIEM, IDS/IPS
* Example scenarios