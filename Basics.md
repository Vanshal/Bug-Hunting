-----------------
Crypto 

bit - 0 or 1 
1 byte - 8bit

Steam cipher - symmetric - take one bit/byte at a time and do XORing       
Block cipher - symmetric - take one block (64bit,128bit etc) at a time      - blowfish, aed, des 
 
Confusion - try to make the Relation between plaintext and cipher texT AS complex as possible, if we change 1 bit of plaintext then half or more bit of cipher text should also change. 
Defusion - try to make the Relation between key and cipher texT AS complex as possible, if we change 1 bit of key then almost all bits of cipher text should change. 


Symmetric - AES 256 - 
Asymmetrric - RSA - 

Since RSA cannot encrypt long messages, we can use AES to encrypt and encrypt the AES key using RSA to securely share it to someone. 

-------------------

SSL Handshake - 

Client Hello  
Server Hello with Certificate which contains Public Key 
Client Verifies the Certificate from CA provider (expiration, validity etc) and check the Cipers which both supports to use
Client generates a key which he encodes using server public key and send it to server (key is symmectric encr)  (To enusure if server is who he say he is)
Server decrypt the key using asymeetric encr (private key) and estabilish a secure encrypted communication.


Mutual TLS 

Client Hello.
Server Hello with Certificate (public key) to the client.
Client then confirm the CAs whether it’s a valid certificate issued by them or not. This step to make sure server is who its claming to be. 
Client share his cert and then server verifeis if client is allowed/whitelisted and in the Trust store or not. 
And then use a aggreed upon secret in symmetric encrpytion. 

--------------------


PIA data is stored how? - Encryption - Symmetric or Assymetric depening of the need. 
password hasing how? -  best practice hash - Argon2 or Bcrypt with SALT
To verify file signatures and certificates, SHA-256
Hashing Rounding - taking a hash -> changing 1 bit and rehashing it.  


-------------
Devsecops

STRIDE - Security threat model framework used  to identify potential threats to applications. Each letter in the STRIDE acronym represents a different type of threat:

Spoofing
Tampering 

Information Disclosure
Denial of Service (DoS) 
Elevation of Privilege 


THREAD MODDELING - Structured process of identifying, assessing, and mitigating security risks in software applications by analyzing the interactions and behaviors of threads, which are concurrent execution units, within the application's architecture and design.
 
Continues Integration/CD -> Dependency Check SCA (Checkmarx)- SAST (checkmarx) - pull DOCKER and SCAN -> PUSH CODE in docker -> OS Hardeding (scanning the final docker in which application is running)

SHIFT LEFT Approach - implementing securtiy as early in SDLC as possible. 

how the after encryption  key is stored? 0in valut 
hashicorp vault

----------


MOBILE 

Certificate Pinning Bypass - 2 methods: By making changes in Source code OR Android SSL-Trust-Killer application or similar modules in xposed 

Approach - shared pref, folder permissions, MODE_WORLD_READBALE writable files and folders, allow_backup should be false,allow_debug should be false,READ_LOGS flag, static analysis, dex2jar, jd-gui, hardcoded, aws urls, internalIPs, drozer, 

LOGS - 
Copy/Paste -  other malicious application can access clipboard and steal data

Exported Content Provider - Could contain keys, creds, secrets  
Exported Activities and Permissions - Open after auth activity using (drozer)
Attacking Services- Any exported service(for ex: location) can be executed without any auth through malicious application (drozer)  (this will enalbed location of the andriod device)


 code obfuscation with the help of Proguard to avoid jd-gui  - dont stop completly but slow down the RE 

how jwt should be stored in android. or any other auth token -  
    - encrypt using 3rd party or EncryptedSharedPreferences lib  and store In shared pref
    - Store tokens in memory while app runs, for short term sessions.
    - In Android Keystore 
    - Biometric Authentication 2fa for Android Keystore 


rootdetectuion - rootbear
sslpinning  bypass xposed - frida 
MOBSF


webview - load webpage within application 
deeplink - customeschemma://call/profiledelete

CSRF - deleteprofile deeplink, any 3rd party applicaiton can call the deeplink and deleteprofile_- (autoverify = true) should be set in AndriodManifest to remidiate this. 
openredirect- find deeplink with intent-filter and schema. and execute

Intent can be used for

To start an Activity, typically opening a user interface for an app
As broadcasts to inform the system and apps of changes
To start, stop, and communicate with a background service




----------
Web


HTTP DYSYNC
Deserialization

DOM - 
sources:
document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location.search
document.cookie
document.referrer

sinks:
eval
element.innerHTML
element.outerHTML
element.insertAdjacentHTML
element.onevent
document.write()
document.writeln()
document.domain



* Oauth flows - 
Authorization Code Flow - Authorization token is reviced and then back-end server-server communication for accesstoken and userdetails
Implicit Grant Type - Used for single page application since, there is no backend. they directly recive the acecss token through the interceptanle request and then send a post request to save it in the dataabsed if needed for furute for user login 

State 
redirect_uri + open redirect chain 


OPENID - layer on top of oauth for authentication 
    - scope openid - must
    - id_token - jwt token recevied with access token as identify identifer of user

attack - self client register with redirect_uri ,logo uri , which is getting trigged causeing an ssrf




------
Network

OSI - Common Attacks
 

Physical -  Cables, wire, Bluethooth, USB, LAN      - DOS attacks, MITM physical device 
DataLink -  ARP, WAN                                - ArpSpoofing, Mac Flooding
Network  -  IMCP, IPv4, IPv6, IPsec                 - IP Spoofing
Transport - TCP/UDP                                 - DDOS- SYN Flood
sessions  - NetBios                                 - Session Hijacking
Presentation  - SSL                                 - SSL Hijacking MITM
Application Layer - ALL the web related attacks - SQLi, xss, parameter tampering

All people should try new dominos pizza


evildropping
DNS posinoing - 
arp SPoofing - Mac:IP 
-----------

Hardik - 

Bufferover flow basic 

Application take username input of 8 char, we give more chars and application should give error if we give more and should not process the input, buffer overflow occurs when ex. we give 10 char input and application processes that last of char input. that is executed in the memorty, attacker could run malicious shell script, rev shell etc. 


Network 

How does Nmap work? 
Ping work?

---------
Config Review.  CIS BenchMark/ TrendMicro 
Azure Benchmark foundation 
GCP Benchmark 
AWS Benchmark 

palo alto

Components/services - iam , lambda, eks, 
------


Owasp cheatsheet -

Database
Crypto
TLS
CSRF
DOM BASED XSS 
Mobile Applicatino
Cloud Architecture Security
Arcitechture review
Secret Management




**Firewalls** control and filter network traffic to protect against unauthorized access and cyber threats. Control What goes out of internal network and what req comes in.

**Intrusion Detection Systems (IDS)** monitor network traffic for signs of potential attacks and generate alerts.

**Intrusion Prevention Systems (IPS)** go a step further by not only detecting threats but actively blocking or mitigating them to protect your network in real-time.





------


**Secure Shell (SSH)** - A network protocol that provides secure access to remote systems and encrypted data communication.

**Secure Sockets Layer (SSL)** - A security protocol that ensures encrypted and secure communication over the internet, commonly used in web browser and a web server.

**Transport Layer Security (TLS)** - A cryptographic protocol that ensures secure communication over internet. It is an updated and more secure version of SSL (Secure Sockets Layer) and is commonly used to encrypt data transmitted between a client (e.g., web browser) and a server, providing confidentiality and integrity of the information exchanged.

**Internet Protocol Security (IPsec)** -  set of protocols  used to secure Internet Protocol (IP) communications (IPs, router, server, http-https,ftp,ssh,packets etc ). It provides authentication, encryption, and data integrity for data transmitted over IP networks, ensuring the confidentiality and security of network traffic. IPsec is often used to establish virtual private networks (VPNs) and secure communication between networked devices.

IP communications enable devices worldwide to exchange data over the internet. It's the language that devices use to talk to each other, and it forms the backbone of our digital connectivity.

**Domain Name System Security Extensions (DNSSEC)** - Set of protocols and security measures designed to enhance the security of the DNS. DNS is responsible for translating human-friendly domain names (like www.example.com) into IP addresses that computers and servers use to locate each other on the internet.

DNSSEC adds a layer of security to this translation process by digitally signing (asymmetric cryptograpy) DNS data.




---------



### Applied cryptography:

**Symmetric encryption** - One Key Shared with All -  AES 

**Asymmetric encryption** - Public And Private Key - RSA

**Hashing** - Integrity of data  (Password should be hashed with random salt)



# Hashing vs. Encryption vs. Encoding

## Hashing

- **Purpose:** Hashing is primarily used to transform data into a fixed-size string of characters, known as a hash value or digest. It is commonly used for data integrity verification and data retrieval.

- **Operation:** It is a one-way process, meaning it cannot be reversed to obtain the original data.

- **Security:** Hashing is not designed for data security or confidentiality; its primary purpose is data integrity verification.

- **Use Cases:** Hashing is used in password storage (with salting), digital signatures, verifying file integrity, and in data structures like hash tables for efficient data retrieval.

## Encryption

- **Purpose:** Encryption is used to protect data confidentiality by converting plain text (original data) into a ciphertext (encrypted data) that can only be read by authorized parties with the decryption key.

- **Operation:** Two way - Public Private Key.

- **Security:** Encryption is focused on protecting data from unauthorized access. It ensures that even if someone gains access to the encrypted data, they cannot decipher it without the decryption key.

- **Use Cases:** Encryption is widely used in securing communications (e.g., SSL/TLS for secure web browsing), protecting sensitive data at rest (e.g., full-disk encryption), and ensuring data privacy.

## Encoding

- **Purpose:** Encoding is used to represent data in a specific format for data transmission . It doesn't provide security or data transformation like hashing or encryption.

- **Operation:** Encoding translates data from one format to another, typically using a well-defined scheme. It's a reversible process, meaning the original data can be obtained by decoding it.

- **Security:** Encoding is not a security measure. It's used to ensure that data is in a format that can be correctly processed by various systems and protocols.

- **Use Cases:** Encoding is used in various scenarios, such as URL encoding for web addresses, Base64 encoding for binary-to-text conversion, and character encoding (e.g., UTF-8) for international character representation.





# Digital Signatures vs. Hashing

Digital signatures and hashing are both cryptographic techniques used to ensure the integrity and authenticity of data, but they serve different purposes and have distinct characteristics:

## Purpose

- **Digital Signatures:** Digital signatures are primarily used to verify the authenticity of a document or message and ensure that it has not been tampered with during transmission. They provide a means to prove the identity of the sender and guarantee that the sender has endorsed the content.

- **Hashing:** Hashing is used to create a fixed-length string of characters (the hash value or digest) from any input data, regardless of its size. Hashing is primarily used for data integrity verification. It ensures that data has not changed by comparing the hash of the original data with the hash of the received data.

## Operation

- **Digital Signatures:** Digital signatures involve the use of asymmetric cryptography. A private key is used to create the signature, and a corresponding public key is used to verify it.

- **Hashing:** Hashing uses a one-way hash function to transform data into a fixed-size string of characters. It is a one-way process, meaning it cannot be reversed to obtain the original data.

## Verification

- **Digital Signatures:** Verification of a digital signature requires the sender's public key and the signature itself. The recipient can confirm the authenticity of the message and the sender's identity.

- **Hashing:** Hash verification only requires the hash value of the original data and the recalculated hash of the received data. If the two hash values match, the data is considered intact.

## Use Cases

- **Digital Signatures:** Used in scenarios where both data integrity and sender authentication are important, such as secure email communication, digital contracts, and software updates.

- **Hashing:** Used for data integrity checks, password storage (by hashing and salting), and in various data structures like hash tables for efficient data retrieval.

In summary, digital signatures are more focused on data integrity and sender authentication, while hashing is primarily used for data integrity verification. These techniques are often used in combination to ensure the security of digital communications and data storage.
