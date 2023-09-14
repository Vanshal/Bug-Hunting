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
