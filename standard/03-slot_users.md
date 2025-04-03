# Cryptoki's User Roles and Authentication  

Cryptoki establishes two distinct user roles: the **security officer (SO)** and the **normal user**. Each role has specific responsibilities in managing and accessing the token’s cryptographic functions.  

## Security Officer vs. Normal User  

The **Security Officer (SO)** is responsible for initializing the token and setting the normal user's **PIN**. The SO may also manage certain public objects but does not have access to private objects. The **normal user**, on the other hand, gains access to private objects only after successful authentication. Some tokens may even require authentication before performing any cryptographic operations, regardless of whether private objects are involved.  

## PIN Management in Cryptoki  

PINs in Cryptoki are **variable-length character strings**, but the standard does not dictate how they should be generated, padded, or entered. These aspects are left to the token's manufacturer or the application handling authentication. Cryptoki simply ensures that the token can wait for PIN input and process it according to its internal requirements.  

## The SO-User Relationship  

Cryptoki does not impose rules on whether the SO and normal user must be different individuals or the same person. It also does not define how an SO interacts with a community of users, allowing flexibility in organizational security policies.  

---

**© RSA Security Inc. — Public-Key Cryptography Standards (PKCS#11) v220**
