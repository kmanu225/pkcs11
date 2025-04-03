# PKCS#11

[PKCS#11](https://www.cryptsoft.com/pkcs11doc/) (Public-Key Cryptography Standard #11) is a platform-independent API standard for managing cryptographic tokens such as smartcards, HSMs (Hardware Security Modules), SSMs (Software Security Modules), and other security modules. In this context, PKCS#11 is also referred to as the Cryptographic Token Interface (Cryptoki).

It defines a set of functions that applications can use to interact with secure elements, enabling secure key storage, digital signatures, and encryption/decryption operations.

## History

- PKCS#11 was initially developed and maintained by RSA Labs from 1995 to 2009.
- Currently, PKCS#11 is maintained by the [OASIS committee](https://groups.oasis-open.org/communities/tc-community-home-new?CommunityKey=000035465).
- The different versions of the standard are available at the [PKCS-DOC](https://www.cryptsoft.com/pkcs11doc/) website:
  - **V2.20**: Widely used and implemented by multiple token vendors.
  - **V2.30**: Still a draft.
  - **V2.40**: The first published version by OASIS.

## Project Structure

The project is organized as follows:

```
.
├── standard/      # Contains references to PKCS#11 documentation 
└── programs/      # Contains programs to interact with cryptographic devices using the PKCS#11 API
```

## Getting Started

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-folder>
   ```
2. Explore the directories:
   - **standard/**: Access PKCS#11 documentation references.
   - **programs/**: Run or modify programs interacting with PKCS#11-compliant devices.

## Resources
- [PKCS#11 Specification](https://www.cryptsoft.com/pkcs11doc/)
- [OASIS PKCS#11 Community](https://groups.oasis-open.org/communities/tc-community-home-new?CommunityKey=000035465)

