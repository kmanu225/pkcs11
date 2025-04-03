# Cryptoki Model  

## Design Goals

The primary goal of Cryptoki was to provide a lower-level programming interface that abstracts the details of cryptographic devices and presents a common model of the cryptographic device, called a **"cryptographic token"** (or simply **"token"**).  

A secondary goal was resource-sharing. As desktop multi-tasking operating systems become more popular, a single device should be shared between more than one application. In addition, an application should be able to interface to more than one device at a given time.

## Cryptoki

Cryptoki's general model is illustrated in the following figure. The model begins with one or more applications that need to perform certain cryptographic operations and ends with one or more cryptographic devices on which some or all of the operations are actually performed. A user may or may not be associated with an application. Cryptoki provides an interface to one or more cryptographic devices that are active in the system through a number of **"slots."**  

<p align="center">
  <img src="https://www.cryptsoft.com/pkcs11doc/v220/v220_figure_1.gif" alt="General Cryptoki Model">
</p>

<p align="center"><b>General Cryptoki Model</b></p>  

## Slot

A slot corresponds to a physical reader or other device interface. A slot may contain a token. A token is typically "present in the slot" when a cryptographic device is present in the reader.  

Since Cryptoki provides a logical view of slots and tokens, there may be other physical interpretations. It is possible that multiple slots may share the same physical reader. The key point is that a system has some number of slots, and applications can connect to tokens in any or all of those slots.  

## Cryptographic Device Abstraction

A cryptographic device can perform certain cryptographic operations using a specific command set. These commands are typically passed through standard device drivers, such as **PCMCIA card services** or **socket services.**  

Cryptoki makes each cryptographic device appear logically similar, regardless of its implementation. This abstraction allows applications to interact with devices without needing direct access to their respective drivers. The underlying "device" may even be implemented entirely in software (for example, as a process running on a server), meaning no special hardware is required.  

## Cryptoki Implementation

Cryptoki is typically implemented as a **library** supporting the functions in its interface. Applications can link to the library either **statically** or **dynamically:**  

- **Static linking:** The application is directly linked to the Cryptoki library.  
- **Dynamic linking:** The Cryptoki library is loaded at runtime as a shared library (DLL or `.so`).  

### Security Considerations

While dynamic linking offers flexibility (allowing updates to libraries without modifying applications), it presents security concerns. Attackers may replace a legitimate library with a rogue version to intercept sensitive information, such as a user's **PIN.**  

For enhanced security, direct linking is preferable. However, **code-signing** techniques can mitigate some of the risks associated with dynamic linking.  

### Library and Token Support

Cryptoki does not dictate which cryptographic devices or algorithms a library must support. Different implementations may support a subset of mechanisms, and vendors may develop libraries that accommodate multiple token types. Over time, **standard library and token profiles** are expected to emerge to improve compatibility.  

---

**© RSA Security Inc. — Public-Key Cryptography Standards (PKCS#11) v220**
