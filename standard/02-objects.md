# Logical View of a Token  

## Token Objects  

Cryptoki's logical view of a token is that of a device that stores objects and can perform cryptographic functions. Cryptoki defines three classes of objects:  

- **Data objects:** Defined by an application.  
- **Certificate objects:** Store certificates.  
- **Key objects:** Store cryptographic keys. Keys can be public, private or secret.  

Each key type may have subtypes for use in specific mechanisms. This view is illustrated in the following figure:  

<p align="center">
  <img src="https://www.cryptsoft.com/pkcs11doc/v220/v220_figure_2.gif" alt="Object Hierarchy">
</p>

<p align="center"><b>Object Hierarchy</b></p>  


## Object Lifetime  

Objects are classified by their **lifetime and visibility:**  

- **Token objects:**  
  - Visible to all applications with sufficient permissions.  
  - Persist on the token even after sessions are closed and the token is removed.  

- **Session objects:**  
  - Temporary objects created during a session.  
  - Destroyed automatically when the session is closed.  
  - Visible only to the application that created them.  



## Object Visibility  

Access to objects depends on authentication requirements:  

- **Public objects:** No login required.  
- **Private objects:** Requires user authentication via **PIN** or other methods (e.g., biometric authentication).  



## Object Operations  

A token can:  

- **Create and destroy objects**  
- **Manipulate and search for objects**  
- **Perform cryptographic functions using objects**  
- **Generate random numbers (if supported by the hardware)**  



## Implementation Considerations  

Not all cryptographic devices implement the concept of **objects** or support all cryptographic functions. Many devices:  

- Have **fixed storage** for keys of specific algorithms.  
- Support a **limited set of cryptographic operations**.  

Cryptoki abstracts these differences by **mapping attributes to storage elements**, providing a consistent logical view. Standard **profiles** may define required algorithm support for interoperability.  



## Attributes  

Objects in Cryptoki have **attributes** that define their properties:  

- **General attributes:** Define if the object is **public** or **private**.  
- **Type-specific attributes:** Example: **RSA keys** have attributes like **modulus** and **exponent**.  

---


**© RSA Security Inc. — Public-Key Cryptography Standards (PKCS#11) v220**  
