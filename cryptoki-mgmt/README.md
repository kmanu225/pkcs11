# Try PKCS#11

The best way to learn **PKCS#11** is by practicing with it—either on a real cryptographic device or with an emulator.
This repository provides example source code for interacting with cryptographic tokens using PKCS#11.

## Prerequisites

* **Java 9 or higher**
* **Maven** (for building the project)
* **Cryptographic token** (or emulator) and its corresponding **PKCS#11 driver/library**

## Usage (Example with crypto-utils)

### 1. Configure the PKCS#11 Library

Update the `library.properties` file to point to your PKCS#11 library:

```
cryptoki-mgmt/crypto-utils/src/main/resources/library.properties
```

### 2. Building the Project

To build the project with Maven:

```sh
mvn clean package
```

The output JAR will be generated in the `target/` directory.

### 3. Run the Predefined Main Class

To run the default entry point:

```sh
java -jar crypto-utils-<version>.jar
```

### 4. Run a Specific Module

To execute a specific module, use:

```sh
java \
  --add-exports jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED \
  -cp crypto-utils-<version>.jar <module> <arguments>
```

#### Example: Get Token Information

```sh
java \
  --add-exports jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED \
  -cp crypto-utils-<version>.jar civ.kem.algo.GetInfo -info -slot -token 0
```