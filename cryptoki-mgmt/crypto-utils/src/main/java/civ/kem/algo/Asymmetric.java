package civ.kem.algo;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

public class Asymmetric {
    /**
     * Encrypts data using the specified asymmetric encryption mechanism.
     *
     * @param p11 PKCS#11 wrapper instance.
     * @param hSession Handle to the PKCS#11 session associated with the token.
     * @param mechanism The encryption mechanism to use (e.g., RSA PKCS1, OAEP).
     * @param hKey Handle of the public key used for encryption.
     * @param plaintext The data to encrypt.
     * @param ciphertext Output buffer for the encrypted data.
     * @throws Exception If an error occurs during the encryption process.
     */
    public static void encrypt(PKCS11 p11, long hSession, CK_MECHANISM mechanism, long hKey, byte[] plaintext, byte[] ciphertext) throws Exception {
        p11.C_EncryptInit(hSession, mechanism, hKey);
        p11.C_Encrypt(hSession, 0L, plaintext, 0, plaintext.length, 0L, ciphertext, 0, ciphertext.length);
    }

    /**
     * Decrypts data using the specified asymmetric decryption mechanism.
     *
     * @param p11 PKCS#11 wrapper instance.
     * @param hSession Handle to the PKCS#11 session associated with the token.
     * @param mechanism The decryption mechanism to use (e.g., RSA PKCS1, OAEP).
     * @param hKey Handle of the private key used for decryption.
     * @param ciphertext The encrypted data.
     * @param plaintext Output buffer for the decrypted data.
     * @throws Exception If an error occurs during the decryption process.
     */
    public static void decrypt(PKCS11 p11, long hSession, CK_MECHANISM mechanism, long hKey, byte[] ciphertext, byte[] plaintext) throws Exception {
        p11.C_DecryptInit(hSession, mechanism, hKey);
        p11.C_Decrypt(hSession, 0L, ciphertext, 0, ciphertext.length, 0L, plaintext, 0, plaintext.length);
    }

    /**
     * Signs a hash using the specified asymmetric signing mechanism.
     *
     * @param p11 PKCS#11 wrapper instance.
     * @param hSession Handle to an open PKCS#11 session.
     * @param signMech The signing mechanism to use (e.g., ECDSA, RSA PKCS1).
     * @param hPrivateKey Handle of the private key used for signing.
     * @param hash The hash value to sign.
     * @param hashLen Length of the hash value.
     * @return The generated signature.
     * @throws PKCS11Exception If an error occurs during signing.
     */
    public static byte[] sign(PKCS11 p11, long hSession, CK_MECHANISM signMech, long hPrivateKey, byte[] hash, long hashLen) throws PKCS11Exception {
        p11.C_SignInit(hSession, signMech, hPrivateKey);
        return p11.C_Sign(hSession, hash);
    }

    /**
     * Verifies a signature against the given data using the specified asymmetric verification mechanism.
     *
     * @param p11 PKCS#11 wrapper instance.
     * @param hSession Handle to an open PKCS#11 session.
     * @param verifyMech The verification mechanism to use (e.g., ECDSA, RSA PKCS1).
     * @param hPublicKey Handle of the public key used for verification.
     * @param data The original data that was signed.
     * @param signature The signature to verify.
     * @throws PKCS11Exception If the verification fails or an error occurs.
     */
    public static void verifySignature(PKCS11 p11, long hSession, CK_MECHANISM verifyMech, long hPublicKey, byte[] data, byte[] signature) throws PKCS11Exception {
        p11.C_VerifyInit(hSession, verifyMech, hPublicKey);
        p11.C_Verify(hSession, data, signature);
    }

    /**
     * Generates an asymmetric key pair.
     *
     * This method generates a public-private key pair using the provided key generation
     * mechanism and attribute templates. The generated keys are returned as handles.
     *
     * @param p11 PKCS#11 wrapper instance used to interact with the token.
     * @param hSession Handle to an open PKCS#11 session associated with the token.
     * @param keyGenMech The key generation mechanism to use (e.g., RSA, EC).
     * @param publicTemplate Attribute template for the public key.
     * @param privateTemplate Attribute template for the private key.
     * @param hPublicKey Output parameter to store the generated public key handle.
     * @param hPrivateKey Output parameter to store the generated private key handle.
     * @throws PKCS11Exception If an error occurs during key pair generation.
     */
    public static void generateKeyPair(PKCS11 p11, long hSession, CK_MECHANISM keyGenMech, CK_ATTRIBUTE[] publicTemplate, CK_ATTRIBUTE[] privateTemplate,
                                       long hPublicKey, long hPrivateKey) throws PKCS11Exception {
        long[] keys = p11.C_GenerateKeyPair(hSession, keyGenMech, publicTemplate, privateTemplate);
        hPublicKey = keys[0];
        hPrivateKey = keys[1];
    }
}
