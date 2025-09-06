package civ.kem.algo;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

public class Symmetric {

    /**
     * Encrypts data using AES or another symmetric encryption algorithm.
     *
     * @param p11 PKCS#11 wrapper instance.
     * @param hSession Handle to the active PKCS#11 session.
     * @param mechanism The encryption mechanism to use (e.g., AES ECB, AES CBC).
     * @param hKey Handle to the encryption key.
     * @param plaintext The data to be encrypted.
     * @param ciphertext The buffer to store the resulting encrypted data.
     * @throws Exception If an error occurs during encryption.
     */
    public static void encrypt(PKCS11 p11, long hSession, CK_MECHANISM mechanism, long hKey, byte[] plaintext, byte[] ciphertext) throws Exception {
        p11.C_EncryptInit(hSession, mechanism, hKey);
        p11.C_Encrypt(hSession, 0L, plaintext, 0, plaintext.length, 0L, ciphertext, 0, ciphertext.length);
    }

    /**
     * Decrypts data using AES or another symmetric encryption algorithm.
     *
     * @param p11 PKCS#11 wrapper instance.
     * @param hSession Handle to the active PKCS#11 session.
     * @param mechanism The decryption mechanism to use (e.g., AES ECB, AES CBC).
     * @param hKey Handle to the decryption key.
     * @param ciphertext The data to be decrypted.
     * @param plaintext The buffer to store the resulting decrypted data.
     * @throws Exception If an error occurs during decryption.
     */
    public static void decrypt(PKCS11 p11, long hSession, CK_MECHANISM mechanism, long hKey, byte[] ciphertext, byte[] plaintext) throws Exception {
        p11.C_DecryptInit(hSession, mechanism, hKey);
        p11.C_Decrypt(hSession, 0L, ciphertext, 0, ciphertext.length, 0L, plaintext, 0, plaintext.length);
    }

    /**
     * Computes the hash (digest) of the given data using a specified hashing algorithm.
     *
     * @param p11 PKCS#11 wrapper instance.
     * @param hSession Handle to the active PKCS#11 session.
     * @param hashMech The hashing mechanism to use (e.g., CKM_SHA_256).
     * @param data The data to hash.
     * @param dataLen Length of the data to hash.
     * @return The computed hash as a byte array.
     * @throws PKCS11Exception If an error occurs during hashing.
     */
    public static byte[] shaHashData(PKCS11 p11, long hSession, CK_MECHANISM hashMech, byte[] data, long dataLen) throws PKCS11Exception {
        byte[] hash = null;

        // Perform a single-step digest operation
        p11.C_DigestSingle(hSession, hashMech, data, 0, data.length, hash, 0, data.length);

        return hash;
    }

    /**
     * Generates a symmetric key using a specified key generation mechanism.
     *
     * @param p11 PKCS#11 wrapper instance.
     * @param session Handle to the active PKCS#11 session.
     * @param template Template defining the attributes of the key (e.g., label, usage).
     * @param mechanismType The key generation mechanism to use (e.g., CKM_AES_KEY_GEN).
     * @param keyName The name (label) assigned to the generated key.
     * @param bPrivate If true, the key is created as a private object.
     * @return The handle of the generated symmetric key.
     * @throws PKCS11Exception If an error occurs during key generation.
     */
    public static long generateKey(PKCS11 p11, long session, CK_ATTRIBUTE[] template, long mechanismType, String keyName, boolean bPrivate) throws PKCS11Exception {
        CK_MECHANISM keyGenMech = new CK_MECHANISM(mechanismType);
        return p11.C_GenerateKey(session, keyGenMech, template);
    }
}
