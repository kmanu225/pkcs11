package civ.kem.algo;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

public class ManageObjects {

    /**
     * Searches for an object on a token matching the provided template.
     *
     * This method initializes a search for objects that match the given
     * template, which could be used to locate keys, certificates, or other
     * PKCS#11 objects. It returns the handle of the first matching object.
     *
     * @param p11 PKCS#11 wrapper instance used to interact with the token.
     * @param hSession Handle to the open PKCS#11 session associated with the
     * token.
     * @param template Cryptoki template defining the desired object's
     * attributes.
     * @return The handle of the first object found that matches the template.
     * @throws Exception If no matching object is found.
     */
    public static long find(PKCS11 p11, long hSession, CK_ATTRIBUTE[] template) throws Exception {

        long[] hObjects;

        // Initialize object search using the provided template.
        p11.C_FindObjectsInit(hSession, template);
        hObjects = p11.C_FindObjects(hSession, 1);  // Fetch at most one object.
        p11.C_FindObjectsFinal(hSession);  // Finalize the search.

        // Return the first object found, or throw an exception if none is found.
        if (hObjects.length >= 1) {
            return hObjects[0];
        } else {
            throw new Exception("Object not found!");
        }
    }

    /**
     * Deletes an object from the token.
     *
     * This method destroys a specified object (such as a key or certificate)
     * from the token, effectively removing it.
     *
     * @param p11 PKCS#11 wrapper instance used to interact with the token.
     * @param hSession Handle to the open PKCS#11 session associated with the
     * token.
     * @param hObject The handle of the object to be destroyed.
     * @throws PKCS11Exception If an error occurs during the object destruction
     * process.
     */
    public static void delete(PKCS11 p11, long hSession, long hObject) throws PKCS11Exception {
        p11.C_DestroyObject(hSession, hObject);
    }

    /**
     * Derives a new cryptographic key based on a provided base key using the
     * specified mechanism.
     *
     * This method uses a cryptographic mechanism (e.g., CKM_ECDH1_DERIVE) to
     * generate a new key from a base key. The new key's attributes are defined
     * by the provided template.
     *
     * @param p11 PKCS#11 wrapper instance used to interact with the token.
     * @param hSession Handle to the open PKCS#11 session associated with the
     * token.
     * @param mechanism The cryptographic mechanism used for key derivation.
     * @param hBaseKey The handle of the base key used for derivation.
     * @param newObjTpl The template specifying attributes for the new derived
     * key.
     * @return The handle of the newly derived key.
     * @throws PKCS11Exception If an error occurs during the key derivation.
     */
    public static long deriveKey(PKCS11 p11, long hSession, CK_MECHANISM mechanism, long hBaseKey, CK_ATTRIBUTE[] newObjTpl) throws PKCS11Exception {
        return p11.C_DeriveKey(hSession, mechanism, hBaseKey, newObjTpl);
    }

    /**
     * Wraps a cryptographic key using another key and a specified wrapping
     * mechanism.
     *
     * This method encrypts (wraps) the specified key using a wrapping key and a
     * cryptographic mechanism (e.g., RSA, AES Key Wrap). The resulting wrapped
     * key can be securely transferred or stored.
     *
     * @param p11 PKCS#11 wrapper instance used to interact with the token.
     * @param hSession Handle to the open PKCS#11 session associated with the
     * token.
     * @param mechanism The mechanism used for wrapping (e.g., CKM_AES_KEY_WRAP,
     * CKM_RSA_PKCS).
     * @param wrappingKeyTemplate Template containing attributes to identify the
     * wrapping key.
     * @param keyToWrapTemplate Template containing attributes to identify the
     * key to be wrapped.
     * @return The wrapped key as a byte array.
     * @throws Exception If an error occurs during the key wrapping process.
     */
    public static byte[] wrapKey(PKCS11 p11, long hSession, CK_MECHANISM mechanism, CK_ATTRIBUTE[] wrappingKeyTemplate, CK_ATTRIBUTE[] keyToWrapTemplate) throws Exception {
        long hWrappingKey = find(p11, hSession, wrappingKeyTemplate);  // Locate the wrapping key.
        long hKeyToWrap = find(p11, hSession, keyToWrapTemplate);  // Locate the key to be wrapped.
        return p11.C_WrapKey(hSession, mechanism, hWrappingKey, hKeyToWrap);
    }

    /**
     * Unwraps an encrypted key using another key and a specified unwrapping
     * mechanism.
     *
     * This method decrypts (unwraps) a previously wrapped key using an
     * unwrapping key and a cryptographic mechanism (e.g., CKM_AES_KEY_WRAP,
     * CKM_RSA_PKCS). The resulting key is stored on the token with the
     * attributes defined in the provided template.
     *
     * @param p11 PKCS#11 wrapper instance used to interact with the token.
     * @param hSession Handle to the open PKCS#11 session associated with the
     * token.
     * @param mechanism The mechanism used for unwrapping (e.g.,
     * CKM_AES_KEY_WRAP, CKM_RSA_PKCS).
     * @param unWrappingKeyTemplate Template containing attributes to identify
     * the unwrapping key.
     * @param wrappedKey The wrapped (encrypted) key in a byte array.
     * @param newKeyTemplate The template defining attributes of the unwrapped
     * key.
     * @return The handle of the unwrapped key.
     * @throws Exception If an error occurs during the key unwrapping process.
     */
    public static long unWrapKey(PKCS11 p11, long hSession, CK_MECHANISM mechanism, CK_ATTRIBUTE[] unWrappingKeyTemplate, byte[] wrappedKey, CK_ATTRIBUTE[] newKeyTemplate) throws Exception {
        long hUnWrappingKey = find(p11, hSession, unWrappingKeyTemplate);  // Locate the unwrapping key.
        return p11.C_UnwrapKey(hSession, mechanism, hUnWrappingKey, wrappedKey, newKeyTemplate);
    }
}
