package civ.kem.algo.ptk;

import java.io.File;
import java.nio.charset.StandardCharsets;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import sun.security.pkcs11.wrapper.PKCS11Exception;

/**
 * This class demonstrates how to use BIP32 Usage : java ...BIP32KeyDerivation
 * -keyName &lt;keyname&gt; -create
 * <li><i>keyname</i> name (label) of the key to delete
 */
public class BIP32KeyDerivation {

    /**
     * easy access to System.out.println
     */
    static public void println(String s) {
        System.out.println(s);
    }


    /**
     * display runtime usage of the class
     */
    public static void usage() {
        println("java ...BIP32KeyDerivation -keyName <keyname> -create");
        println("");
        println("-keyName <keyname> \tname (label) of the generated key");
        println("-create \t\tcreate a new key");
        println("");
        System.exit(1);
    }

     /**
     * Set PKCS#11 library path.
     *
     * @return The path of the cryptoki library.
     */
    public static String setLibrary(String libPath) throws Exception {
        String library;

        if (new File(libPath).exists()) {
            library = libPath;
        } else {
            throw new Exception("Library not found on the plateform.");
        }
        return library;
    }

    /**
     * main execution method
     */
    public static void main(String[] args) {
        long session;
        long slotId = 0;
        boolean create = false;
        String keyName = "";

        /*
         * process command line arguments
         */
        if (args.length == 0) {
            usage();
        }

        for (int i = 0; i < args.length; ++i) {
            if (args[i].equalsIgnoreCase("-keyName")) {
                if (++i >= args.length) {
                    usage();
                }

                keyName = args[i];
            } else if (args[i].equalsIgnoreCase("-create")) {
                create = true;
            } else {
                usage();
            }
        }

        try {
            /*
             * Initialize Cprov so that the library takes care
             * of multithread locking
             */
            String ptk7Windows = "C:\\Program Files\\Safenet\\ProtectToolkit 7\\C SDK\\bin\\sw\\p11.dll";

            String library = setLibrary(ptk7Windows);
            PKCS11 p11 = PKCS11.getInstance(library, "C_GetFunctionList", null, false);

            /*
             * Open a session
             */
            session = p11.C_OpenSession(slotId, PKCS11Constants.CKF_RW_SESSION, null, null);

            long pKey;
            if (create) {
                /* Generate key pair and exit. */
                println("Generating Keys \"" + keyName + "\" in slot 0 and 2\n");
                pKey = generateSecretKey(p11, session, keyName);
                println("Done\n");
            } else {
                pKey = findSecretKey(p11, session, keyName);
            }

            //Now do ECDH Key derive
            println("Generating derived key : ");
            byte[] array = runDerivationTests(p11, session, pKey);
            println(bytesToHex(array));
            println("\n");

            /*
             * Close the session.
             *
             * Note that we are not using p11.
             */
            p11.C_CloseSession(session);

            /*
             * All done with p11
             *
             * Note that we are not using p11.
             */
            p11.C_Finalize(null);

        } catch (PKCS11Exception ex) {
            /*
             * A p11 related exception was thrown
             */
            ex.printStackTrace();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    /**
     * Generate a symetric key.
     *
     * @param session handle to an open session
     *
     * @param label name (label) to give the generated key
     *
     */
    public static long generateSecretKey(PKCS11 p11, long session,
            String label) throws Exception {
        byte[] testvector = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        long pKey;
        CK_ATTRIBUTE[] attr
                = {
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, label.getBytes(StandardCharsets.US_ASCII)),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_VALUE, testvector),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_SECRET_KEY),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_GENERIC_SECRET),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN, PKCS11Constants.TRUE),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_SENSITIVE, PKCS11Constants.FALSE),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_DERIVE, PKCS11Constants.TRUE)
                };

        pKey = p11.C_CreateObject(session, attr);
        return pKey;
    }

    /**
     * Generate a BIP32 master key pair
     *
     * @param hPrivateSession handle to an open session
     *
     * @param hSeed OBJECT_HANDLE linked to a symetric key
     *
     */
    public static CK_BIP32_MASTER_DERIVE_PARAMS generateMasterKeyPair(PKCS11 p11, long hPrivateSession, long hSeed) throws PKCS11Exception {
        String pubLabel = "Master BIP32 Key(Public)";
        String priLabel = "Master BIP32 Key(Private)";

        CK_ATTRIBUTE[] pubKeyAttr
                = {
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, pubLabel.getBytes(StandardCharsets.US_ASCII)),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN, PKCS11Constants.TRUE),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_SENSITIVE, PKCS11Constants.FALSE),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_DERIVE, PKCS11Constants.TRUE),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_EXTRACTABLE, PKCS11Constants.TRUE),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PTK_Constants.CKK_BIP32)
                };

        CK_ATTRIBUTE[] priKeyAttr
                = {
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, priLabel.getBytes(StandardCharsets.US_ASCII)),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN, PKCS11Constants.TRUE),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_SENSITIVE, PKCS11Constants.FALSE),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_DERIVE, PKCS11Constants.TRUE),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_EXTRACTABLE, PKCS11Constants.TRUE),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PTK_Constants.CKK_BIP32)
                };

        CK_BIP32_MASTER_DERIVE_PARAMS mechParams
                = new CK_BIP32_MASTER_DERIVE_PARAMS(pubKeyAttr, priKeyAttr);

        CK_MECHANISM mech = new PTK_CK_MECHANISM(PTK_Constants.CKM_BIP32_MASTER_DERIVE, mechParams);

     p11.C_DeriveKey(hPrivateSession, mech, hSeed, priKeyAttr);

        return mechParams;
    }

    /**
     * Generate a BIP32 child key pair
     *
     * @param hPrivateSession handle to an open session
     *
     * @param hParent OBJECT_HANDLE linked to the master private key
     *
     */
    public static CK_BIP32_CHILD_DERIVE_PARAMS generateChildKeyPair(PKCS11 p11, long hPrivateSession,
            long hParent) throws PKCS11Exception {
        String pubLabel = "Child BIP32 Key(Public)";
        String priLabel = "Child BIP32 Key(Private)";

        CK_ATTRIBUTE[] pubKeyAttr
                = {
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, pubLabel.getBytes(StandardCharsets.US_ASCII)),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN, PKCS11Constants.TRUE),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_SENSITIVE, PKCS11Constants.FALSE),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_DERIVE, PKCS11Constants.TRUE),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_EXTRACTABLE, PKCS11Constants.TRUE),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PTK_Constants.CKK_BIP32)
                };

        CK_ATTRIBUTE[] priKeyAttr
                = {
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, priLabel.getBytes(StandardCharsets.US_ASCII)),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN, PKCS11Constants.TRUE),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_SENSITIVE, PKCS11Constants.FALSE),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_DERIVE, PKCS11Constants.TRUE),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_EXTRACTABLE, PKCS11Constants.TRUE),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PTK_Constants.CKK_BIP32)
                };

        long[] path = {0L, 1L, 4L};

        CK_BIP32_CHILD_DERIVE_PARAMS mechParams
                = new CK_BIP32_CHILD_DERIVE_PARAMS(pubKeyAttr, priKeyAttr, path);

        CK_MECHANISM mech = new PTK_CK_MECHANISM(PTK_Constants.CKM_BIP32_CHILD_DERIVE, mechParams);

   p11.C_DeriveKey(hPrivateSession, mech, hParent, priKeyAttr);

        return mechParams;

    }

    public static long findSecretKey(PKCS11 p11, long hSession,
            String label) throws PKCS11Exception {
        /* array of one object handles */
        long[] hObjects;



        CK_ATTRIBUTE[] findAttr
                = {
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_LABEL, label.getBytes(StandardCharsets.US_ASCII)),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_SECRET_KEY),
                    new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_GENERIC_SECRET)
                };

        p11.C_FindObjectsInit(hSession, findAttr);

        hObjects = p11.C_FindObjects(hSession, PTK_Constants.maxObjects);

        p11.C_FindObjectsFinal(hSession);

        if (hObjects.length == 1) {
            /* return the handle of the located object */
            return hObjects[0];
        } else {
            /* return an object handle which is invalid */
            println("Key not found");
            return 0;
        }
    }

    public static byte[] runDerivationTests(PKCS11 p11, long hPrivateSession,
            long hPrivate) throws Exception {

        CK_BIP32_MASTER_DERIVE_PARAMS master = generateMasterKeyPair(p11, hPrivateSession, hPrivate);
        long masterPri = master.hPrivateKey;

        CK_BIP32_CHILD_DERIVE_PARAMS bip32Childparams = generateChildKeyPair(p11, hPrivateSession, masterPri);
        long childPub = bip32Childparams.hPublicKey;

        byte[] derivedKey = new byte[33];

        CK_ATTRIBUTE[] getDerivedValue = {
            new CK_ATTRIBUTE(PKCS11Constants.CKA_VALUE, derivedKey)
        };
        p11.C_GetAttributeValue(hPrivateSession, childPub, getDerivedValue);

        return derivedKey;
    }

    public static String bytesToHex(byte[] bytes) {
        final char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

}
