package civ.kem.algo;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;

public class Main {

    public static void main(String[] args) {
        String text = "Hello PKCS#11 :)";
        System.out.println(text);

        try {
            PKCS11 p11 = Utils.setMonoThreadedCryptokiFunctions();
            long slotId = 1;
            long flags = PKCS11Constants.CKF_SERIAL_SESSION;
            long hSession = Utils.openSession(p11, slotId, flags);

            // Symmetric functions
            System.out.println("TEST SYMMETRIC FUNCTIONS");
            encryptDecrypt(p11, hSession, new CK_MECHANISM(PKCS11Constants.CKM_AES_ECB), text.getBytes());
            sha2(p11, hSession, new CK_MECHANISM(PKCS11Constants.CKM_SHA256), 32, text.getBytes());

            // Random numers
             System.out.println("\n\nTEST RANDOM NUMBER GENERATION");
            byte[] randomData = new byte[20];
            Random.generateRandomData(p11, hSession, randomData, hSession);
            System.out.println("Random value: " + HexFormat.of().formatHex(randomData));

            String seed = "deadbeefdeadbeef";
            Utils.println("Seed value: " + seed);
            byte[] bSeed = HexFormat.of().parseHex(seed);
            Random.seedRandom(p11, hSession, bSeed);
            Utils.println("Modified value of the seed : " + HexFormat.of().formatHex(bSeed));

            Utils.closeSession(p11, hSession);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }

    public static void encryptDecrypt(PKCS11 p11, long hSession, CK_MECHANISM mechanism, byte[] plaintext) throws Exception {
        CK_ATTRIBUTE[] templateSessionKey = {
            new CK_ATTRIBUTE(PKCS11Constants.CKA_TOKEN, PKCS11Constants.FALSE),
            new CK_ATTRIBUTE(PKCS11Constants.CKA_SENSITIVE, PKCS11Constants.TRUE),
            new CK_ATTRIBUTE(PKCS11Constants.CKA_ENCRYPT, PKCS11Constants.TRUE),
            new CK_ATTRIBUTE(PKCS11Constants.CKA_DECRYPT, PKCS11Constants.TRUE),
            new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_SECRET_KEY),
            new CK_ATTRIBUTE(PKCS11Constants.CKA_KEY_TYPE, PKCS11Constants.CKK_AES),
            new CK_ATTRIBUTE(PKCS11Constants.CKA_VALUE_LEN, 16),};

        long hSessionKey = p11.C_GenerateKey(hSession, new CK_MECHANISM(PKCS11Constants.CKM_AES_KEY_GEN), templateSessionKey);

        // Encrypt plaintext
        byte[] ciphertext = new byte[16];
        Symmetric.encrypt(p11, hSession, mechanism, hSessionKey, plaintext, ciphertext);

        // Decrypt encrypted text
        byte[] decrypted = new byte[16];
        Symmetric.decrypt(p11, hSession, mechanism, hSessionKey, ciphertext, decrypted);

        System.out.println("Plaintext          : " + new String(plaintext, StandardCharsets.UTF_8));
        System.out.println("Ciphertext         : " + HexFormat.of().formatHex(ciphertext));
        System.out.println("Decrypt ciphertext : " + new String(decrypted, StandardCharsets.UTF_8));
    }

    public static void sha2(PKCS11 p11, long hSession, CK_MECHANISM mechanism, int digestLen, byte[] blob) throws Exception {
        byte[] hash = Symmetric.hashData(p11, hSession, mechanism, digestLen, blob);
        System.out.println("Digest : " + HexFormat.of().formatHex(hash));
    }

}
