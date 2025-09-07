package civ.kem.algo;

import java.util.HexFormat;

import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;

public class Random {

    /**
     * Encrypts data using AES or another symmetric encryption algorithm.
     *
     * @param p11 PKCS#11 wrapper instance.
     * @param hSession Handle to the active PKCS#11 session.
     * @param randomData The random data to be generated.
     * @param randomDataLength The length of the data to be generated.
     * @throws Exception If an error occurs during encryption.
     */
    public static void GenerateRandomData(PKCS11 p11, long hSession, byte[] randomData, long randomDataLength) throws Exception {
        p11.C_GenerateRandom(hSession, randomData);
        Utils.println("Random value: " + HexFormat.of().formatHex(randomData));

    }

    public static void main(String[] args) throws Exception {
        PKCS11 p11 = PKCS11.getInstance(Utils.loadLibrary(), "C_GetFunctionList", null, false);
        long hSession = Utils.OpenSession(p11, 2, PKCS11Constants.CKF_RW_SESSION | PKCS11Constants.CKF_SERIAL_SESSION);

        byte[] randomData = new byte[20];
        GenerateRandomData(p11, hSession, randomData, hSession);
        p11.C_CloseSession(hSession);
    }
}
