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
    public static void generateRandomData(PKCS11 p11, long hSession, byte[] randomData, long randomDataLength) throws Exception {
        p11.C_GenerateRandom(hSession, randomData);
    }

    /**
     * Seeds the random number generator of the PKCS#11 token.
     *
     * <p>
     * This method mixes the given seed value into the token's random number
     * generator, improving randomness. Some tokens may ignore the provided seed
     * if they use a true hardware random number generator (TRNG).</p>
     *
     * @param p11 The PKCS#11 Cryptoki library interface.
     * @param hSession Handle of the session in which to seed the RNG.
     * @param seed The seed value to inject into the random number generator.
     * @throws Exception if the seeding operation fails.
     */
    public static void seedRandom(PKCS11 p11, long hSession, byte[] seed) throws Exception {
        p11.C_SeedRandom(hSession, seed);
    }

    public static void main(String[] args) throws Exception {
        PKCS11 p11 = Utils.setMonoThreadedCryptokiFunctions();
        long hSession = Utils.openSession(p11, 2, PKCS11Constants.CKF_RW_SESSION | PKCS11Constants.CKF_SERIAL_SESSION);

        byte[] randomData = new byte[20];
        generateRandomData(p11, hSession, randomData, hSession);
        Utils.println("Random value: " + HexFormat.of().formatHex(randomData));

        String seed = "deadbeefdeadbeef";
        Utils.println("Seed value: " + seed);
        byte[] bSeed = HexFormat.of().parseHex(seed);
        seedRandom(p11, hSession, bSeed);
        Utils.println("Modified value of the seed : " + HexFormat.of().formatHex(bSeed));

        Utils.closeSession(p11, hSession);
    }
}
