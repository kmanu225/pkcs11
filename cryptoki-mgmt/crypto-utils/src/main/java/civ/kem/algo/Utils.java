package civ.kem.algo;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import sun.security.pkcs11.wrapper.PKCS11;

/**
 * The class demonstrates the retrieval of Slot and Token Information.
 * <p>
 * Usage : java ...GetInfo (-slot, -token) [&lt;slotId&gt;]
 * <li>-info retrieve the General information
 * <li>-slot retrieve the Slot Information of the specified slot
 * <li>-token retrieve the Token Information of the token in the specified slot
 * <li><i>slotId</i> the realted slot Id of the slot or token information to
 * retrieve, default (all)
 */
public class Utils {

    /**
     * Loads a properties file from the classpath (e.g. src/main/resources).
     *
     * @param fileName the name of the properties file (e.g. "app.properties")
     * @return a Properties object containing the loaded key-value pairs
     * @throws IOException if the file is not found or cannot be read
     */
    public static Properties loadProperties(String fileName) throws IOException {
        Properties props = new Properties();

        try (InputStream input = Utils.class.getClassLoader().getResourceAsStream(fileName)) {
            if (input == null) {
                throw new IOException("Properties file not found: " + fileName);
            }
            props.load(input);
        }

        return props;
    }

    /**
     * Obtains entry points of Cryptoki (PKCS#11) library functions in a
     * single-threaded (non-multithreaded) mode.
     *
     * <p>
     * This method loads the PKCS#11 library dynamically and retrieves its
     * function list, providing access to the standard Cryptoki API
     * functions.</p>
     *
     * @return A {@link PKCS11} instance with initialized function pointers.
     * @throws Exception if the library cannot be loaded or the function list
     * cannot be obtained.
     */
    public static PKCS11 setMonoThreadedCryptokiFunctions() throws Exception {
        return PKCS11.getInstance(Utils.loadLibrary(), "C_GetFunctionList", null, false);
    }

    /**
     * Opens a new PKCS#11 session on a specified token slot.
     *
     * @param p11 The PKCS#11 cryptoki library interface.
     * @param slotId Identifier of the token slot to open the session on.
     * @param flags Session flags (e.g., CKF_SERIAL_SESSION, CKF_RW_SESSION).
     * @return A session handle representing the opened session.
     * @throws Exception if the session cannot be opened.
     */
    public static long openSession(PKCS11 p11, long slotId, long flags) throws Exception {
        long hSession = p11.C_OpenSession(slotId, flags, null, null);
        return hSession;
    }

    /**
     * Closes an existing PKCS#11 session.
     *
     * @param p11 The PKCS#11 cryptoki library interface.
     * @param hSession Handle of the session to be closed.
     * @throws Exception if the session cannot be closed.
     */
    public static void closeSession(PKCS11 p11, long hSession) throws Exception {
        p11.C_CloseSession(hSession);
    }

    /**
     * Authenticates a user to a PKCS#11 token within an active session.
     *
     * @param p11 The PKCS#11 cryptoki library interface.
     * @param hSession Handle of the session in which to log in.
     * @param hUser User type (e.g., CKU_USER, CKU_SO).
     * @param pin User PIN as a character array.
     * @throws Exception if the login attempt fails.
     */
    public static void login(PKCS11 p11, long hSession, long hUser, char[] pin) throws Exception {
        p11.C_Login(hSession, hUser, pin);
    }

    /**
     * Logs out a user from a PKCS#11 token session.
     *
     * @param p11 The PKCS#11 cryptoki library interface.
     * @param hSession Handle of the session from which to log out.
     * @throws Exception if the logout attempt fails.
     */
    public static void logout(PKCS11 p11, long hSession) throws Exception {
        p11.C_Logout(hSession);
    }

    /**
     * easy access to System.out.println
     */
    static public void println(String s) {
        System.out.println(s);
    }

    /**
     * Validates and sets the PKCS#11 library path.
     *
     * <p>
     * This method checks whether the provided library path exists on the file
     * system before returning it. If the path does not exist, an exception is
     * thrown.</p>
     *
     * @param libPath The path to the PKCS#11 (Cryptoki) library (.dll on
     * Windows, .so on Unix/Linux).
     * @return The validated library path.
     * @throws Exception if the specified library path does not exist.
     */
    public static String setLibrary(String libPath) throws Exception {
        if (new File(libPath).exists()) {
            return libPath;
        } else {
            throw new Exception("Library not found on the platform.");
        }
    }

    /**
     * Loads the PKCS#11 library path from configuration properties.
     *
     * <p>
     * The method reads the {@code library.properties} file and retrieves the
     * value of the property {@code cryptoki.library}, which specifies the
     * PKCS#11 library path. It then validates the path using
     * {@link #setLibrary(String)}.</p>
     *
     * @return The validated path of the PKCS#11 (Cryptoki) library.
     * @throws Exception if the properties file cannot be loaded, the property
     * is missing, or the library path is invalid.
     */
    public static String loadLibrary() throws Exception {
        Properties props = Utils.loadProperties("library.properties");
        String library = props.getProperty("cryptoki.library");
        return setLibrary(library);
    }
}
