package civ.kem.algo;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import sun.security.pkcs11.wrapper.CK_INFO;
import sun.security.pkcs11.wrapper.CK_SLOT_INFO;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.CK_VERSION;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKF_HW_SLOT;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKF_LOGIN_REQUIRED;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKF_REMOVABLE_DEVICE;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKF_RNG;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKF_TOKEN_INITIALIZED;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKF_TOKEN_PRESENT;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKF_USER_PIN_INITIALIZED;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKF_WRITE_PROTECTED;
import sun.security.pkcs11.wrapper.PKCS11Exception;

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
     * main execution method
     */
    public static void main(String[] args) throws Exception {
        long slotId = -1;
        boolean bGetGeneralInfo = false;
        boolean bGetSlotInfo = false;
        boolean bGetTokenInfo = false;

        /*
         * process command line arguments
         */
        for (int i = 0; i < args.length; ++i) {
            if (args[i].equalsIgnoreCase("-info")) {
                bGetGeneralInfo = true;
            } else if (args[i].equalsIgnoreCase("-slot")) {
                bGetSlotInfo = true;
            } else if (args[i].equalsIgnoreCase("-token")) {
                bGetTokenInfo = true;
            } else if (args[i].startsWith("-")) {
                usage();
            } else {
                /* assume that we have the slot id */

                try {
                    slotId = Integer.parseInt(args[i]);
                } catch (NumberFormatException ex) {
                    println("Invalid slotid :" + args[i]);
                    println("");
                    usage();
                }
            }
        }

        /* no work to do - error */
        if (!bGetGeneralInfo && !bGetSlotInfo && !bGetTokenInfo) {
            usage();
        }

        try {

            PKCS11 p11 = PKCS11.getInstance(loadLibrary(), "C_GetFunctionList", null, false);
            if (bGetGeneralInfo) {
                DisplayGeneralInformation(p11);
            }

            if (slotId == -1) {
                /* display information for all slots */
                long[] slotList;

                /* get the slot list */
                slotList = p11.C_GetSlotList(PKCS11Constants.TRUE);

                /* enumerate over the list, displaying the relevant inforamtion */
                for (int i = 0; i < slotList.length; ++i) {
                    if (bGetSlotInfo) {
                        DisplaySlotInformation(p11, slotList[i]);
                    }

                    if (bGetTokenInfo) {
                        DisplayTokenInformation(p11, slotList[i]);
                    }
                }
            } else {
                if (bGetSlotInfo) {
                    DisplaySlotInformation(p11, slotId);
                }

                if (bGetTokenInfo) {
                    DisplayTokenInformation(p11, slotId);
                }
            }

            p11.C_Finalize(null);

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

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
     * Opens a PKCS11 session with on a specific token slot.
     *
     * @param library Cryptoki library, dynamically loaded (.dll on Windows, .so
     * on Unix/Linux).
     * @param slotId The slot identification number.
     * @param flags Session information (eg. PKCS11Constants.CKF_SERIAL_SESSION |
     * PKCS11Constants.CKF_RW_SESSION).
     * @return a Properties object containing the loaded key-value pairs
     */
    public static long OpenSession(PKCS11 p11, long slotId, long flags) throws Exception {
        long hSession = p11.C_OpenSession(slotId, flags, null, null);
        return hSession;
    }

    /**
     * display runtime usage of the class
     */
    public static void usage() {
        println("java ...GetInfo (-info, -slot, -token) [<slotId>]");
        println("");
        println("-info          get the General information");
        println("-slot          get the Slot Information of the specified slot");
        println("-token         get the Token Information of the token in the specified slot");
        println("<slotId>       realted slot Id of the slot or token information to retrieve, default (all)");
        println("");

        System.exit(1);
    }

    /**
     * easy access to System.out.println
     */
    static public void println(String s) {
        System.out.println(s);
    }

    /**
     * Set PKCS#11 library path.
     *
     * @return The path of the cryptoki library.
     */
    public static String setupLibrary(String libPath) throws Exception {
        if (new File(libPath).exists()) {
            return libPath;
        } else {
            throw new Exception("Library not found on the plateform.");
        }
    }

    public static String loadLibrary() throws Exception {
        Properties props = Utils.loadProperties("library.properties");
        String library = props.getProperty("cryptoki.library");
        return setupLibrary(library);
    }

    static String versionString(CK_VERSION version) {
        if (version.minor < 10) {
            return version.major + ".0" + version.minor;
        } else {
            return version.major + "." + version.minor;
        }
    }

    static void DisplayGeneralInformation(PKCS11 p11) throws PKCS11Exception {

        println("General Info");

        CK_INFO info = p11.C_GetInfo();

        println("   Cryptoki Version   :" + versionString(info.cryptokiVersion));
        println("   Manufacturer       :" + new String(info.manufacturerID));
        println("   Library Description:" + new String(info.libraryDescription));
        println("   Library Version    :" + versionString(info.libraryVersion));
    }

    static void DisplaySlotInformation(PKCS11 p11, long slotId) throws PKCS11Exception {
        String flagString = "";

        println("Slot ID " + slotId);

        CK_SLOT_INFO info = p11.C_GetSlotInfo(slotId);

        println("   Description     :" + new String(info.slotDescription));
        println("   Manufacturer    :" + new String(info.manufacturerID));
        println("   Hardware Version:" + versionString(info.hardwareVersion));
        println("   Firmware Version:" + versionString(info.firmwareVersion));

        if ((info.flags & CKF_TOKEN_PRESENT) > 0) {
            flagString = "TokenPresent ";
        }

        if ((info.flags & CKF_REMOVABLE_DEVICE) > 0) {
            flagString += "RemovableDevice ";
        }

        if ((info.flags & CKF_HW_SLOT) > 0) {
            flagString += "Hardware";
        }

        if (flagString.length() == 0) {
            println("   Flags           :<none>");
        } else {
            println("   Flags           :" + flagString);
        }

        println("");
    }

    static void DisplayTokenInformation(PKCS11 p11, long slotId) throws Exception {
        String flagString = "";

        println("Token for Slot ID " + slotId);

        CK_TOKEN_INFO info = p11.C_GetTokenInfo(slotId);

        println("   Label           :" + new String(info.label));
        println("   Manufacturer    :" + new String(info.manufacturerID));
        println("   Model           :" + new String(info.model));
        println("   Serial Number   :" + new String(info.serialNumber));
        println("   Hardware Version:" + versionString(info.hardwareVersion));
        println("   Firmware Version:" + versionString(info.firmwareVersion));
        println("   Clock (GMT)     :" + new String(info.utcTime));
        println("   Sessions        :" + info.ulSessionCount + " out of " + info.ulMaxSessionCount);
        println("   RW Sessions     :" + info.ulRwSessionCount + " out of " + info.ulMaxRwSessionCount);
        println("   PIN Length      :" + info.ulMinPinLen + " to " + info.ulMaxPinLen);
        println("   Public Memory   :" + info.ulFreePublicMemory + " free, " + info.ulTotalPublicMemory + " total");
        println("   Private Memory  :" + info.ulFreePublicMemory + " free, " + info.ulTotalPublicMemory + " total");

        if ((info.flags & CKF_TOKEN_INITIALIZED) > 0) {
            flagString += "TokenInitialised ";
        }

        if ((info.flags & CKF_RNG) > 0) {
            flagString += "RNG ";
        }

        if ((info.flags & CKF_WRITE_PROTECTED) > 0) {
            flagString += "WriteProtected ";
        }

        if ((info.flags & CKF_LOGIN_REQUIRED) > 0) {
            flagString += "LoginRequired ";
        }

        if ((info.flags & CKF_USER_PIN_INITIALIZED) > 0) {
            flagString += "UserPINInitialised ";
        }

        /* and so on ... */
        if (flagString.length() == 0) {
            println("   Flags           :<none> (and maybe more)");
        } else {
            println("   Flags           :" + flagString + " (and maybe more)");
        }

        println("");
    }
}
