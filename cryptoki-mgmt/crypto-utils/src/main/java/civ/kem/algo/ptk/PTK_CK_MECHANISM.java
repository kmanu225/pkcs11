package civ.kem.algo.ptk;
import sun.security.pkcs11.wrapper.CK_MECHANISM;



public class PTK_CK_MECHANISM extends CK_MECHANISM {
    
    public PTK_CK_MECHANISM(long mechanism, CK_BIP32_MASTER_DERIVE_PARAMS params) {
        super(mechanism);
        this.pParameter = params;
    }

    public PTK_CK_MECHANISM(long mechanism, CK_BIP32_CHILD_DERIVE_PARAMS params) {
        super(mechanism);
        this.pParameter = params;
    }
}