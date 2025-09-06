package civ.kem.algo.ptk;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;

public class CK_BIP32_MASTER_DERIVE_PARAMS {

    public CK_ATTRIBUTE[] publicKeyTemplate;
    public long publicKeyAttributeCount;
    public CK_ATTRIBUTE[] privateKeyTemplate;
    public long privateKeyAttributeCount;
    public long hPublicKey;
    public long hPrivateKey;

    public CK_BIP32_MASTER_DERIVE_PARAMS() {
    }

    public CK_BIP32_MASTER_DERIVE_PARAMS(CK_ATTRIBUTE[] var1, long var2, CK_ATTRIBUTE[] var4, long var5) {
        this.publicKeyTemplate = var1;
        this.publicKeyAttributeCount = var2;
        this.privateKeyTemplate = var4;
        this.privateKeyAttributeCount = var5;
    }

    public CK_BIP32_MASTER_DERIVE_PARAMS(CK_ATTRIBUTE[] var1, CK_ATTRIBUTE[] var2) {
        this.publicKeyTemplate = var1;
        this.publicKeyAttributeCount = (long) var1.length;
        this.privateKeyTemplate = var2;
        this.privateKeyAttributeCount = (long) var1.length;
    }
}
