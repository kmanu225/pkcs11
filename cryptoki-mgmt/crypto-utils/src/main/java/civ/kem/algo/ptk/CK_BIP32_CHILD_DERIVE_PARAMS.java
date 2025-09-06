package civ.kem.algo.ptk;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;

public class CK_BIP32_CHILD_DERIVE_PARAMS {
   public CK_ATTRIBUTE[] publicKeyTemplate;
   public long publicKeyAttributeCount;
   public CK_ATTRIBUTE[] privateKeyTemplate;
   public long privateKeyAttributeCount;
   public long[] path;
   public long pathLen;
   public long hPublicKey ;
   public long hPrivateKey;
   public long pathErrorIndex;

   public CK_BIP32_CHILD_DERIVE_PARAMS() {
   }

   public CK_BIP32_CHILD_DERIVE_PARAMS(CK_ATTRIBUTE[] var1, long var2, CK_ATTRIBUTE[] var4, long var5, long[] var7, long var8) {
      this.publicKeyTemplate = var1;
      this.publicKeyAttributeCount = var2;
      this.privateKeyTemplate = var4;
      this.privateKeyAttributeCount = var5;
      this.path = var7;
      this.pathLen = var8;
   }

   public CK_BIP32_CHILD_DERIVE_PARAMS(CK_ATTRIBUTE[] var1, CK_ATTRIBUTE[] var2, long[] var3) {
      this.publicKeyTemplate = var1;
      this.publicKeyAttributeCount = (long)var1.length;
      this.privateKeyTemplate = var2;
      this.privateKeyAttributeCount = (long)var1.length;
      this.path = var3;
      this.pathLen = (long)var3.length;
   }
}
