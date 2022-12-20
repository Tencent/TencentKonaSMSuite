package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.TestUtils;
import com.tencent.kona.crypto.spec.SM2KeyAgreementParamSpec;
import com.tencent.kona.crypto.spec.SM2ParameterSpec;
import com.tencent.kona.crypto.spec.SM2PrivateKeySpec;
import com.tencent.kona.crypto.spec.SM2PublicKeySpec;
import com.tencent.kona.crypto.spec.SM2SignatureParameterSpec;
import com.tencent.kona.crypto.util.Constants;
import com.tencent.kona.sun.security.ec.ECOperator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.crypto.TestUtils.EMPTY;
import static com.tencent.kona.crypto.TestUtils.PROVIDER;
import static com.tencent.kona.crypto.util.Constants.SM2_PRIKEY_LEN;
import static com.tencent.kona.crypto.util.Constants.SM2_PUBKEY_LEN;

/**
 * The test for SM2 cipher, signature and key agreement.
 */
public class SM2Test {

    private final static String PUB_KEY
            = "041D9E2952A06C913BAD21CCC358905ADB3A8097DB6F2F87EB5F393284EC2B7208C30B4D9834D0120216D6F1A73164FDA11A87B0A053F63D992BFB0E4FC1C5D9AD";
    private final static String PRI_KEY
            = "3B03B35C2F26DBC56F6D33677F1B28AF15E45FE9B594A6426BDCAD4A69FF976B";
    private final static byte[] ID = toBytes("01234567");

    private final static byte[] MESSAGE = toBytes(
            "4003607F75BEEE81A027BB6D265BA1499E71D5D7CD8846396E119161A57E01EEB91BF8C9FE");

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
    }

    @Test
    public void testKeyPairGen() throws Exception {
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("SM2", PROVIDER);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey priKey = (ECPrivateKey) keyPair.getPrivate();
        Assertions.assertEquals(SM2_PUBKEY_LEN, pubKey.getEncoded().length);
        Assertions.assertEquals(SM2_PRIKEY_LEN, priKey.getEncoded().length);
    }

    @Test
    public void testKeyPairGenSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testKeyPairGen();
            return null;
        });
    }

    @Test
    public void testKeyPairParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testKeyPairGen();
            return null;
        });
    }

    @Test
    public void testPubKeyPointOnCurve() throws Exception {
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("SM2", PROVIDER);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        ECPoint pubKeyPoint = pubKey.getW();
        boolean onCurve = checkPointOnCurve(pubKeyPoint);
        Assertions.assertTrue(onCurve);
    }

    private static boolean checkPointOnCurve(ECPoint pubKeyPoint) {
        BigInteger x = pubKeyPoint.getAffineX();
        BigInteger y = pubKeyPoint.getAffineY();
        EllipticCurve curve =  SM2ParameterSpec.instance().getCurve();
        ECFieldFp field = (ECFieldFp) curve.getField();
        BigInteger a = curve.getA();
        BigInteger b = curve.getB();
        BigInteger rhs = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(field.getP());
        BigInteger lhs = y.multiply(y).mod(field.getP());

        return lhs.equals(rhs);
    }

    @Test
    public void testSignatureParameterSpec() throws Exception {
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("SM2", PROVIDER);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        SM2SignatureParameterSpec paramSpec
                = new SM2SignatureParameterSpec((ECPublicKey) keyPair.getPublic());
        Assertions.assertArrayEquals(Constants.defaultId(),
                                 paramSpec.getId());

        TestUtils.checkIAE(()-> new SM2SignatureParameterSpec(
                TestUtils.dataKB(8), (ECPublicKey) keyPair.getPublic()));
        TestUtils.checkNPE(()-> new SM2SignatureParameterSpec(
                TestUtils.dataKB(1), null));
    }

    @Test
    public void testCipher() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec pubKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, priKey);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testCipherOnKeyRange() throws Exception {
        // privateKey = order - 2
        testCipherOnKeyRange(2);

        // privateKey = order - 1
        testCipherOnKeyRange(1);

        // privateKey = order
        TestUtils.checkThrowable(IllegalArgumentException.class,
                () -> testCipherOnKeyRange(0));

        // privateKey = order + 1
        TestUtils.checkThrowable(IllegalArgumentException.class,
                () -> testCipherOnKeyRange(-1));
    }

    private void testCipherOnKeyRange(int orderOffset) throws Exception {
        BigInteger privateKeyS = ECOperator.SM2.getOrder().subtract(
                BigInteger.valueOf(orderOffset));
        ECPrivateKey privateKey = new SM2PrivateKey(privateKeyS);

        ECPoint publicPoint = ECOperator.SM2.multiply(privateKeyS);
        ECPublicKey publicKey = new SM2PublicKey(publicPoint);

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testCipherTwice() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec pubKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        cipher.doFinal(MESSAGE);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, priKey);
        cipher.doFinal(ciphertext);
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testCipherParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testCipher();
            return null;
        });
    }

    @Test
    public void testCipherSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testCipher();
            return null;
        });
    }

    @Test
    public void testCipherFailed() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec pubKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("SM2", PROVIDER);
        KeyPair altKeyPair = keyPairGenerator.generateKeyPair();

        cipher.init(Cipher.DECRYPT_MODE, altKeyPair.getPrivate());
        TestUtils.checkThrowable(
                BadPaddingException.class, () -> cipher.doFinal(ciphertext));
    }

    @Test
    public void testCipherEmpty() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec pubKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        TestUtils.checkThrowable(BadPaddingException.class,
                () -> cipher.doFinal(EMPTY));

        cipher.init(Cipher.DECRYPT_MODE, priKey);
        TestUtils.checkThrowable(BadPaddingException.class,
                () -> cipher.doFinal(EMPTY));
    }

    @Test
    public void testCipherWithKeyGen() throws Exception {
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("SM2", PROVIDER);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);

        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] cleartext = cipher.doFinal(ciphertext);

        Assertions.assertArrayEquals(MESSAGE, cleartext);
    }

    @Test
    public void testCipherWithKeyGenParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testCipherWithKeyGen();
            return null;
        });
    }

    @Test
    public void testCipherWithKeyGenSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testCipherWithKeyGen();
            return null;
        });
    }

    @Test
    public void testSignature() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec publicKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        SM2SignatureParameterSpec paramSpec
                = new SM2SignatureParameterSpec(ID, (ECPublicKey) pubKey);

        Signature signer = Signature.getInstance("SM2", PROVIDER);
        signer.setParameter(paramSpec);
        signer.initSign(priKey);

        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SM2", PROVIDER);
        verifier.setParameter(paramSpec);
        verifier.initVerify(pubKey);
        verifier.update(MESSAGE);
        boolean verified = verifier.verify(signature);

        Assertions.assertTrue(verified);
    }

    @Test
    public void testSignatureOnKeyRange() throws Exception {
        // privateKey = order - 2
        testSignatureOnKeyRange(2);

        // privateKey = order - 1
        // Per the specification, the private key cannot be (order - 1)
        // on generating the signature.
        TestUtils.checkThrowable(InvalidKeyException.class,
                () -> testSignatureOnKeyRange(1));

        // privateKey = order
        TestUtils.checkThrowable(InvalidKeyException.class,
                () -> testSignatureOnKeyRange(0));

        // privateKey = order + 1
        TestUtils.checkThrowable(InvalidKeyException.class,
                () -> testSignatureOnKeyRange(-1));
    }

    // orderOffset: the relative offset to the order
    private void testSignatureOnKeyRange(int orderOffset)
            throws Exception {
        BigInteger privateKeyS = ECOperator.SM2.getOrder().subtract(
                BigInteger.valueOf(orderOffset));
        ECPrivateKey privateKey = new SM2PrivateKey(privateKeyS);

        ECPoint publicPoint = ECOperator.SM2.multiply(privateKeyS);
        ECPublicKey publicKey = new SM2PublicKey(publicPoint);

        Signature signer = Signature.getInstance("SM2", PROVIDER);
        signer.initSign(privateKey);
        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SM2", PROVIDER);
        verifier.initVerify(publicKey);
        verifier.update(MESSAGE);
        boolean verified = verifier.verify(signature);

        Assertions.assertTrue(verified);
    }

    @Test
    public void testSignatureEmpty() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec publicKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        SM2SignatureParameterSpec paramSpec
                = new SM2SignatureParameterSpec(ID, (ECPublicKey) pubKey);

        Signature signer = Signature.getInstance("SM2", PROVIDER);
        signer.setParameter(paramSpec);
        signer.initSign(priKey);

        signer.update(EMPTY);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SM2", PROVIDER);
        verifier.setParameter(paramSpec);
        verifier.initVerify(pubKey);
        verifier.update(EMPTY);
        boolean verified = verifier.verify(signature);

        Assertions.assertTrue(verified);
    }

    @Test
    public void testSignatureWithoutParamSpec() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec publicKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        Signature signer = Signature.getInstance("SM2", PROVIDER);
        signer.initSign(priKey);

        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SM2", PROVIDER);
        verifier.initVerify(pubKey);
        verifier.update(MESSAGE);
        boolean verified = verifier.verify(signature);

        Assertions.assertTrue(verified);
    }

    @Test
    public void testSignatureTwice() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec publicKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        SM2SignatureParameterSpec paramSpec
                = new SM2SignatureParameterSpec(ID, (ECPublicKey) pubKey);

        Signature signer = Signature.getInstance("SM2", PROVIDER);
        signer.setParameter(paramSpec);
        signer.initSign(priKey);

        signer.update(MESSAGE, 0, MESSAGE.length / 2);
        signer.update(MESSAGE, MESSAGE.length / 2,
                MESSAGE.length - MESSAGE.length / 2);
        byte[] signature = signer.sign();

        signer.update(MESSAGE);
        signature = signer.sign();

        Signature verifier = Signature.getInstance("SM2", PROVIDER);
        verifier.setParameter(paramSpec);
        verifier.initVerify(pubKey);

        verifier.update(MESSAGE);
        Assertions.assertTrue(verifier.verify(signature));

        verifier.update(MESSAGE, 0, MESSAGE.length / 2);
        verifier.update(MESSAGE, MESSAGE.length / 2,
                MESSAGE.length - MESSAGE.length / 2);
        Assertions.assertTrue(verifier.verify(signature));
    }

    @Test
    public void testSignatureParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testSignature();
            return null;
        });
    }

    @Test
    public void testSignatureSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testSignature();
            return null;
        });
    }

    @Test
    public void testSignatureWithKeyGen() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SM2");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        SM2SignatureParameterSpec paramSpec
                = new SM2SignatureParameterSpec(
                ID, (ECPublicKey) keyPair.getPublic());

        Signature signer = Signature.getInstance("SM2", PROVIDER);
        signer.setParameter(paramSpec);
        signer.initSign(keyPair.getPrivate());

        signer.update(MESSAGE);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SM2", PROVIDER);
        verifier.setParameter(paramSpec);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(MESSAGE);
        boolean verified = verifier.verify(signature);

        Assertions.assertTrue(verified);
    }

    @Test
    public void testSignatureWithKeyGenParallelly() throws Exception {
        TestUtils.repeatTaskParallelly(() -> {
            testSignatureWithKeyGen();
            return null;
        });
    }

    @Test
    public void testSignatureWithKeyGenSerially() throws Exception {
        TestUtils.repeatTaskSerially(() -> {
            testSignatureWithKeyGen();
            return null;
        });
    }

    @Test
    public void testKeyAgreementInit() throws Exception {
        ECPrivateKey priKey = new SM2PrivateKey(toBytes(PRI_KEY));
        ECPublicKey pubKey = new SM2PublicKey(toBytes(PUB_KEY));

        SM2KeyAgreementParamSpec paramSpec = new SM2KeyAgreementParamSpec(
                ID,
                priKey,
                pubKey,
                ID,
                pubKey,
                true,
                32);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2", PROVIDER);

        Assertions.assertThrows(
                UnsupportedOperationException.class,
                () -> keyAgreement.init(priKey));
        keyAgreement.init(priKey, paramSpec);
    }

    @Test
    public void testKeyAgreementDoPhase() throws Exception {
        ECPrivateKey priKey = new SM2PrivateKey(toBytes(PRI_KEY));
        ECPublicKey pubKey = new SM2PublicKey(toBytes(PUB_KEY));

        SM2KeyAgreementParamSpec paramSpec = new SM2KeyAgreementParamSpec(
                ID,
                priKey,
                pubKey,
                ID,
                pubKey,
                true,
                32);

        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2", PROVIDER);

        Assertions.assertThrows(
                IllegalStateException.class,
                () -> keyAgreement.doPhase(priKey, true));

        keyAgreement.init(priKey, paramSpec);

        Assertions.assertThrows(
                InvalidKeyException.class,
                () -> keyAgreement.doPhase(priKey, true));

        Assertions.assertThrows(
                IllegalStateException.class,
                () -> keyAgreement.doPhase(pubKey, false));

        keyAgreement.doPhase(pubKey, true);

        Assertions.assertThrows(
                IllegalStateException.class,
                () -> keyAgreement.doPhase(pubKey, true));
    }

    @Test
    public void testSM2KeyAgreement() throws Exception {
        testSM2KeyAgreementKeySize(16, toBytes("6C89347354DE2484C60B4AB1FDE4C6E5"));
    }

    @Test
    public void testSM2KeyAgreementKeySize() throws Exception {
        testSM2KeyAgreementKeySize(7);
        testSM2KeyAgreementKeySize(15);
        testSM2KeyAgreementKeySize(17);
        testSM2KeyAgreementKeySize(32);
        testSM2KeyAgreementKeySize(33);
        testSM2KeyAgreementKeySize(63);
        testSM2KeyAgreementKeySize(64);
        testSM2KeyAgreementKeySize(65);
    }

    private void testSM2KeyAgreementKeySize(int keySize)
            throws Exception {
        testSM2KeyAgreementKeySize(keySize, null);
    }

    private void testSM2KeyAgreementKeySize(int keySize, byte[] expectedSharedKey)
            throws Exception {
        String idHex = "31323334353637383132333435363738";
        String priKeyHex = "81EB26E941BB5AF16DF116495F90695272AE2CD63D6C4AE1678418BE48230029";
        String pubKeyHex = "04160E12897DF4EDB61DD812FEB96748FBD3CCF4FFE26AA6F6DB9540AF49C942324A7DAD08BB9A459531694BEB20AA489D6649975E1BFCF8C4741B78B4B223007F";
        String tmpPriKeyHex = "D4DE15474DB74D06491C440D305E012400990F3E390C7E87153C12DB2EA60BB3";
        String tmpPubKeyHex = "0464CED1BDBC99D590049B434D0FD73428CF608A5DB8FE5CE07F15026940BAE40E376629C7AB21E7DB260922499DDB118F07CE8EAAE3E7720AFEF6A5CC062070C0";

        String peerIdHex = "31323334353637383132333435363738";
        String peerPriKeyHex = "785129917D45A9EA5437A59356B82338EAADDA6CEB199088F14AE10DEFA229B5";
        String peerPubKeyHex = "046AE848C57C53C7B1B5FA99EB2286AF078BA64C64591B8B566F7357D576F16DFBEE489D771621A27B36C5C7992062E9CD09A9264386F3FBEA54DFF69305621C4D";
        String peerTmpPriKeyHex = "7E07124814B309489125EAED101113164EBF0F3458C5BD88335C1F9D596243D6";
        String peerTmpPubKeyHex = "04ACC27688A6F7B706098BC91FF3AD1BFF7DC2802CDB14CCCCDB0A90471F9BD7072FEDAC0494B2FFC4D6853876C79B8F301C6573AD0AA50F39FC87181E1A1B46FE";

        // Generate shared secret by the local endpoint
        SM2KeyAgreementParamSpec paramSpec = new SM2KeyAgreementParamSpec(
                toBytes(idHex),
                new SM2PrivateKey(toBytes(priKeyHex)),
                new SM2PublicKey(toBytes(pubKeyHex)),
                toBytes(peerIdHex),
                new SM2PublicKey(toBytes(peerPubKeyHex)),
                true,
                keySize);
        KeyAgreement keyAgreement = KeyAgreement.getInstance("SM2", PROVIDER);
        keyAgreement.init(new SM2PrivateKey(toBytes(tmpPriKeyHex)), paramSpec);
        keyAgreement.doPhase(new SM2PublicKey(toBytes(peerTmpPubKeyHex)), true);
        SecretKey sharedKey = keyAgreement.generateSecret("SM2SharedSecret");

        Assertions.assertEquals(keySize, sharedKey.getEncoded().length);
        if (expectedSharedKey != null) {
            Assertions.assertArrayEquals(expectedSharedKey, sharedKey.getEncoded());
        }

        // Generate shared secret by the remote endpoint
        SM2KeyAgreementParamSpec peerParamSpec = new SM2KeyAgreementParamSpec(
                toBytes(peerIdHex),
                new SM2PrivateKey(toBytes(peerPriKeyHex)),
                new SM2PublicKey(toBytes(peerPubKeyHex)),
                toBytes(idHex),
                new SM2PublicKey(toBytes(pubKeyHex)),
                false,
                keySize);
        KeyAgreement peerKeyAgreement = KeyAgreement.getInstance("SM2", PROVIDER);
        peerKeyAgreement.init(new SM2PrivateKey(toBytes(peerTmpPriKeyHex)), peerParamSpec);
        peerKeyAgreement.doPhase(new SM2PublicKey(toBytes(tmpPubKeyHex)), true);
        SecretKey peerSharedKey = peerKeyAgreement.generateSecret("SM2SharedSecret");

        Assertions.assertArrayEquals(sharedKey.getEncoded(), peerSharedKey.getEncoded());
    }
}
