package com.tencent.kona.crypto;

import com.tencent.kona.crypto.provider.SM2PrivateKey;
import com.tencent.kona.crypto.provider.SM2PublicKey;
import com.tencent.kona.crypto.spec.SM2KeyAgreementParamSpec;
import com.tencent.kona.crypto.spec.SM2PrivateKeySpec;
import com.tencent.kona.crypto.spec.SM2PublicKeySpec;
import com.tencent.kona.crypto.spec.SM2SignatureParameterSpec;
import com.tencent.kona.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static com.tencent.kona.crypto.util.Constants.SM2_PRIKEY_LEN;
import static com.tencent.kona.crypto.util.Constants.SM2_PUBKEY_LEN;
import static com.tencent.kona.crypto.CryptoUtils.toBytes;
import static com.tencent.kona.TestUtils.PROVIDER;

/**
 * The test for SM2 cipher, signature and key agreement.
 */
public class SM2Test {

    private final static String PUB_KEY
            = "041D9E2952A06C913BAD21CCC358905ADB3A8097DB6F2F87EB5F393284EC2B7208C30B4D9834D0120216D6F1A73164FDA11A87B0A053F63D992BFB0E4FC1C5D9AD";
    private final static String PRI_KEY
            = "3B03B35C2F26DBC56F6D33677F1B28AF15E45FE9B594A6426BDCAD4A69FF976B";
    private final static byte[] USER_ID = toBytes("01234567");

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
    public void testSignature() throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("SM2", PROVIDER);
        SM2PublicKeySpec publicKeySpec = new SM2PublicKeySpec(toBytes(PUB_KEY));
        PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
        SM2PrivateKeySpec privateKeySpec = new SM2PrivateKeySpec(toBytes(PRI_KEY));
        PrivateKey priKey = keyFactory.generatePrivate(privateKeySpec);

        SM2SignatureParameterSpec paramSpec
                = new SM2SignatureParameterSpec(USER_ID, (ECPublicKey) pubKey);

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
    public void testKeyAgreement() throws Exception {
        testKeyAgreementKeySize(16, toBytes("6C89347354DE2484C60B4AB1FDE4C6E5"));
    }

    private void testKeyAgreementKeySize(int keySize, byte[] expectedSharedKey)
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
