package com.tencent.kona.crypto.provider;

import com.tencent.kona.crypto.TestUtils;
import com.tencent.kona.crypto.spec.SM2SignatureParameterSpec;
import com.tencent.kona.crypto.util.Constants;
import com.tencent.kona.crypto.util.SM2Ciphertext;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import static com.tencent.kona.crypto.TestUtils.PROVIDER;

/**
 * The test for SM2 with BouncyCastle.
 */
public class SM2WithBCTest {

    private final static byte[] MESSAGE = TestUtils.data(1);

    @BeforeAll
    public static void setup() {
        TestUtils.addProviders();
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testSMCSCipherWithBCKeyPair() throws Exception {
        KeyPair keyPairBC = keyPairBC();
        KeyPair keyPair = toSMCSKeyPair(keyPairBC);
        testCipher(keyPair, keyPairBC);
    }

    @Test
    public void testBCCipherWithSMCSKeyPair() throws Exception {
        KeyPair keyPair = keyPair();
        KeyPair keyPairBC = toBCKeyPair(keyPair);
        testCipher(keyPair, keyPairBC);
    }

    public void testCipher(KeyPair keyPair, KeyPair keyPairBC)
            throws Exception {
        Cipher cipher = Cipher.getInstance("SM2", PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        // Ciphertext produced by SMCS
        // The format is C1||C3||C2 ASN.1 DER
        byte[] ciphertext = cipher.doFinal(MESSAGE);

        Cipher cipherBC = Cipher.getInstance("SM2", "BC");
        cipherBC.init(Cipher.ENCRYPT_MODE, keyPairBC.getPublic());
        // Ciphertext produced by BC
        // The format is C1||C2||C3
        byte[] ciphertextBC = cipherBC.doFinal(MESSAGE);

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        // Convert BC ciphertext to SMCS ciphertext
        byte[] derC1C3C2 = SM2Ciphertext.builder()
                .format(SM2Ciphertext.Format.RAW_C1C2C3)
                .encodedCiphertext(ciphertextBC)
                .build()
                .derC1C3C2();
        byte[] cleartext = cipher.doFinal(derC1C3C2);
        Assertions.assertArrayEquals(MESSAGE, cleartext);

        cipherBC.init(Cipher.DECRYPT_MODE, keyPairBC.getPrivate());
        // Convert SMCS ciphertext to BC ciphertext
        byte[] rawC1C2C3 = SM2Ciphertext.builder()
                .format(SM2Ciphertext.Format.DER_C1C3C2)
                .encodedCiphertext(ciphertext)
                .build()
                .rawC1C2C3();
        byte[] cleartextBC = cipherBC.doFinal(rawC1C2C3);
        Assertions.assertArrayEquals(MESSAGE, cleartextBC);
    }

    @Test
    public void testSMCSSignatureWithBCKeyPair() throws Exception {
        KeyPair keyPairBC = keyPairBC();
        KeyPair keyPair = toSMCSKeyPair(keyPairBC);
        testSignature(keyPair, keyPairBC);
    }

    @Test
    public void testBCSignatureWithSMCSKeyPair() throws Exception {
        KeyPair keyPair = keyPair();
        KeyPair keyPairBC = toBCKeyPair(keyPair);
        testSignature(keyPair, keyPairBC);
    }

    private void testSignature(KeyPair keyPair, KeyPair keyPairBC)
            throws Exception {
        Signature signature = Signature.getInstance("SM2", PROVIDER);
        SM2SignatureParameterSpec paramSpec = new SM2SignatureParameterSpec(
                Constants.defaultId(),
                (ECPublicKey) keyPair.getPublic());
        signature.initSign(keyPair.getPrivate());
        signature.setParameter(paramSpec);
        signature.update(MESSAGE);
        // Signature produced by SMCS
        byte[] sign = signature.sign();

        Signature signatureBC = Signature.getInstance(
                GMObjectIdentifiers.sm2sign_with_sm3.toString(), "BC");
        SM2ParameterSpec paramSpecBC = new SM2ParameterSpec(
                Constants.defaultId());
        signatureBC.initSign(keyPairBC.getPrivate());
        signatureBC.setParameter(paramSpecBC);
        signatureBC.update(MESSAGE);
        // Signature produced by BC
        byte[] signBC = signatureBC.sign();

        signature.initVerify(keyPair.getPublic());
        signature.setParameter(paramSpec);
        signature.update(MESSAGE);
        // SMCS verifies the signature produced by BC
        Assertions.assertTrue(signature.verify(signBC));

        signatureBC.initVerify(keyPairBC.getPublic());
        signatureBC.setParameter(paramSpecBC);
        signatureBC.update(MESSAGE);
        // BC verifies the signature produced by SMCS
        Assertions.assertTrue(signatureBC.verify(sign));
    }

    private KeyPair toSMCSKeyPair(KeyPair keyPairBC) {
        BCECPublicKey pubKeyBC = (BCECPublicKey) keyPairBC.getPublic();
        BCECPrivateKey priKeyBC = (BCECPrivateKey) keyPairBC.getPrivate();

        return new KeyPair(
                new SM2PublicKey(pubKeyBC.getW()),
                new SM2PrivateKey(priKeyBC.getS()));
    }

    private KeyPair toBCKeyPair(KeyPair keyPair) {
        SM2PublicKey pubKey = (SM2PublicKey) keyPair.getPublic();
        SM2PrivateKey priKey = (SM2PrivateKey) keyPair.getPrivate();

        BCECPublicKey pubKeyBC = new BCECPublicKey(pubKey, null);
        BCECPrivateKey priKeyBC = new BCECPrivateKey(priKey, null);
        return new KeyPair(pubKeyBC, priKeyBC);
    }

    private KeyPair keyPair() throws Exception {
        KeyPairGenerator keyPairGenerator
                = KeyPairGenerator.getInstance("SM2", PROVIDER);
        return keyPairGenerator.generateKeyPair();
    }

    private KeyPair keyPairBC() throws Exception {
        ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGen.initialize(sm2Spec);
        return keyPairGen.generateKeyPair();
    }
}
