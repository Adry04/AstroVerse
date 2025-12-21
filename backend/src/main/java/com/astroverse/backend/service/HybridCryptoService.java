package com.astroverse.backend.service;

import jakarta.annotation.PostConstruct;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.springframework.stereotype.Service;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class HybridCryptoService {

    private KeyPair serverPqcKeyPair;
    private KeyPair serverEccKeyPair;
    private static final String KEY_GENERATION_SEED = "QUESTA_FRASE_GENERA_SEMPRE_LE_STESSE_CHIAVI_PER_ASTROVERSE_2025";

    static {
        Security.removeProvider("BC");
        Security.addProvider(new BouncyCastleProvider());
    }

    // Al'avvio del server, generiamo le chiavi MASTER del server.
    // NOTA: Se riavvii il server, perdi le chiavi e non decifri più i dati vecchi.
    // Per il tirocinio: "Simuliamo che queste chiavi siano persistenti in un HSM".
    @PostConstruct
    public void init() throws Exception {
        System.out.println("🔒 Generazione Chiavi Deterministiche in corso...");

        // Creiamo un generatore di casualità che parte sempre dallo stesso punto
        SecureRandom deterministicRandom = SecureRandom.getInstance("SHA1PRNG");
        deterministicRandom.setSeed(KEY_GENERATION_SEED.getBytes());

        // 1. Genera ML-KEM (Kyber) usando il random deterministico
        KeyPairGenerator pqcKpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
        pqcKpg.initialize(MLKEMParameterSpec.ml_kem_768, deterministicRandom);
        serverPqcKeyPair = pqcKpg.generateKeyPair();

        // 2. Genera ECC usando lo STESSO random (che ora è avanzato di stato)
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("ECDH", "BC");
        ecKpg.initialize(new ECGenParameterSpec("secp256r1"), deterministicRandom);
        serverEccKeyPair = ecKpg.generateKeyPair();

        System.out.println("✅ Chiavi Server pronte (Stabili tra i riavvii)");
    }

    // Classe contenitore per i risultati
    public record EncryptionResult(String encryptedData, String encapsulation, String clientEccPub) {}

    /**
     * FASE 1: REGISTRAZIONE / CIFRATURA
     * Simula il client che crea le chiavi e cifra il dato.
     */
    public EncryptionResult encrypt(String plainData) {
        try {
            // 1. Simula Client ECC
            KeyPairGenerator clientEcKpg = KeyPairGenerator.getInstance("ECDH", "BC");
            clientEcKpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair clientEcPair = clientEcKpg.generateKeyPair();

            // 2. ECDH Agreement
            KeyAgreement ecAgreement = KeyAgreement.getInstance("ECDH", "BC");
            ecAgreement.init(clientEcPair.getPrivate());
            ecAgreement.doPhase(serverEccKeyPair.getPublic(), true);
            byte[] classicalSecret = ecAgreement.generateSecret();

            // 3. ML-KEM Encapsulation
            KeyGenerator kemGen = KeyGenerator.getInstance("ML-KEM", "BC");
            kemGen.init(new KEMGenerateSpec(serverPqcKeyPair.getPublic(), "Generic"));
            SecretKeyWithEncapsulation kemResult = (SecretKeyWithEncapsulation) kemGen.generateKey();

            // 4. Chiave Finale
            SecretKey finalKey = combineSecrets(classicalSecret, kemResult.getEncoded());

            // 5. AES Encrypt
            String cipherText = aesEncrypt(plainData, finalKey);

            return new EncryptionResult(
                    cipherText,
                    Base64.getEncoder().encodeToString(kemResult.getEncapsulation()),
                    Base64.getEncoder().encodeToString(clientEcPair.getPublic().getEncoded())
            );
        } catch (Exception e) {
            throw new RuntimeException("Errore cifratura Quantum", e);
        }
    }

    /**
     * FASE 2: LETTURA / DECIFRATURA
     * Il server usa i metadati salvati nel DB per ricostruire la chiave.
     */
    public String decrypt(String encryptedData, String encapsulationStr, String clientEccPubStr) {
        try {
            // Ricostruisce chiave pubblica client
            byte[] clientPubBytes = Base64.getDecoder().decode(clientEccPubStr);
            KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
            PublicKey clientEccPub = kf.generatePublic(new X509EncodedKeySpec(clientPubBytes));

            // ECDH
            KeyAgreement ecAgreement = KeyAgreement.getInstance("ECDH", "BC");
            ecAgreement.init(serverEccKeyPair.getPrivate());
            ecAgreement.doPhase(clientEccPub, true);
            byte[] classicalSecret = ecAgreement.generateSecret();

            // ML-KEM Decapsulate
            byte[] encapsulation = Base64.getDecoder().decode(encapsulationStr);
            KeyGenerator kemGen = KeyGenerator.getInstance("ML-KEM", "BC");
            kemGen.init(new KEMExtractSpec(serverPqcKeyPair.getPrivate(), encapsulation, "Generic"));
            SecretKeyWithEncapsulation kemResult = (SecretKeyWithEncapsulation) kemGen.generateKey();

            // Chiave Finale
            SecretKey finalKey = combineSecrets(classicalSecret, kemResult.getEncoded());

            return aesDecrypt(encryptedData, finalKey);
        } catch (Exception e) {
            throw new RuntimeException("Errore decifratura Quantum", e);
        }
    }

    public String hashString(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Hashing fallito", e);
        }
    }

    private SecretKey combineSecrets(byte[] s1, byte[] s2) throws Exception {
        MessageDigest d = MessageDigest.getInstance("SHA-256");
        d.update(s1);
        d.update(s2);
        return new SecretKeySpec(d.digest(), "AES");
    }

    private String aesEncrypt(String data, SecretKey key) throws Exception {
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", "BC");
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        c.init(javax.crypto.Cipher.ENCRYPT_MODE, key, new javax.crypto.spec.GCMParameterSpec(128, iv));
        byte[] ct = c.doFinal(data.getBytes());
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return Base64.getEncoder().encodeToString(out);
    }

    private String aesDecrypt(String data, SecretKey key) throws Exception {
        byte[] in = Base64.getDecoder().decode(data);
        byte[] iv = new byte[12];
        System.arraycopy(in, 0, iv, 0, 12);
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", "BC");
        c.init(javax.crypto.Cipher.DECRYPT_MODE, key, new javax.crypto.spec.GCMParameterSpec(128, iv));
        return new String(c.doFinal(in, 12, in.length - 12));
    }
}