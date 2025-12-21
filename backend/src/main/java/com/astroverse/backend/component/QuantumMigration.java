package com.astroverse.backend.component;

import com.astroverse.backend.model.User;
import com.astroverse.backend.repository.UserRepository;
import com.astroverse.backend.service.HybridCryptoService;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import java.util.List;

@Component
public class QuantumMigration {

    private final UserRepository userRepository;
    private final HybridCryptoService cryptoService;

    public QuantumMigration(UserRepository userRepository, HybridCryptoService cryptoService) {
        this.userRepository = userRepository;
        this.cryptoService = cryptoService;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void migrateLegacyUsers() {
        // Cerchiamo utenti che hanno il flag isQuantumEncrypted = FALSE (0)
        List<User> legacyUsers = userRepository.findByIsQuantumEncryptedFalse();
        if (legacyUsers.isEmpty()) {
            return; // Nessuno da migrare
        }
        System.out.println("⚡ [MIGRAZIONE] Trovati " + legacyUsers.size() + " utenti vulnerabili. Avvio procedura Post-Quantum...");
        for (User user : legacyUsers) {
            try {
                String emailInChiaro = user.getEmail();
                // Se per qualche motivo l'email è nulla o vuota, saltiamo
                if (emailInChiaro == null || emailInChiaro.isEmpty()) continue;
                System.out.println("    -> Migrazione utente: " + user.getUsername() + " (" + emailInChiaro + ")");
                // CIFRATURA (Protezione Privacy)
                // Usiamo Kyber + AES per rendere l'email illeggibile
                var encryptionResult = cryptoService.encrypt(emailInChiaro);
                // HASHING (Indicizzazione)
                // Creiamo l'hash SHA-256 per permettere il login futuro
                String emailHash = cryptoService.hashString(emailInChiaro);
                // AGGIORNAMENTO DEL RECORD
                user.setEmail(encryptionResult.encryptedData()); // Sovrascriviamo il chiaro col cifrato
                user.setEmailHash(emailHash);
                // Salviamo le chiavi pubbliche/busta per poter decifrare dopo
                user.setQuantumEncapsulation(encryptionResult.encapsulation());
                user.setClientEccPublicKey(encryptionResult.clientEccPub());
                // Settiamo il flag a TRUE: ora l'utente è al sicuro
                user.setQuantumEncrypted(true);
                userRepository.save(user);
                System.out.println("   ✅ Successo! Utente blindato contro attacchi quantistici.");
            } catch (Exception e) {
                System.err.println("   ❌ Errore durante la migrazione: " + e.getMessage());
            }
        }
    }
}