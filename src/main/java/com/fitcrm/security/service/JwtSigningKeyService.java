package com.fitcrm.security.service;

import com.fitcrm.security.model.entity.JwtSigningKey;
import com.fitcrm.security.repository.JwtSigningKeyRepository;
import com.fitcrm.security.utils.JwtKeyUtil;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtSigningKeyService {

    private final JwtSigningKeyRepository keyRepo;
    private final JwtKeyUtil jwtKeyUtil;

    @Getter
    private String signingKey;

    @PostConstruct
    public void init() {
        this.signingKey = loadOrGenerateKey();
        log.info("JWT signing key loaded ({} chars)", signingKey.length());
    }

    private String loadOrGenerateKey() {
        return keyRepo.findLatestKey()
                .map(key -> {
                    try {
                        return jwtKeyUtil.decrypt(key.getSigningKey());
                    } catch (Exception e) {
                        log.error("Failed to decrypt JWT key, generating new one", e);
                        return generateAndSaveNewKey();
                    }
                })
                .orElseGet(this::generateAndSaveNewKey);
    }

    private String generateAndSaveNewKey() {
        String plainKey = generateSecureKey();
        try {
            String encryptedKey = jwtKeyUtil.encrypt(plainKey);
            JwtSigningKey entity = JwtSigningKey.builder()
                    .signingKey(encryptedKey)
                    .createdAt(LocalDateTime.now())
                    .build();
            keyRepo.save(entity);
            log.warn("New JWT signing key generated and encrypted in DB");
            return plainKey;
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt new JWT key", e);
        }
    }

    private String generateSecureKey() {
        byte[] randomBytes = new byte[64];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}
