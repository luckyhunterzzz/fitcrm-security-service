package com.fitcrm.security.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fitcrm.security.clients.UserServiceClient;
import com.fitcrm.security.model.dto.AuthTokensDto;
import com.fitcrm.security.model.dto.UserDto;
import com.fitcrm.security.model.entity.JwtToken;
import com.fitcrm.security.model.enums.TokenType;
import com.fitcrm.security.repository.JwtTokenRepository;
import jakarta.annotation.PostConstruct;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtSigningKeyService keyService;
    private final JwtTokenRepository tokenRepo;
    private final UserServiceClient userClient;

    private JWTVerifier verifier;

    @Value("${security.jwt.access-expiration-ms}")
    private long accessExpMs;

    @Value("${security.jwt.refresh-expiration-ms}")
    private long refreshExpMs;

    @PostConstruct
    public void initVerifier() {
        Algorithm algorithm = Algorithm.HMAC512(keyService.getSigningKey().getBytes(StandardCharsets.UTF_8));
        this.verifier = JWT.require(algorithm).build();
        log.info("JWTVerifier initialized and cached");
    }

    // ========================================================================
    // 1. ВЫДАЧА ТОКЕНОВ (с сохранением в БД)
    // ========================================================================
    @Transactional
    public AuthTokensDto issueTokens(Long userId, String email, String role) {
        String access = generateAccessToken(userId, email, role);
        String refresh = generateRefreshToken(userId);

        saveOrUpdateToken(userId, TokenType.ACCESS, access);
        saveOrUpdateToken(userId, TokenType.REFRESH, refresh);

        LocalDateTime expiresAt = LocalDateTime.now().plus(accessExpMs, ChronoUnit.MILLIS);

        return new AuthTokensDto(access, refresh, expiresAt);
    }

    private String generateAccessToken(Long userId, String email, String role) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime exp = now.plus(accessExpMs, ChronoUnit.MILLIS);

        return JWT.create()
                .withJWTId(UUID.randomUUID().toString())
                .withSubject(email)
                .withIssuedAt(Date.from(now.atZone(ZoneId.systemDefault()).toInstant()))
                .withExpiresAt(Date.from(exp.atZone(ZoneId.systemDefault()).toInstant()))
                .withClaim("user_id", userId)
                .withClaim("role", role)
                .withClaim("type", TokenType.ACCESS.name())
                .sign(getAlgorithm());
    }

    private String generateRefreshToken(Long userId) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime exp = now.plus(refreshExpMs, ChronoUnit.MILLIS);

        return JWT.create()
                .withJWTId(UUID.randomUUID().toString())
                .withSubject(userId.toString())
                .withIssuedAt(Date.from(now.atZone(ZoneId.systemDefault()).toInstant()))
                .withExpiresAt(Date.from(exp.atZone(ZoneId.systemDefault()).toInstant()))
                .withClaim("type", TokenType.REFRESH.name())
                .sign(getAlgorithm());
    }

    private Algorithm getAlgorithm() {
        return Algorithm.HMAC512(keyService.getSigningKey().getBytes(StandardCharsets.UTF_8));
    }

    // ========================================================================
    // 2. СОХРАНЕНИЕ/ОБНОВЛЕНИЕ В БД
    // ========================================================================
    private void saveOrUpdateToken(Long userId, TokenType type, String tokenValue) {
        JwtToken existing = tokenRepo.findByUserIdAndTokenType(userId, type).orElse(null);

        if (existing != null) {
            // UPDATE
            existing.setTokenValue(tokenValue);
            existing.setCreatedAt(LocalDateTime.now());
            existing.setRevoked(false);
            existing.setRevokedAt(null);
            tokenRepo.save(existing);
            log.debug("Updated {} token for user {}", type, userId);
        } else {
            // INSERT
            JwtToken newToken = JwtToken.builder()
                    .userId(userId)
                    .tokenType(type)
                    .tokenValue(tokenValue)
                    .createdAt(LocalDateTime.now())
                    .revoked(false)
                    .build();
            tokenRepo.save(newToken);
            log.debug("Saved new {} token for user {}", type, userId);
        }
    }

    // ========================================================================
    // 3. ВАЛИДАЦИЯ
    // ========================================================================
    public DecodedJWT verifyToken(String token, TokenType expectedType) {
        try {
            DecodedJWT decoded = verifier.verify(token);
            String type = decoded.getClaim("type").asString();

            if (!expectedType.name().equals(type)) {
                throw new JWTVerificationException("Invalid token type");
            }

            // Проверяем в БД
            boolean exists = tokenRepo.findByTokenValueAndTokenTypeAndRevokedFalse(token, expectedType).isPresent();
            if (!exists) {
                throw new JWTVerificationException("Token not found or revoked");
            }

            return decoded;
        } catch (JWTVerificationException e) {
            log.debug("Token validation failed: {}", e.getMessage());
            throw e;
        }
    }

    // ========================================================================
    // 4. ИЗВЛЕЧЕНИЕ
    // ========================================================================
    public Long extractUserId(String token, TokenType type) {
        DecodedJWT decoded = verifyToken(token, type);
        return type == TokenType.REFRESH
                ? Long.parseLong(decoded.getSubject())
                : decoded.getClaim("user_id").asLong();
    }

    // ========================================================================
    // 5. РОТАЦИЯ (с перезаписью)
    // ========================================================================
    @Transactional
    public AuthTokensDto refreshToken(String oldRefreshToken) {
        DecodedJWT decoded = verifyToken(oldRefreshToken, TokenType.REFRESH);
        Long userId = Long.parseLong(decoded.getSubject());

        UserDto user = userClient.getUserById(userId);
        if (user == null || !user.isActive()) {
            throw new RuntimeException("User not found or inactive");
        }

        String email = user.getEmail();
        String role = user.getRole();

        String newAccess = generateAccessToken(userId, email, role);
        String newRefresh = generateRefreshToken(userId);

        saveOrUpdateToken(userId, TokenType.ACCESS, newAccess);
        saveOrUpdateToken(userId, TokenType.REFRESH, newRefresh);

        DecodedJWT accessDecoded = verifier.verify(newAccess);
        LocalDateTime expiresAt = accessDecoded.getExpiresAt()
                .toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();

        log.info("Tokens rotated for user {}", userId);
        return new AuthTokensDto(newAccess, newRefresh, expiresAt);
    }

    // ========================================================================
    // 6. ОТЗЫВ
    // ========================================================================
    @Transactional
    public void revokeTokens(Long userId) {
        tokenRepo.findByUserIdAndTokenType(userId, TokenType.ACCESS)
                .ifPresent(this::revokeToken);
        tokenRepo.findByUserIdAndTokenType(userId, TokenType.REFRESH)
                .ifPresent(this::revokeToken);
    }

    private void revokeToken(JwtToken token) {
        token.setRevoked(true);
        token.setRevokedAt(LocalDateTime.now());
        tokenRepo.save(token);
    }
}