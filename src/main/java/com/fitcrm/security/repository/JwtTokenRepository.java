package com.fitcrm.security.repository;

import com.fitcrm.security.model.entity.JwtToken;
import com.fitcrm.security.model.enums.TokenType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface JwtTokenRepository extends JpaRepository<JwtToken, Long> {
    Optional<JwtToken> findByUserIdAndTokenType(Long userId, TokenType tokenType);

    Optional<JwtToken> findByTokenValueAndTokenTypeAndRevokedFalse(
            String tokenValue, TokenType tokenType);
}