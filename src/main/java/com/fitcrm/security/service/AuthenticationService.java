package com.fitcrm.security.service;

import com.fitcrm.security.clients.UserServiceClient;
import com.fitcrm.security.model.dto.AuthTokensDto;
import com.fitcrm.security.model.dto.LoginRequestDto;
import com.fitcrm.security.model.dto.RefreshTokenRequestDto;
import com.fitcrm.security.model.dto.UserDto;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final JwtService jwtService;
    private final UserServiceClient userClient;

    /**
     * Логин пользователя:
     * проверяет email+пароль, выдает access+refresh и сохраняет их в БД.
     */
    public AuthTokensDto login(LoginRequestDto request) {
        String email = request.getEmail();

        UserDto user = userClient.verifyCredentials(request);

        AuthTokensDto tokens = jwtService.issueTokens(user.getId(), email, user.getRole());

        log.info("User {} logged in successfully", email);
        return tokens;
    }

    /**
     * Обновление токенов через refresh-токен.
     */
    @Transactional
    public AuthTokensDto refresh(RefreshTokenRequestDto request) {
        String oldRefresh = request.getRefreshToken();
        AuthTokensDto rotated = jwtService.refreshToken(oldRefresh);

        log.info("Tokens refreshed for refreshToken={}", oldRefresh.substring(0, 10) + "...");
        return rotated;
    }

    /**
     * Отзыв всех токенов пользователя.
     */
    @Transactional
    public void logout(Long userId) {
        jwtService.revokeTokens(userId);
        log.info("Tokens revoked for user {}", userId);
    }
}