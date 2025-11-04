package com.fitcrm.security.model.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AuthTokensDto {

    private String accessToken;
    private String refreshToken;
    private LocalDateTime accessTokenExpiresAt;
}