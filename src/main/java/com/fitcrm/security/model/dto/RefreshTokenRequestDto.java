package com.fitcrm.security.model.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class RefreshTokenRequestDto {
    private String refreshToken;
}