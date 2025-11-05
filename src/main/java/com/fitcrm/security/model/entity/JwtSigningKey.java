package com.fitcrm.security.model.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "jwt_signing_keys")
public class JwtSigningKey {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "signing_key", nullable = false, columnDefinition = "TEXT")
    private String signingKey;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;
}