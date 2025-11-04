package com.fitcrm.security.repository;

import com.fitcrm.security.model.entity.JwtSigningKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface JwtSigningKeyRepository extends JpaRepository<JwtSigningKey, Long> {
    @Query(value = "SELECT * FROM jwt_signing_keys ORDER BY created_at DESC LIMIT 1", nativeQuery = true)
    Optional<JwtSigningKey> findLatestKey();
}