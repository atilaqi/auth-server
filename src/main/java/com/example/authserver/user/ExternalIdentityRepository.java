package com.example.authserver.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ExternalIdentityRepository extends JpaRepository<ExternalIdentityEntity, Long> {

    Optional<ExternalIdentityEntity> findByProviderAndProviderUserId(String provider, String providerUserId);
}