package com.example.authserver.user;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(
        name = "external_identities",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_provider_user",
                        columnNames = {"provider", "providerUserId"}
                )
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ExternalIdentityEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // e.g. "google"
    @Column(nullable = false, length = 50)
    private String provider;

    // Google "sub" claim
    @Column(nullable = false, length = 191)
    private String providerUserId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;

    @Column(length = 191)
    private String email;
}
