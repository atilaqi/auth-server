package com.example.authserver.config;

import com.example.authserver.user.*;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.*;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.user.*;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collections;

@Configuration
@RequiredArgsConstructor
@Profile("federated")
public class FederatedIdentityConfig {

    private final UserRepository userRepository;
    private final ExternalIdentityRepository externalIdentityRepository;
    private final PasswordEncoder passwordEncoder;

    @Bean
    @Order(2) // same order as appSecurityFilterChain, we override only oauth2 part
    public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {

        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

        OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService = request -> {
            OAuth2User oauth2User = delegate.loadUser(request);
            String registrationId = request.getClientRegistration().getRegistrationId(); // "google"

            String provider = registrationId;
            String providerUserId = oauth2User.getName(); // usually "sub"
            String email = oauth2User.getAttribute("email");

            ExternalIdentityEntity external = externalIdentityRepository
                    .findByProviderAndProviderUserId(provider, providerUserId)
                    .orElse(null);

            UserEntity user;
            if (external != null) {
                user = external.getUser();
            } else {
                // Try link by email if exists
                if (email != null) {
                    user = userRepository.findByEmail(email).orElse(null);
                } else {
                    user = null;
                }

                if (user == null) {
                    // Create new local user
                    String username = email != null ? email : ("user_" + provider + "_" + providerUserId);

                    user = UserEntity.builder()
                            .email(email != null ? email : (providerUserId + "@example.com"))
                            .username(username)
                            // no password yet; user can set later
                            .passwordHash(null)
                            .enabled(true)
                            .locked(false)
                            .build();
                    user = userRepository.save(user);
                }

                ExternalIdentityEntity newExternal = ExternalIdentityEntity.builder()
                        .provider(provider)
                        .providerUserId(providerUserId)
                        .email(email)
                        .user(user)
                        .build();
                externalIdentityRepository.save(newExternal);
            }

            // Here you could enforce "must set password" logic
            // e.g. if (user.getPasswordHash() == null) => flag in attributes

            return new DefaultOAuth2User(
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")),
                    oauth2User.getAttributes(),
                    "email"
            );
        };

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/login", "/set-password", "/css/**").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .permitAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .userInfoEndpoint(info -> info.userService(oauth2UserService))
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/").permitAll()
                );

        return http.build();
    }
}