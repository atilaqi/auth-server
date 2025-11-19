package com.example.authserver.config;

import com.example.authserver.user.ExternalIdentityEntity;
import com.example.authserver.user.ExternalIdentityRepository;
import com.example.authserver.user.UserEntity;
import com.example.authserver.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Configuration
@RequiredArgsConstructor
public class FederatedIdentityConfig {

    private final UserRepository userRepository;
    private final ExternalIdentityRepository externalIdentityRepository;
    private final PasswordEncoder passwordEncoder; // currently not used, but fine to keep for future

    @Bean
    @Order(2) // same order as appSecurityFilterChain, we override only oauth2 part
    public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {

        // For Google (OIDC), we must use OidcUserService instead of DefaultOAuth2UserService
        OidcUserService delegate = new OidcUserService();

        OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService = request -> {
            // 1. Let default OIDC user service load the user (ID token + userinfo)
            OidcUser oidcUser = delegate.loadUser(request);

            String registrationId = request.getClientRegistration().getRegistrationId(); // "google"
            String provider = registrationId;

            // "sub" is the stable subject identifier for the user at this provider
            String providerUserId = oidcUser.getSubject();
            String email = oidcUser.getEmail();

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
                            // you can later let user set password (password reset flow)
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

            // Here you could enforce "must set password" logic using user.getPasswordHash()

            // Combine provider authorities with your own
            Collection<? extends GrantedAuthority> defaultAuthorities = oidcUser.getAuthorities();

            Collection<GrantedAuthority> mappedAuthorities =
                    Stream.concat(
                            defaultAuthorities.stream(),
                            Stream.of(new SimpleGrantedAuthority("ROLE_USER"))
                    ).collect(Collectors.toSet());

            // Return a new OidcUser with updated authorities.
            // Use "email" as name attribute if available, else "sub".
            String nameAttributeKey = (email != null ? "email" : "sub");

            return new DefaultOidcUser(
                    mappedAuthorities,
                    oidcUser.getIdToken(),
                    oidcUser.getUserInfo(),
                    nameAttributeKey
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
                        .userInfoEndpoint(info -> info
                                // IMPORTANT: use oidcUserService for Google (OIDC)
                                .oidcUserService(oidcUserService)
                        )
                )
                .logout(logout -> logout
                        // accept GET /logout (for RP-initiated logout from demo-client)
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                        .logoutSuccessHandler((request, response, authentication) -> {
                            String redirect = request.getParameter("post_logout_redirect_uri");
                            if (redirect == null || redirect.isBlank()) {
                                redirect = "/";
                            }
                            response.sendRedirect(redirect);
                        })
                        .permitAll()
                );

        return http.build();
    }
}
