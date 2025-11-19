package com.example.authserver.web;

import com.example.authserver.user.UserEntity;
import com.example.authserver.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequiredArgsConstructor
public class PasswordController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @GetMapping("/set-password")
    public String showSetPasswordForm() {
        return "set-password";
    }

    @PostMapping("/set-password")
    public String setPassword(@AuthenticationPrincipal UserDetails principal,
                              @RequestParam String newPassword,
                              Model model) {
        if (principal == null) {
            return "redirect:/login";
        }

        UserEntity user = userRepository.findByUsername(principal.getUsername())
                .orElseThrow(() -> new IllegalStateException("User not found"));

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        model.addAttribute("message", "Password set successfully");
        return "set-password";
    }
}