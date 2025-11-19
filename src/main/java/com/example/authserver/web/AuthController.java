package com.example.authserver.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthController {

    @GetMapping("/")
    public String index(@AuthenticationPrincipal Object principal, Model model) {
        model.addAttribute("principal", principal);
        return "index";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}