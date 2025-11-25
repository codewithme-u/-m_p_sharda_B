package com.mp.config;

import com.mp.entity.Role;
import com.mp.entity.User;
import com.mp.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Configuration
public class DataInitializer {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    public CommandLineRunner createAdminUser() {
        return args -> {
            try {
                // Call initializer but don't let failures block application startup
                this.createAdminIfMissing();
            } catch (Exception e) {
                // Log and continue startup
                System.err.println("DataInitializer skipped due to exception: " + e.getMessage());
            }
        };
    }

    @Transactional
    public void createAdminIfMissing() {
        String adminEmail = "admin@gmail.com";

        // IMPORTANT: admin password must be provided via env var for safety
        String adminPassword = System.getenv("INIT_ADMIN_PASSWORD");

        if (adminPassword == null || adminPassword.isBlank()) {
            System.err.println("INIT_ADMIN_PASSWORD not set — skipping admin creation. " +
                    "Set INIT_ADMIN_PASSWORD env var on the host to enable automatic admin creation.");
            return;
        }

        try {
            if (userRepository.findByEmail(adminEmail).isEmpty()) {
                User admin = User.builder()
                        .email(adminEmail)
                        .name("System Admin")
                        .password(passwordEncoder.encode(adminPassword))
                        .roles(Set.of(Role.ADMIN))
                        .userType("ADMIN")
                        .active(true)
                        .emailVerified(true)
                        .build();

                userRepository.save(admin);
                System.out.println("Created admin user: " + adminEmail);
            } else {
                System.out.println("Admin user already exists: " + adminEmail);
            }
        } catch (Exception e) {
            // Do NOT rethrow here — just log so startup can complete
            String msg = e.getMessage() == null ? e.toString() : e.getMessage();
            if (msg.contains("users' doesn't exist") || msg.toLowerCase().contains("table") && msg.toLowerCase().contains("not found")) {
                System.err.println("WARNING: Admin user check skipped on startup due to schema creation timing.");
            } else {
                System.err.println("ERROR during data initialization (non-fatal): " + msg);
            }
            // do not throw; let app continue
        }
    }
}
