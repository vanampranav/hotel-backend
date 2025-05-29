package com.Colombus.HotelManagement.Controllers;

import com.Colombus.HotelManagement.Models.User;
import com.Colombus.HotelManagement.Services.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Optional;
import java.util.Map;

@RestController
@RequestMapping("/users")
//@CrossOrigin(origins="*")
@CrossOrigin(origins = "http://localhost:3000") // Allow frontend access
public class UserController {
    private final UserService userService;
    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getAllUsers() {
        try {
            List<User> users = userService.getAllUsers();
            return ResponseEntity.ok(users);
        } catch (Exception e) {
            logger.error("Error getting all users: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    // Get user details by ID
    @GetMapping("/{id}")
    public ResponseEntity<?> getUserById(@PathVariable Long id) {
        try {
            Optional<User> user = userService.getUserById(id);
            return user.map(ResponseEntity::ok)
                    .orElseGet(() -> ResponseEntity.notFound().build());
        } catch (Exception e) {
            logger.error("Error getting user by ID {}: {}", id, e.getMessage(), e);
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @DeleteMapping("/terminate/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> terminateUser(@PathVariable Long userId) {
        try {
            logger.info("Attempting to terminate user with ID: {}", userId);
            
            // Log the current user's authorities
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            logger.info("Current user authorities: {}", auth.getAuthorities());
            
            // First fetch the user to verify it exists
            Optional<User> userOptional = userService.getUserById(userId);
            if (userOptional.isEmpty()) {
                logger.warn("User with ID {} not found for termination", userId);
                return ResponseEntity.badRequest().body(Map.of("message", "User not found"));
            }
            
            User user = userOptional.get();
            logger.info("Found user for termination: {} (current termination status: {}, role: {})", 
                    user.getUserName(), user.isTerminated(), user.getRole());
            
            // Check if user is already terminated
            if (user.isTerminated()) {
                logger.warn("User {} is already terminated", user.getUserName());
                return ResponseEntity.badRequest().body(Map.of("message", "User is already terminated"));
            }
            
            // Check if user is an admin
            String userRole = user.getRole();
            if (userRole != null && (userRole.equals("ROLE_ADMIN") || userRole.equals("ADMIN"))) {
                logger.warn("Cannot terminate admin user: {}", user.getUserName());
                return ResponseEntity.badRequest().body(Map.of("message", "Cannot terminate admin users"));
            }
            
            User terminatedUser = userService.terminateUser(userId);
            logger.info("User {} successfully terminated", terminatedUser.getUserName());
            
            return ResponseEntity.ok(Map.of(
                "message", "User terminated successfully",
                "user", Map.of(
                    "id", terminatedUser.getId(),
                    "userName", terminatedUser.getUserName(),
                    "email", terminatedUser.getEmail(),
                    "terminated", terminatedUser.isTerminated(),
                    "role", terminatedUser.getRole()
                )
            ));
        } catch (Exception e) {
            logger.error("Error terminating user: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(Map.of("message", "Failed to terminate user: " + e.getMessage()));
        }
    }

    @PostMapping("/restore/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> restoreUser(@PathVariable Long userId) {
        try {
            logger.info("Attempting to restore user with ID: {}", userId);
            User restoredUser = userService.restoreUser(userId);
            logger.info("User {} successfully restored", restoredUser.getUserName());
            return ResponseEntity.ok(Map.of(
                "message", "User restored successfully",
                "user", Map.of(
                    "id", restoredUser.getId(),
                    "userName", restoredUser.getUserName(),
                    "email", restoredUser.getEmail(),
                    "terminated", restoredUser.isTerminated(),
                    "role", restoredUser.getRole()
                )
            ));
        } catch (Exception e) {
            logger.error("Error restoring user: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(Map.of("message", "Failed to restore user: " + e.getMessage()));
        }
    }

    @GetMapping("/terminated")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getTerminatedUsers() {
        try {
            List<User> terminatedUsers = userService.getTerminatedUsers();
            return ResponseEntity.ok(terminatedUsers);
        } catch (Exception e) {
            logger.error("Error getting terminated users: {}", e.getMessage(), e);
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
