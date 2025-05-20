package com.Colombus.HotelManagement.Services;

import com.Colombus.HotelManagement.Models.User;
import com.Colombus.HotelManagement.Repositories.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Optional;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private EmailService emailService;

    public UserService(UserRepository userRepository, @Lazy PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // Register a new user
    public User registerUser(User user) {
        // Check if email already exists
        if (userRepository.existsByEmail(user.getEmail())) {
            throw new RuntimeException("Email already registered");
        }

        // Check if username already exists
        if (userRepository.existsByUserName(user.getUserName())) {
            throw new RuntimeException("Username already taken");
        }

        // Hash the password
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        // Set default role and approval status
        user.setRole("ROLE_USER");
        user.setApproved(false);

        // Save the user
        User savedUser = userRepository.save(user);

        // Send registration confirmation email
        try {
            emailService.sendRegistrationConfirmation(user.getEmail());
        } catch (Exception e) {
            logger.error("Failed to send registration confirmation email", e);
            // Don't throw the exception - we don't want to fail registration if email fails
        }

        return savedUser;
    }

    // Authenticate user
    public Optional<User> authenticateUser(String userName, String password) {
        Optional<User> user = userRepository.findByUserName(userName);
        
        if (user.isEmpty()) {
            logger.warn("User not found: {}", userName);
            return Optional.empty();
        }
        
        User foundUser = user.get();
        boolean passwordMatches = passwordEncoder.matches(password, foundUser.getPassword());
        
        logger.info("Authentication attempt - User: {}, PasswordMatches: {}, Role: {}, Approved: {}, Terminated: {}", 
                foundUser.getUserName(), 
                passwordMatches, 
                foundUser.getRole(),
                foundUser.isApproved(),
                foundUser.isTerminated());
        
        // First check if user exists and password matches
        if (passwordMatches) {
            // For admins, always allow login regardless of approval status
            if ("ROLE_ADMIN".equals(foundUser.getRole()) || "ADMIN".equals(foundUser.getRole())) {
                logger.info("Admin login successful: {}", userName);
                return user;
            }
            
            // Check if user is terminated
            if (foundUser.isTerminated()) {
                logger.warn("Terminated user {} attempted to login", userName);
                return Optional.empty();
            }
            
            // For regular users, check approval status
            if (foundUser.isApproved()) {
                logger.info("Approved user login successful: {}", userName);
                return user;
            }
            
            // User exists and password is correct, but not approved
            logger.warn("User {} attempted to login but is not approved", userName);
        } else {
            logger.warn("Password does not match for user: {}", userName);
        }
        
        return Optional.empty();
    }

    // Get user by ID
    public Optional<User> getUserById(Long id) {
        return userRepository.findById(id);
    }
    
    // Get user by username
    public Optional<User> getUserByUserName(String userName) {
        return userRepository.findByUserName(userName);
    }
    
    // Get all pending approval users
    public List<User> getPendingApprovalUsers() {
        return userRepository.findByApprovedFalse();
    }
    
    // Get all users
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
    
    // Get user count
    public long getUserCount() {
        return userRepository.count();
    }
    
    // Approve user
    public User approveUser(Long userId) {
        logger.info("Starting approval process for user ID: {}", userId);
        
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        logger.info("Found user: {} with email: {}", user.getUserName(), user.getEmail());
        
        user.setApproved(true);
        User approvedUser = userRepository.save(user);
        logger.info("User approved and saved to database");

        // Send approval notification email
        try {
            logger.info("Attempting to send approval notification email to: {}", user.getEmail());
            emailService.sendApprovalNotification(user.getEmail());
            logger.info("Approval notification email sent successfully");
        } catch (Exception e) {
            logger.error("Failed to send approval notification email to: " + user.getEmail(), e);
            logger.error("Error details: ", e);
            // Don't throw the exception - we don't want to fail approval if email fails
        }

        return approvedUser;
    }
    
    // Save user
    public User saveUser(User user) {
        return userRepository.save(user);
    }
    
    // Reject/delete user
    public void rejectUser(Long userId) {
        userRepository.deleteById(userId);
    }

    // Terminate user
    public User terminateUser(Long userId) {
        logger.info("Starting termination process for user ID: {}", userId);
        
        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    logger.error("User not found with ID: {}", userId);
                    return new RuntimeException("User not found");
                });
        
        // Don't allow terminating admin users
        if ("ROLE_ADMIN".equals(user.getRole()) || "ADMIN".equals(user.getRole())) {
            logger.error("Attempted to terminate admin user: {}", user.getUserName());
            throw new RuntimeException("Cannot terminate admin users");
        }
        
        logger.info("Found user for termination - Username: {}, Email: {}, Current status: [Terminated: {}, Approved: {}]", 
                user.getUserName(), user.getEmail(), user.isTerminated(), user.isApproved());
        
        // Set user as terminated and not approved
        user.setTerminated(true);
        user.setApproved(false);
        
        try {
            User terminatedUser = userRepository.save(user);
            logger.info("User terminated successfully - Username: {}, New status: [Terminated: {}, Approved: {}]", 
                    terminatedUser.getUserName(), terminatedUser.isTerminated(), terminatedUser.isApproved());

            // Send termination notification email
            try {
                logger.info("Attempting to send termination notification email to: {}", user.getEmail());
                emailService.sendTerminationNotification(user.getEmail());
                logger.info("Termination notification email sent successfully");
            } catch (Exception e) {
                logger.error("Failed to send termination notification email: {}", e.getMessage(), e);
                // Don't throw the exception - we don't want to fail termination if email fails
            }

            return terminatedUser;
        } catch (Exception e) {
            logger.error("Error saving terminated user: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to terminate user: " + e.getMessage());
        }
    }

    // Restore user
    public User restoreUser(Long userId) {
        logger.info("Starting restoration process for user ID: {}", userId);
        
        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    logger.error("User not found with ID: {}", userId);
                    return new RuntimeException("User not found");
                });
        
        logger.info("Found user for restoration - Username: {}, Email: {}, Current status: [Terminated: {}, Approved: {}]", 
                user.getUserName(), user.getEmail(), user.isTerminated(), user.isApproved());
        
        // Set user as not terminated and approved
        user.setTerminated(false);
        user.setApproved(true);
        
        try {
            User restoredUser = userRepository.save(user);
            logger.info("User restored successfully - Username: {}, New status: [Terminated: {}, Approved: {}]", 
                    restoredUser.getUserName(), restoredUser.isTerminated(), restoredUser.isApproved());

            // Send restoration notification email
            try {
                logger.info("Attempting to send restoration notification email to: {}", user.getEmail());
                emailService.sendRestorationNotification(user.getEmail());
                logger.info("Restoration notification email sent successfully");
            } catch (Exception e) {
                logger.error("Failed to send restoration notification email: {}", e.getMessage(), e);
                // Don't throw the exception - we don't want to fail restoration if email fails
            }

            return restoredUser;
        } catch (Exception e) {
            logger.error("Error saving restored user: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to restore user: " + e.getMessage());
        }
    }

    // Get all terminated users
    public List<User> getTerminatedUsers() {
        return userRepository.findByTerminatedTrue();
    }

    public User findByUsername(String username) {
        logger.info("Finding user by username: {}", username);
        return userRepository.findByUserName(username)
                .orElse(null);
    }
}
