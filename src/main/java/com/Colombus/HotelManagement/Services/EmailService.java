package com.Colombus.HotelManagement.Services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

    @Autowired
    private JavaMailSender emailSender;

    public void sendRegistrationConfirmation(String to) {
        logger.info("Attempting to send registration confirmation email to: {}", to);
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject("Welcome to Colombus Vacations!");
            message.setText(
                "Dear Valued Customer,\n\n" +
                "Thank you for choosing to register with Colombus Vacations! We're excited to have you join our community of travelers.\n\n" +
                "Your account is currently pending approval by our administrative team. This process typically takes 24-48 hours. " +
                "You will receive another email once your account is approved.\n\n" +
                "Once approved, you'll be able to:\n" +
                "- Browse our extensive collection of hotels\n" +
                "- Book accommodations for your next vacation\n" +
                "- Access exclusive deals and promotions\n" +
                "- Manage your bookings and preferences\n\n" +
                "If you have any questions during this process, please don't hesitate to contact our support team.\n\n" +
                "Best regards,\n" +
                "The Colombus Vacations Team"
            );
            
            logger.info("Email message prepared. Sending to: {}", to);
            emailSender.send(message);
            logger.info("Registration confirmation email successfully sent to: {}", to);
        } catch (Exception e) {
            logger.error("Failed to send registration confirmation email to: " + to, e);
            logger.error("Error details: ", e);
        }
    }

    public void sendApprovalNotification(String to) {
        logger.info("Attempting to send approval notification email to: {}", to);
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject("Your Colombus Vacations Account is Approved!");
            message.setText(
                "Dear Valued Customer,\n\n" +
                "Great news! Your Colombus Vacations account has been approved. You can now access all our services and start planning your next adventure!\n\n" +
                "To get started:\n" +
                "1. Visit http://localhost:3000\n" +
                "2. Log in with your credentials\n" +
                "3. Explore our wide range of hotels and accommodations\n" +
                "4. Book your next stay with us\n\n" +
                "As a registered member, you'll enjoy:\n" +
                "- Exclusive member-only rates\n" +
                "- Special promotions and discounts\n" +
                "- Easy booking management\n" +
                "- 24/7 customer support\n\n" +
                "If you have any questions or need assistance, our support team is always here to help.\n\n" +
                "Happy travels!\n" +
                "The Colombus Vacations Team"
            );
            
            logger.info("Email message prepared. Sending to: {}", to);
            emailSender.send(message);
            logger.info("Approval notification email successfully sent to: {}", to);
        } catch (Exception e) {
            logger.error("Failed to send approval notification email to: " + to, e);
            logger.error("Error details: ", e);
        }
    }

    public void sendTerminationNotification(String to) {
        logger.info("Attempting to send termination notification email to: {}", to);
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject("Your Colombus Vacations Account Access Has Been Terminated");
            message.setText(
                "Dear Valued Customer,\n\n" +
                "This email is to inform you that your access to Colombus Vacations has been terminated. " +
                "Your account is no longer active and you will not be able to access our services.\n\n" +
                "If you believe this action was taken in error, please contact our support team.\n\n" +
                "Best regards,\n" +
                "The Colombus Vacations Team"
            );
            
            logger.info("Email message prepared. Sending to: {}", to);
            emailSender.send(message);
            logger.info("Termination notification email successfully sent to: {}", to);
        } catch (Exception e) {
            logger.error("Failed to send termination notification email to: " + to, e);
            logger.error("Error details: ", e);
        }
    }

    public void sendRestorationNotification(String to) {
        logger.info("Attempting to send restoration notification email to: {}", to);
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(to);
            message.setSubject("Your Colombus Vacations Account Has Been Restored");
            message.setText(
                "Dear Valued Customer,\n\n" +
                "We are pleased to inform you that your access to Colombus Vacations has been restored. " +
                "Your account is now active again, but it will need to be approved by an administrator before you can access our services.\n\n" +
                "You will receive another email once your account is approved.\n\n" +
                "If you have any questions, please contact our support team.\n\n" +
                "Best regards,\n" +
                "The Colombus Vacations Team"
            );
            
            logger.info("Email message prepared. Sending to: {}", to);
            emailSender.send(message);
            logger.info("Restoration notification email successfully sent to: {}", to);
        } catch (Exception e) {
            logger.error("Failed to send restoration notification email to: " + to, e);
            logger.error("Error details: ", e);
        }
    }
} 