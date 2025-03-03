package com.Colombus.HotelManagement.Models;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Data
@Table(name="hotels")
public class Hotel {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String hotelName;

    @Column(nullable = false, unique = true)
    private String email1;

    @Column(unique = true)
    private String email2;

    @Column(nullable = false)
    private String address;

    @Column(nullable = false, unique = true)
    private String mobilePhoneContact;

    @Column(unique = true)
    private String landlineContact;

    @Column(nullable = false)
    private String concerningPersonName;

    private boolean preferred;  // To mark preferred hotels

}
