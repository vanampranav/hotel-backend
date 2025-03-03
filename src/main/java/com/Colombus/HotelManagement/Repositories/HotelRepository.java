package com.Colombus.HotelManagement.Repositories;

import com.Colombus.HotelManagement.Models.Hotel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface HotelRepository extends JpaRepository<Hotel,Long> {
    List<Hotel> findByHotelNameContainingIgnoreCase(String hotelName);


    List<Hotel> findByPreferredTrue();
}
