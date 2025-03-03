package com.Colombus.HotelManagement.Services;

import com.Colombus.HotelManagement.Models.Hotel;
import com.Colombus.HotelManagement.Repositories.HotelRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class HotelService {
    private final HotelRepository hotelRepository;

    public HotelService(HotelRepository hotelRepository) {
        this.hotelRepository = hotelRepository;
    }

    // Add a new hotel
    public Hotel addHotel(Hotel hotel) {
        return hotelRepository.save(hotel);
    }

    // Get all hotels
    public List<Hotel> getAllHotels() {
        return hotelRepository.findAll();
    }

    // Search hotels by name
    public List<Hotel> searchHotelsByName(String hotelName) {
        return hotelRepository.findByHotelNameContainingIgnoreCase(hotelName);
    }

    // Get preferred hotels
    public List<Hotel> getPreferredHotels() {
        return hotelRepository.findByPreferredTrue();
    }

    // Get hotel by ID
    public Optional<Hotel> getHotelById(Long id) {
        return hotelRepository.findById(id);
    }

    // Update hotel details
    public Hotel updateHotel(Long id, Hotel updatedHotel) {
        return hotelRepository.findById(id).map(hotel -> {
            hotel.setHotelName(updatedHotel.getHotelName());
            hotel.setEmail1(updatedHotel.getEmail1());
            hotel.setEmail2(updatedHotel.getEmail2());
            hotel.setAddress(updatedHotel.getAddress());
            hotel.setMobilePhoneContact(updatedHotel.getMobilePhoneContact());
            hotel.setLandlineContact(updatedHotel.getLandlineContact());
            hotel.setConcerningPersonName(updatedHotel.getConcerningPersonName());
            hotel.setPreferred(updatedHotel.isPreferred());
            return hotelRepository.save(hotel);
        }).orElseThrow(() -> new RuntimeException("Hotel not found"));
    }

    // Delete hotel by ID
    public void deleteHotel(Long id) {
        hotelRepository.deleteById(id);
    }
}
