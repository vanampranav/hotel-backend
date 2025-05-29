package com.Colombus.HotelManagement.Services;

import com.Colombus.HotelManagement.Models.Hotel;
import com.Colombus.HotelManagement.Repositories.HotelRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class HotelService {
    private static final Logger logger = LoggerFactory.getLogger(HotelService.class);

    @Autowired
    private HotelRepository hotelRepository;

    public List<Hotel> getAllHotels() {
        return hotelRepository.findAll();
    }

    public Optional<Hotel> getHotelById(Long id) {
        return hotelRepository.findById(id);
    }

    public Hotel saveHotel(Hotel hotel) {
        return hotelRepository.save(hotel);
    }

    public void deleteHotel(Long id) {
        hotelRepository.deleteById(id);
    }

    public List<Hotel> searchHotelsByName(String name) {
        return hotelRepository.findByHotelNameContainingIgnoreCase(name);
    }

    public List<Hotel> getPreferredHotels() {
        return hotelRepository.findByPreferredTrue();
    }

    public List<Hotel> searchHotelsByCity(String city) {
        return hotelRepository.findByCityContainingIgnoreCase(city);
    }

    public List<Hotel> searchHotelsByState(String state) {
        return hotelRepository.findByStateContainingIgnoreCase(state);
    }

    public List<Hotel> searchHotelsByCityAndState(String city, String state) {
        return hotelRepository.findByCityContainingIgnoreCaseAndStateContainingIgnoreCase(city, state);
    }

    public Hotel addHotel(Hotel hotel) {
        return hotelRepository.save(hotel);
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
            hotel.setCity(updatedHotel.getCity());
            hotel.setState(updatedHotel.getState());
            hotel.setWebsite(updatedHotel.getWebsite());
            return hotelRepository.save(hotel);
        }).orElseThrow(() -> new RuntimeException("Hotel not found"));
    }

    public List<Hotel> processCSVFile(MultipartFile file) throws IOException {
        List<Hotel> hotels = new ArrayList<>();
        List<Hotel> savedHotels = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        int lineNumber = 0;
        
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(file.getInputStream()))) {
            String line;
            // Skip header line
            reader.readLine();
            lineNumber = 1;
            
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                logger.info("Processing line {}: {}", lineNumber, line);
                
                try {
                    // Handle quoted CSV values
                    String[] data = parseCSVLine(line);
                    if (data.length < 7) { // Minimum required fields
                        String error = "Line " + lineNumber + " has insufficient fields: " + data.length + " (needs at least 7)";
                        logger.warn(error);
                        errors.add(error);
                        continue;
                    }
                    
                    Hotel hotel = new Hotel();
                    hotel.setHotelName(data[0].trim());
                    hotel.setEmail1(data[1].trim());
                    hotel.setEmail2(data.length > 2 ? (data[2].trim().isEmpty() ? null : data[2].trim()) : null);
                    hotel.setAddress(data[3].trim());
                    hotel.setMobilePhoneContact(data[4].trim());
                    hotel.setLandlineContact(data.length > 5 ? (data[5].trim().isEmpty() ? null : data[5].trim()) : null);
                    hotel.setConcerningPersonName(data.length > 6 ? data[6].trim() : "Not Specified");
                    
                    try {
                        hotel.setPreferred(data.length > 7 ? Boolean.parseBoolean(data[7].trim()) : false);
                    } catch (Exception e) {
                        logger.warn("Invalid boolean value for 'preferred' at line {}: '{}'. Setting to false.", 
                            lineNumber, data.length > 7 ? data[7] : "not provided");
                        hotel.setPreferred(false);
                    }
                    
                    hotel.setCity(data.length > 8 ? data[8].trim() : "");
                    hotel.setState(data.length > 9 ? data[9].trim() : "");
                    hotel.setWebsite(data.length > 10 ? (data[10].trim().isEmpty() ? null : data[10].trim()) : null);
                    
                    // Validate required fields
                    List<String> missingFields = validateHotel(hotel);
                    if (missingFields.isEmpty()) {
                        logger.info("Valid hotel found at line {}: {}", lineNumber, hotel.getHotelName());
                        hotels.add(hotel);
                    } else {
                        String error = String.format("Line %d has invalid hotel data: Missing required fields: %s", 
                            lineNumber, String.join(", ", missingFields));
                        logger.warn(error);
                        errors.add(error);
                    }
                } catch (Exception e) {
                    String error = "Error processing line " + lineNumber + ": " + e.getMessage();
                    logger.error(error, e);
                    errors.add(error);
                }
            }
        }
        
        if (hotels.isEmpty()) {
            logger.warn("No valid hotels found in CSV file. Errors: {}", errors);
            throw new IOException("No valid hotels found in the CSV file. Errors: " + String.join("; ", errors));
        }
        
        logger.info("Saving {} valid hotels to database", hotels.size());
        
        // Save hotels individually to handle duplicates gracefully
        for (Hotel hotel : hotels) {
            try {
                // Check for existing hotel with same email1
                Optional<Hotel> existingHotel = hotelRepository.findByEmail1(hotel.getEmail1());
                if (existingHotel.isPresent()) {
                    // Update existing hotel instead of creating new one
                    Hotel existing = existingHotel.get();
                    existing.setHotelName(hotel.getHotelName());
                    existing.setEmail2(hotel.getEmail2());
                    existing.setAddress(hotel.getAddress());
                    existing.setMobilePhoneContact(hotel.getMobilePhoneContact());
                    existing.setLandlineContact(hotel.getLandlineContact());
                    existing.setConcerningPersonName(hotel.getConcerningPersonName());
                    existing.setPreferred(hotel.isPreferred());
                    existing.setCity(hotel.getCity());
                    existing.setState(hotel.getState());
                    existing.setWebsite(hotel.getWebsite());
                    
                    Hotel savedHotel = hotelRepository.save(existing);
                    savedHotels.add(savedHotel);
                    logger.info("Updated existing hotel: {}", hotel.getHotelName());
                } else {
                    Hotel savedHotel = hotelRepository.save(hotel);
                    savedHotels.add(savedHotel);
                    logger.info("Successfully saved new hotel: {}", hotel.getHotelName());
                }
            } catch (Exception e) {
                String errorMsg = e.getMessage();
                logger.error("Error saving hotel: " + hotel.getHotelName(), e);
                errors.add("Error saving: " + hotel.getHotelName() + " - " + e.getMessage());
            }
        }
        
        if (savedHotels.isEmpty()) {
            throw new IOException("Could not save any hotels. " + String.join("; ", errors));
        }
        
        logger.info("Successfully saved {}/{} hotels", savedHotels.size(), hotels.size());
        if (!errors.isEmpty()) {
            logger.warn("Some hotels were not saved: {}", errors);
        }
        
        return savedHotels;
    }
    
    private String[] parseCSVLine(String line) {
        List<String> result = new ArrayList<>();
        boolean inQuotes = false;
        StringBuilder current = new StringBuilder();
        
        for (char c : line.toCharArray()) {
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                result.add(current.toString().trim());
                current = new StringBuilder();
            } else {
                current.append(c);
            }
        }
        result.add(current.toString().trim());
        
        return result.toArray(new String[0]);
    }
    
    private List<String> validateHotel(Hotel hotel) {
        List<String> missingFields = new ArrayList<>();
        
        // Check required fields
        if (hotel.getHotelName() == null || hotel.getHotelName().trim().isEmpty()) {
            missingFields.add("hotelName");
        }
        if (hotel.getEmail1() == null || hotel.getEmail1().trim().isEmpty()) {
            missingFields.add("email1");
        }
        if (hotel.getMobilePhoneContact() == null || hotel.getMobilePhoneContact().trim().isEmpty()) {
            missingFields.add("mobilePhoneContact");
        }
        if (hotel.getAddress() == null || hotel.getAddress().trim().isEmpty()) {
            missingFields.add("address");
        }
        if (hotel.getCity() == null || hotel.getCity().trim().isEmpty()) {
            missingFields.add("city");
        }
        if (hotel.getState() == null || hotel.getState().trim().isEmpty()) {
            missingFields.add("state");
        }
        
        // concerningPersonName is optional
        if (hotel.getConcerningPersonName() == null || hotel.getConcerningPersonName().trim().isEmpty()) {
            hotel.setConcerningPersonName("Not Specified");
        }
        
        return missingFields;
    }
}
