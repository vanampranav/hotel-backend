package com.Colombus.HotelManagement.Repositories;

import com.Colombus.HotelManagement.Models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Long> {
    Optional<User> findByUserName(String userName);

    boolean existsByEmail(String email);

    boolean existsByUserName(String userName);
    
    List<User> findByApprovedFalse();

    List<User> findByTerminatedTrue();
    List<User> findByTerminatedFalse();
    Optional<User> findByIdAndTerminatedTrue(Long id);
    Optional<User> findByIdAndTerminatedFalse(Long id);
}
