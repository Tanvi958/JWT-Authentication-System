package com.tanvi.auth.repository;

import com.tanvi.auth.domain.Role;
import com.tanvi.auth.domain.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    long countByRoleAndEnabledTrue(Role role);

    @Query("""
            SELECT u FROM User u
            WHERE :q = ''
               OR u.username LIKE CONCAT('%', :q, '%')
               OR u.email LIKE CONCAT('%', :q, '%')
               OR LOWER(u.fullName) LIKE CONCAT('%', :q, '%')
            """)
    Page<User> search(@Param("q") String lowerCaseQuery, Pageable pageable);
}
