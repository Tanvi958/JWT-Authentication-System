package com.tanvi.auth.repository;

import com.tanvi.auth.domain.SecurityEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;

public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {

    Page<SecurityEvent> findByType(SecurityEvent.Type type, Pageable pageable);

    List<SecurityEvent> findTop20ByUserIdOrderByOccurredAtDescIdDesc(Long userId);

    @Modifying
    @Query("DELETE FROM SecurityEvent e WHERE e.occurredAt < :cutoff")
    int deleteOlderThan(@Param("cutoff") Instant cutoff);
}
