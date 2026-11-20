package com.tanvi.auth.repository;

import com.tanvi.auth.domain.RefreshToken;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    @EntityGraph(attributePaths = "user")
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /** Is this session (token family) still signed in? Checked on every authenticated request. */
    @Query("""
            SELECT COUNT(t) > 0 FROM RefreshToken t
            WHERE t.familyId = :familyId AND t.revokedAt IS NULL AND t.expiresAt > :now
            """)
    boolean isFamilyActive(@Param("familyId") String familyId, @Param("now") Instant now);

    /** One row per signed-in session: the current (not yet rotated) token of each family. */
    @Query("""
            SELECT t FROM RefreshToken t
            WHERE t.user.id = :userId AND t.revokedAt IS NULL AND t.expiresAt > :now
            ORDER BY t.createdAt DESC
            """)
    List<RefreshToken> findActiveByUser(@Param("userId") Long userId, @Param("now") Instant now);

    @Query("""
            SELECT COUNT(t) FROM RefreshToken t
            WHERE t.user.id = :userId AND t.revokedAt IS NULL AND t.expiresAt > :now
            """)
    long countActiveByUser(@Param("userId") Long userId, @Param("now") Instant now);

    @Modifying(flushAutomatically = true)
    @Query("""
            UPDATE RefreshToken t SET t.revokedAt = :now, t.revokeReason = :reason
            WHERE t.familyId = :familyId AND t.revokedAt IS NULL
            """)
    int revokeFamily(@Param("familyId") String familyId, @Param("reason") RefreshToken.RevokeReason reason,
                     @Param("now") Instant now);

    @Modifying(flushAutomatically = true)
    @Query("""
            UPDATE RefreshToken t SET t.revokedAt = :now, t.revokeReason = :reason
            WHERE t.user.id = :userId AND t.revokedAt IS NULL
            """)
    int revokeAllForUser(@Param("userId") Long userId, @Param("reason") RefreshToken.RevokeReason reason,
                         @Param("now") Instant now);

    @Modifying
    @Query("DELETE FROM RefreshToken t WHERE t.expiresAt < :cutoff")
    int deleteExpiredBefore(@Param("cutoff") Instant cutoff);
}
