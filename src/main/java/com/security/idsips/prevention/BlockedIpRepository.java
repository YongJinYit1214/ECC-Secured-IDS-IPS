package com.security.idsips.prevention;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for BlockedIp entities
 */
@Repository
public interface BlockedIpRepository extends JpaRepository<BlockedIp, Long> {
    
    /**
     * Find blocked IP by IP address
     */
    Optional<BlockedIp> findByIpAddress(String ipAddress);
    
    /**
     * Find all active blocked IPs
     */
    List<BlockedIp> findByStatusOrderByBlockedAtDesc(BlockedIp.BlockStatus status);
    
    /**
     * Find expired blocks
     */
    @Query("SELECT b FROM BlockedIp b WHERE b.expiresAt IS NOT NULL AND b.expiresAt < :now AND b.status = 'ACTIVE'")
    List<BlockedIp> findExpiredBlocks(@Param("now") LocalDateTime now);
    
    /**
     * Find blocks by alert ID
     */
    List<BlockedIp> findByAlertId(String alertId);
    
    /**
     * Count active blocks
     */
    long countByStatus(BlockedIp.BlockStatus status);
    
    /**
     * Find blocks created within time range
     */
    @Query("SELECT b FROM BlockedIp b WHERE b.blockedAt BETWEEN :startTime AND :endTime ORDER BY b.blockedAt DESC")
    List<BlockedIp> findByBlockedAtBetween(@Param("startTime") LocalDateTime startTime, 
                                          @Param("endTime") LocalDateTime endTime);
    
    /**
     * Check if IP is currently blocked
     */
    @Query("SELECT CASE WHEN COUNT(b) > 0 THEN true ELSE false END FROM BlockedIp b " +
           "WHERE b.ipAddress = :ipAddress AND b.status = 'ACTIVE' AND " +
           "(b.expiresAt IS NULL OR b.expiresAt > :now)")
    boolean isIpBlocked(@Param("ipAddress") String ipAddress, @Param("now") LocalDateTime now);
}
