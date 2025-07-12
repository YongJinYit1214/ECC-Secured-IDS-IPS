package com.security.idsips.detection;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for SecurityAlert entities
 */
@Repository
public interface SecurityAlertRepository extends JpaRepository<SecurityAlert, Long> {
    
    /**
     * Find alert by alert ID
     */
    Optional<SecurityAlert> findByAlertId(String alertId);
    
    /**
     * Find alerts by source IP
     */
    List<SecurityAlert> findBySourceIpOrderByTimestampDesc(String sourceIp);
    
    /**
     * Find alerts by status
     */
    List<SecurityAlert> findByStatusOrderByTimestampDesc(SecurityAlert.AlertStatus status);
    
    /**
     * Find alerts by severity
     */
    List<SecurityAlert> findBySeverityOrderByTimestampDesc(SecurityAlert.AlertSeverity severity);
    
    /**
     * Find alerts by alert type
     */
    List<SecurityAlert> findByAlertTypeOrderByTimestampDesc(SecurityAlert.AlertType alertType);
    
    /**
     * Find alerts within time range
     */
    @Query("SELECT a FROM SecurityAlert a WHERE a.timestamp BETWEEN :startTime AND :endTime ORDER BY a.timestamp DESC")
    List<SecurityAlert> findByTimestampBetween(@Param("startTime") LocalDateTime startTime, 
                                              @Param("endTime") LocalDateTime endTime);
    
    /**
     * Count alerts by status
     */
    long countByStatus(SecurityAlert.AlertStatus status);
    
    /**
     * Count alerts by severity
     */
    long countBySeverity(SecurityAlert.AlertSeverity severity);
    
    /**
     * Count alerts created today
     */
    @Query("SELECT COUNT(a) FROM SecurityAlert a WHERE a.timestamp >= CURRENT_DATE")
    long countAlertsToday();
    
    /**
     * Find recent alerts (last 24 hours)
     */
    @Query("SELECT a FROM SecurityAlert a WHERE a.timestamp >= :since ORDER BY a.timestamp DESC")
    List<SecurityAlert> findRecentAlerts(@Param("since") LocalDateTime since);
    
    /**
     * Find top source IPs by alert count
     */
    @Query("SELECT a.sourceIp, COUNT(a) as alertCount FROM SecurityAlert a " +
           "GROUP BY a.sourceIp ORDER BY alertCount DESC")
    List<Object[]> findTopSourceIpsByAlertCount();
}
