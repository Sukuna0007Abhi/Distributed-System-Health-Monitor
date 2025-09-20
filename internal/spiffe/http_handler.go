package spiffe

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// SPIFFEHandler provides HTTP handlers for SPIFFE operations
type SPIFFEHandler struct {
	manager SPIFFEManager
	logger  *logrus.Logger
	meter   metric.Meter
	
	// Metrics
	requestsTotal    metric.Int64Counter
	requestDuration  metric.Float64Histogram
	validationsTotal metric.Int64Counter
	errorsTotal      metric.Int64Counter
}

// NewSPIFFEHandler creates a new SPIFFE HTTP handler
func NewSPIFFEHandler(manager SPIFFEManager, logger *logrus.Logger) *SPIFFEHandler {
	meter := otel.Meter("spiffe_handler")
	
	requestsTotal, _ := meter.Int64Counter(
		"spiffe_requests_total",
		metric.WithDescription("Total number of SPIFFE API requests"),
	)
	
	requestDuration, _ := meter.Float64Histogram(
		"spiffe_request_duration_seconds",
		metric.WithDescription("Duration of SPIFFE API requests"),
	)
	
	validationsTotal, _ := meter.Int64Counter(
		"spiffe_validations_total",
		metric.WithDescription("Total number of SPIFFE ID validations"),
	)
	
	errorsTotal, _ := meter.Int64Counter(
		"spiffe_errors_total",
		metric.WithDescription("Total number of SPIFFE API errors"),
	)
	
	return &SPIFFEHandler{
		manager:          manager,
		logger:           logger,
		meter:           meter,
		requestsTotal:   requestsTotal,
		requestDuration: requestDuration,
		validationsTotal: validationsTotal,
		errorsTotal:     errorsTotal,
	}
}

// RegisterRoutes registers SPIFFE API routes
func (h *SPIFFEHandler) RegisterRoutes(r *gin.Engine) {
	spiffeGroup := r.Group("/api/v1/spiffe")
	{
		// Identity management
		spiffeGroup.GET("/identity", h.GetIdentity)
		spiffeGroup.GET("/svid/x509", h.GetX509SVID)
		spiffeGroup.POST("/svid/jwt", h.GetJWTSVID)
		
		// Validation
		spiffeGroup.POST("/validate", h.ValidateSPIFFEID)
		spiffeGroup.GET("/validate/:spiffe_id", h.ValidateSPIFFEIDByPath)
		
		// Workload management
		spiffeGroup.GET("/workloads", h.ListWorkloads)
		spiffeGroup.GET("/workloads/:workload_id", h.GetWorkload)
		spiffeGroup.POST("/workloads", h.RegisterWorkload)
		spiffeGroup.PUT("/workloads/:workload_id", h.UpdateWorkload)
		spiffeGroup.DELETE("/workloads/:workload_id", h.UnregisterWorkload)
		
		// Attestation
		spiffeGroup.GET("/workloads/:workload_id/attestation", h.GetWorkloadAttestation)
		spiffeGroup.POST("/workloads/:workload_id/attest", h.AttestWorkload)
		
		// Trust domain information
		spiffeGroup.GET("/trust-domain", h.GetTrustDomain)
		spiffeGroup.GET("/federation", h.GetFederationInfo)
		
		// Health and status
		spiffeGroup.GET("/health", h.Health)
		spiffeGroup.GET("/status", h.Status)
	}
}

// GetIdentity returns the current workload identity
func (h *SPIFFEHandler) GetIdentity(c *gin.Context) {
	start := time.Now()
	defer h.recordMetrics("get_identity", start, c)
	
	ctx := c.Request.Context()
	
	// Get X.509 SVID
	svid, err := h.manager.GetX509SVID(ctx)
	if err != nil {
		h.handleError(c, http.StatusInternalServerError, "Failed to get X.509 SVID", err)
		return
	}
	
	// Extract certificate information
	cert := svid.Certificates[0]
	
	response := gin.H{
		"spiffe_id":    svid.ID.String(),
		"trust_domain": h.manager.GetTrustDomain().String(),
		"subject":      cert.Subject.String(),
		"issuer":       cert.Issuer.String(),
		"serial":       cert.SerialNumber.String(),
		"not_before":   cert.NotBefore,
		"not_after":    cert.NotAfter,
		"dns_names":    cert.DNSNames,
		"ip_addresses": cert.IPAddresses,
		"key_usage":    getKeyUsageStrings(cert.KeyUsage),
		"ext_key_usage": getExtKeyUsageStrings(cert.ExtKeyUsage),
	}
	
	c.JSON(http.StatusOK, response)
}

// GetX509SVID returns the X.509 SVID in PEM format
func (h *SPIFFEHandler) GetX509SVID(c *gin.Context) {
	start := time.Now()
	defer h.recordMetrics("get_x509_svid", start, c)
	
	ctx := c.Request.Context()
	
	svid, err := h.manager.GetX509SVID(ctx)
	if err != nil {
		h.handleError(c, http.StatusInternalServerError, "Failed to get X.509 SVID", err)
		return
	}
	
	// Return as PEM or JSON based on Accept header
	if c.GetHeader("Accept") == "application/x-pem-file" {
		pemData, err := svid.Marshal()
		if err != nil {
			h.handleError(c, http.StatusInternalServerError, "Failed to marshal SVID", err)
			return
		}
		
		c.Header("Content-Type", "application/x-pem-file")
		c.Header("Content-Disposition", "attachment; filename=\"svid.pem\"")
		c.Data(http.StatusOK, "application/x-pem-file", pemData)
		return
	}
	
	// Return as JSON
	response := gin.H{
		"spiffe_id":  svid.ID.String(),
		"not_after":  svid.Certificates[0].NotAfter,
		"hint":       svid.Hint,
		"cert_count": len(svid.Certificates),
	}
	
	c.JSON(http.StatusOK, response)
}

// GetJWTSVID returns a JWT SVID for specified audiences
func (h *SPIFFEHandler) GetJWTSVID(c *gin.Context) {
	start := time.Now()
	defer h.recordMetrics("get_jwt_svid", start, c)
	
	ctx := c.Request.Context()
	
	var request struct {
		Audiences []string `json:"audiences" binding:"required"`
		ExtraAudiences []string `json:"extra_audiences"`
	}
	
	if err := c.ShouldBindJSON(&request); err != nil {
		h.handleError(c, http.StatusBadRequest, "Invalid request", err)
		return
	}
	
	// Combine audiences
	allAudiences := append(request.Audiences, request.ExtraAudiences...)
	
	svid, err := h.manager.GetJWTSVID(ctx, allAudiences)
	if err != nil {
		h.handleError(c, http.StatusInternalServerError, "Failed to get JWT SVID", err)
		return
	}
	
	response := gin.H{
		"token":     svid.Marshal(),
		"spiffe_id": svid.ID.String(),
		"audiences": svid.Audience,
		"expiry":    svid.Expiry,
		"hint":      svid.Hint,
	}
	
	c.JSON(http.StatusOK, response)
}

// ValidateSPIFFEID validates a SPIFFE ID
func (h *SPIFFEHandler) ValidateSPIFFEID(c *gin.Context) {
	start := time.Now()
	defer h.recordMetrics("validate_spiffe_id", start, c)
	
	ctx := c.Request.Context()
	
	var request struct {
		SPIFFEID string `json:"spiffe_id" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&request); err != nil {
		h.handleError(c, http.StatusBadRequest, "Invalid request", err)
		return
	}
	
	result, err := h.manager.ValidateSPIFFEID(ctx, request.SPIFFEID)
	if err != nil {
		h.handleError(c, http.StatusInternalServerError, "Validation failed", err)
		return
	}
	
	// Record validation metrics
	h.validationsTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("spiffe_id", request.SPIFFEID),
		attribute.Bool("valid", result.Valid),
		attribute.String("trust_level", result.TrustLevel.String()),
	))
	
	c.JSON(http.StatusOK, result)
}

// ValidateSPIFFEIDByPath validates a SPIFFE ID passed as URL path parameter
func (h *SPIFFEHandler) ValidateSPIFFEIDByPath(c *gin.Context) {
	spiffeID := c.Param("spiffe_id")
	
	// URL decode the SPIFFE ID
	if decoded, err := c.Request.URL.QueryUnescape(spiffeID); err == nil {
		spiffeID = decoded
	}
	
	ctx := c.Request.Context()
	
	result, err := h.manager.ValidateSPIFFEID(ctx, spiffeID)
	if err != nil {
		h.handleError(c, http.StatusInternalServerError, "Validation failed", err)
		return
	}
	
	c.JSON(http.StatusOK, result)
}

// ListWorkloads returns all registered workloads
func (h *SPIFFEHandler) ListWorkloads(c *gin.Context) {
	start := time.Now()
	defer h.recordMetrics("list_workloads", start, c)
	
	// Parse query parameters
	limitStr := c.DefaultQuery("limit", "100")
	offsetStr := c.DefaultQuery("offset", "0")
	status := c.Query("status")
	
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 100
	}
	
	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}
	
	// For demonstration, return mock workloads
	// In a real implementation, this would query the workload registry
	workloads := []gin.H{
		{
			"workload_id": "web-server-1",
			"spiffe_id":   fmt.Sprintf("spiffe://%s/web/server", h.manager.GetTrustDomain().String()),
			"status":      "active",
			"created_at":  time.Now().Add(-24 * time.Hour),
			"updated_at":  time.Now(),
		},
		{
			"workload_id": "database-1",
			"spiffe_id":   fmt.Sprintf("spiffe://%s/db/postgres", h.manager.GetTrustDomain().String()),
			"status":      "active",
			"created_at":  time.Now().Add(-48 * time.Hour),
			"updated_at":  time.Now().Add(-1 * time.Hour),
		},
	}
	
	// Filter by status if specified
	if status != "" {
		filtered := make([]gin.H, 0)
		for _, workload := range workloads {
			if workload["status"] == status {
				filtered = append(filtered, workload)
			}
		}
		workloads = filtered
	}
	
	// Apply pagination
	total := len(workloads)
	end := offset + limit
	if end > total {
		end = total
	}
	
	if offset >= total {
		workloads = []gin.H{}
	} else {
		workloads = workloads[offset:end]
	}
	
	response := gin.H{
		"workloads": workloads,
		"total":     total,
		"limit":     limit,
		"offset":    offset,
	}
	
	c.JSON(http.StatusOK, response)
}

// GetWorkload returns a specific workload
func (h *SPIFFEHandler) GetWorkload(c *gin.Context) {
	start := time.Now()
	defer h.recordMetrics("get_workload", start, c)
	
	workloadID := c.Param("workload_id")
	ctx := c.Request.Context()
	
	workload, err := h.manager.GetWorkloadAttestation(ctx, workloadID)
	if err != nil {
		h.handleError(c, http.StatusNotFound, "Workload not found", err)
		return
	}
	
	c.JSON(http.StatusOK, workload)
}

// RegisterWorkload registers a new workload
func (h *SPIFFEHandler) RegisterWorkload(c *gin.Context) {
	start := time.Now()
	defer h.recordMetrics("register_workload", start, c)
	
	ctx := c.Request.Context()
	
	var registration WorkloadRegistration
	if err := c.ShouldBindJSON(&registration); err != nil {
		h.handleError(c, http.StatusBadRequest, "Invalid registration request", err)
		return
	}
	
	// Validate required fields
	if registration.WorkloadID == "" {
		h.handleError(c, http.StatusBadRequest, "workload_id is required", nil)
		return
	}
	
	if registration.SPIFFEID == "" {
		h.handleError(c, http.StatusBadRequest, "spiffe_id is required", nil)
		return
	}
	
	// Set defaults
	if registration.TTL == 0 {
		registration.TTL = 24 * time.Hour
	}
	
	if err := h.manager.RegisterWorkload(ctx, &registration); err != nil {
		h.handleError(c, http.StatusInternalServerError, "Failed to register workload", err)
		return
	}
	
	h.logger.WithFields(logrus.Fields{
		"workload_id": registration.WorkloadID,
		"spiffe_id":   registration.SPIFFEID,
	}).Info("Workload registered via API")
	
	response := gin.H{
		"message":     "Workload registered successfully",
		"workload_id": registration.WorkloadID,
		"spiffe_id":   registration.SPIFFEID,
		"ttl":         registration.TTL.String(),
	}
	
	c.JSON(http.StatusCreated, response)
}

// UpdateWorkload updates an existing workload
func (h *SPIFFEHandler) UpdateWorkload(c *gin.Context) {
	start := time.Now()
	defer h.recordMetrics("update_workload", start, c)
	
	workloadID := c.Param("workload_id")
	
	var update struct {
		TTL           *time.Duration     `json:"ttl"`
		Selectors     []WorkloadSelector `json:"selectors"`
		FederatesWith []string          `json:"federates_with"`
		Status        *string           `json:"status"`
	}
	
	if err := c.ShouldBindJSON(&update); err != nil {
		h.handleError(c, http.StatusBadRequest, "Invalid update request", err)
		return
	}
	
	// For demonstration, return success
	// In a real implementation, this would update the workload in the registry
	response := gin.H{
		"message":     "Workload updated successfully",
		"workload_id": workloadID,
		"updated_at":  time.Now(),
	}
	
	c.JSON(http.StatusOK, response)
}

// UnregisterWorkload removes a workload registration
func (h *SPIFFEHandler) UnregisterWorkload(c *gin.Context) {
	start := time.Now()
	defer h.recordMetrics("unregister_workload", start, c)
	
	workloadID := c.Param("workload_id")
	
	// For demonstration, return success
	// In a real implementation, this would remove the workload from the registry
	response := gin.H{
		"message":      "Workload unregistered successfully",
		"workload_id":  workloadID,
		"unregistered_at": time.Now(),
	}
	
	h.logger.WithField("workload_id", workloadID).Info("Workload unregistered via API")
	
	c.JSON(http.StatusOK, response)
}

// GetWorkloadAttestation returns workload attestation data
func (h *SPIFFEHandler) GetWorkloadAttestation(c *gin.Context) {
	start := time.Now()
	defer h.recordMetrics("get_workload_attestation", start, c)
	
	workloadID := c.Param("workload_id")
	ctx := c.Request.Context()
	
	attestation, err := h.manager.GetWorkloadAttestation(ctx, workloadID)
	if err != nil {
		h.handleError(c, http.StatusNotFound, "Workload attestation not found", err)
		return
	}
	
	c.JSON(http.StatusOK, attestation)
}

// AttestWorkload performs workload attestation
func (h *SPIFFEHandler) AttestWorkload(c *gin.Context) {
	start := time.Now()
	defer h.recordMetrics("attest_workload", start, c)
	
	workloadID := c.Param("workload_id")
	ctx := c.Request.Context()
	
	var request struct {
		AttestationData map[string]interface{} `json:"attestation_data"`
		TTL             time.Duration          `json:"ttl"`
	}
	
	if err := c.ShouldBindJSON(&request); err != nil {
		h.handleError(c, http.StatusBadRequest, "Invalid attestation request", err)
		return
	}
	
	// Set default TTL
	if request.TTL == 0 {
		request.TTL = time.Hour
	}
	
	// For demonstration, create a mock SVID response
	svidResponse, err := h.manager.CreateWorkloadSVID(ctx, workloadID, request.TTL)
	if err != nil {
		h.handleError(c, http.StatusInternalServerError, "Failed to create workload SVID", err)
		return
	}
	
	response := gin.H{
		"workload_id":  workloadID,
		"svid_created": true,
		"spiffe_id":    svidResponse.SPIFFEID,
		"ttl":          svidResponse.TTL.String(),
		"expires_at":   svidResponse.ExpiresAt,
		"created_at":   svidResponse.CreatedAt,
	}
	
	c.JSON(http.StatusOK, response)
}

// GetTrustDomain returns trust domain information
func (h *SPIFFEHandler) GetTrustDomain(c *gin.Context) {
	start := time.Now()
	defer h.recordMetrics("get_trust_domain", start, c)
	
	trustDomain := h.manager.GetTrustDomain()
	
	response := gin.H{
		"trust_domain": trustDomain.String(),
		"name":         trustDomain.Name(),
	}
	
	c.JSON(http.StatusOK, response)
}

// GetFederationInfo returns federation information
func (h *SPIFFEHandler) GetFederationInfo(c *gin.Context) {
	start := time.Now()
	defer h.recordMetrics("get_federation_info", start, c)
	
	// For demonstration, return mock federation info
	response := gin.H{
		"trust_domain": h.manager.GetTrustDomain().String(),
		"federated_with": []gin.H{
			{
				"trust_domain": "partner.local",
				"status":       "active",
				"established":  time.Now().Add(-30 * 24 * time.Hour),
			},
			{
				"trust_domain": "vendor.local",
				"status":       "pending",
				"established":  nil,
			},
		},
		"federation_count": 2,
	}
	
	c.JSON(http.StatusOK, response)
}

// Health returns SPIFFE service health status
func (h *SPIFFEHandler) Health(c *gin.Context) {
	ctx := c.Request.Context()
	
	// Check if we can get current SVID
	_, err := h.manager.GetX509SVID(ctx)
	if err != nil {
		response := gin.H{
			"status":    "unhealthy",
			"error":     err.Error(),
			"timestamp": time.Now(),
		}
		c.JSON(http.StatusServiceUnavailable, response)
		return
	}
	
	response := gin.H{
		"status":      "healthy",
		"trust_domain": h.manager.GetTrustDomain().String(),
		"timestamp":   time.Now(),
	}
	
	c.JSON(http.StatusOK, response)
}

// Status returns detailed SPIFFE service status
func (h *SPIFFEHandler) Status(c *gin.Context) {
	start := time.Now()
	defer h.recordMetrics("get_status", start, c)
	
	ctx := c.Request.Context()
	
	// Get current SVID info
	svid, err := h.manager.GetX509SVID(ctx)
	var svidInfo gin.H
	if err != nil {
		svidInfo = gin.H{
			"available": false,
			"error":     err.Error(),
		}
	} else {
		cert := svid.Certificates[0]
		svidInfo = gin.H{
			"available":  true,
			"spiffe_id":  svid.ID.String(),
			"not_before": cert.NotBefore,
			"not_after":  cert.NotAfter,
			"serial":     cert.SerialNumber.String(),
		}
	}
	
	response := gin.H{
		"trust_domain": h.manager.GetTrustDomain().String(),
		"svid":         svidInfo,
		"workloads": gin.H{
			"registered": 2, // Mock count
			"active":     2,
			"inactive":   0,
		},
		"uptime":     time.Since(start).String(),
		"timestamp":  time.Now(),
	}
	
	c.JSON(http.StatusOK, response)
}

// Helper methods

func (h *SPIFFEHandler) handleError(c *gin.Context, statusCode int, message string, err error) {
	h.errorsTotal.Add(c.Request.Context(), 1, metric.WithAttributes(
		attribute.String("endpoint", c.FullPath()),
		attribute.Int("status_code", statusCode),
	))
	
	response := gin.H{
		"error":     message,
		"timestamp": time.Now(),
	}
	
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"endpoint":    c.FullPath(),
			"method":      c.Request.Method,
			"status_code": statusCode,
		}).Error(message)
		
		response["details"] = err.Error()
	}
	
	c.JSON(statusCode, response)
}

func (h *SPIFFEHandler) recordMetrics(operation string, start time.Time, c *gin.Context) {
	duration := time.Since(start).Seconds()
	
	attrs := []attribute.KeyValue{
		attribute.String("operation", operation),
		attribute.String("method", c.Request.Method),
	}
	
	h.requestsTotal.Add(c.Request.Context(), 1, metric.WithAttributes(attrs...))
	h.requestDuration.Record(c.Request.Context(), duration, metric.WithAttributes(attrs...))
}

func getKeyUsageStrings(usage x509.KeyUsage) []string {
	var usages []string
	
	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "digital_signature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "content_commitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "key_encipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "data_encipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "key_agreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "cert_sign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "crl_sign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "encipher_only")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "decipher_only")
	}
	
	return usages
}

func getExtKeyUsageStrings(usage []x509.ExtKeyUsage) []string {
	var usages []string
	
	for _, u := range usage {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "server_auth")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "client_auth")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "code_signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "email_protection")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "time_stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "ocsp_signing")
		}
	}
	
	return usages
}
