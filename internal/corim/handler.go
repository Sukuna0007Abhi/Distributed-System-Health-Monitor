package corim

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
)

// Handler provides REST API endpoints for CoRIM profile management
type Handler struct {
	provisioner *Provisioner
	parser      *Parser
	metrics     *Metrics
	logger      Logger
	maxFileSize int64
	uploadDir   string
}

// NewHandler creates a new CoRIM HTTP handler
func NewHandler(provisioner *Provisioner, parser *Parser, metrics *Metrics, logger Logger, maxFileSize int64, uploadDir string) *Handler {
	return &Handler{
		provisioner: provisioner,
		parser:      parser,
		metrics:     metrics,
		logger:      logger,
		maxFileSize: maxFileSize,
		uploadDir:   uploadDir,
	}
}

// RegisterRoutes registers CoRIM API routes with the Gin router
func (h *Handler) RegisterRoutes(r *gin.RouterGroup) {
	corimGroup := r.Group("/corim")
	{
		// Profile management endpoints
		corimGroup.POST("/profiles", h.UploadProfile)
		corimGroup.GET("/profiles", h.ListProfiles)
		corimGroup.GET("/profiles/:id", h.GetProfile)
		corimGroup.DELETE("/profiles/:id", h.DeleteProfile)
		corimGroup.PUT("/profiles/:id/refresh", h.RefreshProfile)
		
		// Reference value query endpoints
		corimGroup.GET("/reference-values", h.QueryReferenceValues)
		corimGroup.GET("/reference-values/:key", h.GetReferenceValue)
		
		// Statistics and monitoring endpoints
		corimGroup.GET("/stats", h.GetGlobalStats)
		corimGroup.GET("/profiles/:id/stats", h.GetProfileStats)
		
		// Health check
		corimGroup.GET("/health", h.HealthCheck)
	}
}

// ProfileUploadRequest represents the request structure for profile upload
type ProfileUploadRequest struct {
	Name        string            `form:"name"`
	Description string            `form:"description"`
	Tags        map[string]string `form:"tags"`
}

// ProfileUploadResponse represents the response structure for profile upload
type ProfileUploadResponse struct {
	ProfileID       string        `json:"profile_id"`
	Status          string        `json:"status"`
	RefValuesStored int           `json:"reference_values_stored"`
	Duration        time.Duration `json:"duration"`
	Warnings        []string      `json:"warnings,omitempty"`
	Message         string        `json:"message"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// UploadProfile handles POST /api/v1/corim/profiles
func (h *Handler) UploadProfile(c *gin.Context) {
	ctx := c.Request.Context()
	
	// Parse multipart form
	if err := c.Request.ParseMultipartForm(h.maxFileSize); err != nil {
		h.respondError(c, http.StatusBadRequest, "Failed to parse multipart form", err)
		return
	}
	
	// Get uploaded file
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		h.respondError(c, http.StatusBadRequest, "No file provided or invalid file", err)
		return
	}
	defer file.Close()
	
	// Validate file size
	if header.Size > h.maxFileSize {
		h.respondError(c, http.StatusBadRequest, 
			fmt.Sprintf("File too large: %d bytes (max: %d)", header.Size, h.maxFileSize), nil)
		return
	}
	
	// Validate file extension
	if filepath.Ext(header.Filename) != ".cbor" {
		h.respondError(c, http.StatusBadRequest, "Only .cbor files are supported", nil)
		return
	}
	
	// Read file contents
	data, err := io.ReadAll(file)
	if err != nil {
		h.respondError(c, http.StatusInternalServerError, "Failed to read uploaded file", err)
		return
	}
	
	h.logger.Info("Processing CoRIM profile upload", 
		"filename", header.Filename, 
		"size", header.Size)
	
	// Parse the CoRIM file
	parseResult, err := h.parser.Parse(ctx, data)
	if err != nil {
		h.metrics.IncParseErrors("upload")
		h.respondError(c, http.StatusBadRequest, "Failed to parse CoRIM file", err)
		return
	}
	
	// Parse form data for metadata
	var req ProfileUploadRequest
	if err := c.ShouldBind(&req); err != nil {
		h.logger.Warn("Failed to parse form metadata", "error", err)
		// Continue without metadata
	}
	
	// Update profile metadata from form
	if parseResult.Profile.Metadata != nil {
		if req.Name != "" {
			parseResult.Profile.Name = req.Name
		}
		if req.Description != "" {
			parseResult.Profile.Metadata.Description = req.Description
		}
		parseResult.Profile.Metadata.FilePath = header.Filename
		parseResult.Profile.Metadata.FileSize = header.Size
	}
	
	// Provision the profile
	provisionResult, err := h.provisioner.ProvisionProfile(ctx, parseResult.Profile)
	if err != nil {
		h.respondError(c, http.StatusInternalServerError, "Failed to provision CoRIM profile", err)
		return
	}
	
	// Save file to upload directory if configured
	if h.uploadDir != "" {
		if err := h.saveUploadedFile(header.Filename, data); err != nil {
			h.logger.Warn("Failed to save uploaded file", "error", err)
		}
	}
	
	response := ProfileUploadResponse{
		ProfileID:       provisionResult.ProfileID,
		Status:          "success",
		RefValuesStored: provisionResult.RefValuesStored,
		Duration:        provisionResult.Duration,
		Warnings:        append(parseResult.Warnings, provisionResult.Warnings...),
		Message:         fmt.Sprintf("Profile %s uploaded and provisioned successfully", provisionResult.ProfileID),
	}
	
	h.logger.Info("CoRIM profile uploaded successfully", 
		"profile_id", provisionResult.ProfileID,
		"ref_values_stored", provisionResult.RefValuesStored)
	
	c.JSON(http.StatusOK, response)
}

// ListProfiles handles GET /api/v1/corim/profiles
func (h *Handler) ListProfiles(c *gin.Context) {
	ctx := c.Request.Context()
	
	profiles, err := h.provisioner.ListProfiles(ctx)
	if err != nil {
		h.respondError(c, http.StatusInternalServerError, "Failed to list profiles", err)
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"profiles": profiles,
		"count":    len(profiles),
	})
}

// GetProfile handles GET /api/v1/corim/profiles/:id
func (h *Handler) GetProfile(c *gin.Context) {
	ctx := c.Request.Context()
	profileID := c.Param("id")
	
	if profileID == "" {
		h.respondError(c, http.StatusBadRequest, "Profile ID is required", nil)
		return
	}
	
	profile, err := h.provisioner.GetProfile(ctx, profileID)
	if err != nil {
		if IsProfileNotFound(err) {
			h.respondError(c, http.StatusNotFound, fmt.Sprintf("Profile %s not found", profileID), err)
		} else {
			h.respondError(c, http.StatusInternalServerError, "Failed to retrieve profile", err)
		}
		return
	}
	
	c.JSON(http.StatusOK, profile)
}

// DeleteProfile handles DELETE /api/v1/corim/profiles/:id
func (h *Handler) DeleteProfile(c *gin.Context) {
	ctx := c.Request.Context()
	profileID := c.Param("id")
	
	if profileID == "" {
		h.respondError(c, http.StatusBadRequest, "Profile ID is required", nil)
		return
	}
	
	err := h.provisioner.DeleteProfile(ctx, profileID)
	if err != nil {
		if IsProfileNotFound(err) {
			h.respondError(c, http.StatusNotFound, fmt.Sprintf("Profile %s not found", profileID), err)
		} else {
			h.respondError(c, http.StatusInternalServerError, "Failed to delete profile", err)
		}
		return
	}
	
	h.logger.Info("CoRIM profile deleted", "profile_id", profileID)
	
	c.JSON(http.StatusOK, gin.H{
		"status":     "success",
		"message":    fmt.Sprintf("Profile %s deleted successfully", profileID),
		"profile_id": profileID,
	})
}

// RefreshProfile handles PUT /api/v1/corim/profiles/:id/refresh
func (h *Handler) RefreshProfile(c *gin.Context) {
	ctx := c.Request.Context()
	profileID := c.Param("id")
	
	if profileID == "" {
		h.respondError(c, http.StatusBadRequest, "Profile ID is required", nil)
		return
	}
	
	result, err := h.provisioner.RefreshProfile(ctx, profileID)
	if err != nil {
		if IsProfileNotFound(err) {
			h.respondError(c, http.StatusNotFound, fmt.Sprintf("Profile %s not found", profileID), err)
		} else {
			h.respondError(c, http.StatusInternalServerError, "Failed to refresh profile", err)
		}
		return
	}
	
	h.logger.Info("CoRIM profile refreshed", "profile_id", profileID)
	
	c.JSON(http.StatusOK, gin.H{
		"status":               "success",
		"message":              fmt.Sprintf("Profile %s refreshed successfully", profileID),
		"profile_id":           result.ProfileID,
		"reference_values_stored": result.RefValuesStored,
		"duration":            result.Duration,
		"warnings":            result.Warnings,
	})
}

// QueryReferenceValues handles GET /api/v1/corim/reference-values
func (h *Handler) QueryReferenceValues(c *gin.Context) {
	ctx := c.Request.Context()
	
	// Parse query parameters
	environmentClass := c.Query("environment_class")
	environmentInstance := c.Query("environment_instance")
	
	if environmentClass == "" {
		h.respondError(c, http.StatusBadRequest, "environment_class parameter is required", nil)
		return
	}
	
	envID := &EnvironmentIdentifier{
		Class:    environmentClass,
		Instance: environmentInstance,
	}
	
	// Add optional query parameters
	if vendor := c.Query("vendor"); vendor != "" {
		envID.Vendor = vendor
	}
	if model := c.Query("model"); model != "" {
		envID.Model = model
	}
	
	queryResult, err := h.provisioner.GetReferenceValues(ctx, envID)
	if err != nil {
		h.respondError(c, http.StatusInternalServerError, "Failed to query reference values", err)
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"reference_values": queryResult.Values,
		"environment":      queryResult.Environment,
		"count":           queryResult.Count,
		"query_time":      queryResult.QueryTime,
	})
}

// GetReferenceValue handles GET /api/v1/corim/reference-values/:key
func (h *Handler) GetReferenceValue(c *gin.Context) {
	ctx := c.Request.Context()
	key := c.Param("key")
	
	if key == "" {
		h.respondError(c, http.StatusBadRequest, "Reference value key is required", nil)
		return
	}
	
	refValue, err := h.provisioner.GetReferenceValue(ctx, key)
	if err != nil {
		if IsProfileNotFound(err) {
			h.respondError(c, http.StatusNotFound, fmt.Sprintf("Reference value %s not found", key), err)
		} else {
			h.respondError(c, http.StatusInternalServerError, "Failed to retrieve reference value", err)
		}
		return
	}
	
	c.JSON(http.StatusOK, refValue)
}

// GetGlobalStats handles GET /api/v1/corim/stats
func (h *Handler) GetGlobalStats(c *gin.Context) {
	ctx := c.Request.Context()
	
	stats, err := h.provisioner.GetGlobalStats(ctx)
	if err != nil {
		h.respondError(c, http.StatusInternalServerError, "Failed to retrieve statistics", err)
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"stats":      stats,
		"timestamp":  time.Now(),
	})
}

// GetProfileStats handles GET /api/v1/corim/profiles/:id/stats
func (h *Handler) GetProfileStats(c *gin.Context) {
	ctx := c.Request.Context()
	profileID := c.Param("id")
	
	if profileID == "" {
		h.respondError(c, http.StatusBadRequest, "Profile ID is required", nil)
		return
	}
	
	stats, err := h.provisioner.GetProfileStats(ctx, profileID)
	if err != nil {
		if IsProfileNotFound(err) {
			h.respondError(c, http.StatusNotFound, fmt.Sprintf("Profile %s not found", profileID), err)
		} else {
			h.respondError(c, http.StatusInternalServerError, "Failed to retrieve profile statistics", err)
		}
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"stats":      stats,
		"timestamp":  time.Now(),
	})
}

// HealthCheck handles GET /api/v1/corim/health
func (h *Handler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now(),
		"service":   "corim-handler",
	})
}

// Helper methods

// respondError sends a structured error response
func (h *Handler) respondError(c *gin.Context, statusCode int, message string, err error) {
	response := ErrorResponse{
		Error:   message,
		Code:    statusCode,
		Message: message,
	}
	
	if err != nil {
		h.logger.Error("API error", "message", message, "error", err, "status", statusCode)
		response.Message = fmt.Sprintf("%s: %v", message, err)
	} else {
		h.logger.Warn("API error", "message", message, "status", statusCode)
	}
	
	c.JSON(statusCode, response)
}

// saveUploadedFile saves the uploaded file to the upload directory
func (h *Handler) saveUploadedFile(filename string, data []byte) error {
	if h.uploadDir == "" {
		return nil
	}
	
	// Ensure upload directory exists
	if err := os.MkdirAll(h.uploadDir, 0755); err != nil {
		return fmt.Errorf("failed to create upload directory: %w", err)
	}
	
	// Generate unique filename
	timestamp := time.Now().Format("20060102_150405")
	safeFilename := fmt.Sprintf("%s_%s", timestamp, filepath.Base(filename))
	filePath := filepath.Join(h.uploadDir, safeFilename)
	
	// Write file
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	
	h.logger.Info("Uploaded file saved", "path", filePath)
	return nil
}

// Middleware for request validation, logging, etc.

// ValidateContentType middleware ensures the correct content type for file uploads
func (h *Handler) ValidateContentType() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "POST" && c.FullPath() == "/api/v1/corim/profiles" {
			contentType := c.GetHeader("Content-Type")
			if contentType != "" && contentType != "multipart/form-data" {
				if !gin.IsDebugging() {
					h.respondError(c, http.StatusUnsupportedMediaType, 
						"Content-Type must be multipart/form-data for file uploads", nil)
					c.Abort()
					return
				}
			}
		}
		c.Next()
	}
}

// RequestLogging middleware logs API requests
func (h *Handler) RequestLogging() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("[CoRIM-API] %v | %3d | %13v | %15s | %-7s %#v\n",
			param.TimeStamp.Format("2006/01/02 - 15:04:05"),
			param.StatusCode,
			param.Latency,
			param.ClientIP,
			param.Method,
			param.Path,
		)
	})
}

// RateLimiting middleware (basic implementation)
func (h *Handler) RateLimiting() gin.HandlerFunc {
	// This is a simplified rate limiting implementation
	// In production, use a proper rate limiting library
	return func(c *gin.Context) {
		// Add rate limiting logic here
		c.Next()
	}
}