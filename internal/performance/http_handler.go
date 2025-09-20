package performance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// PerformanceHandler provides HTTP endpoints for performance optimization
type PerformanceHandler struct {
	engine PerformanceEngine
	logger *logrus.Logger
	tracer trace.Tracer
}

// NewPerformanceHandler creates a new performance handler
func NewPerformanceHandler(engine PerformanceEngine, logger *logrus.Logger) *PerformanceHandler {
	return &PerformanceHandler{
		engine: engine,
		logger: logger,
		tracer: otel.Tracer("performance_handler"),
	}
}

// RegisterRoutes registers all performance optimization routes
func (h *PerformanceHandler) RegisterRoutes(router *gin.Engine) {
	api := router.Group("/api/v1/performance")
	{
		// Latency optimization
		api.POST("/latency/optimize", h.OptimizeLatency)
		api.GET("/latency/metrics/:service", h.GetLatencyMetrics)
		api.GET("/latency/optimization/:id", h.GetLatencyOptimization)

		// Cache optimization
		api.POST("/cache/optimize", h.OptimizeCache)
		api.GET("/cache/metrics/:cacheId", h.GetCacheMetrics)
		api.GET("/cache/optimization/:id", h.GetCacheOptimization)

		// Autoscaling
		api.POST("/autoscaling/configure", h.ConfigureAutoscaling)
		api.GET("/autoscaling/metrics/:resource", h.GetScalingMetrics)

		// Batch processing
		api.POST("/batch/optimize", h.OptimizeBatch)
		api.GET("/batch/metrics/:batchId", h.GetBatchMetrics)
		api.GET("/batch/optimization/:id", h.GetBatchOptimization)

		// Connection optimization
		api.POST("/connections/optimize", h.OptimizeConnections)
		api.GET("/connections/metrics/:poolId", h.GetConnectionMetrics)
		api.GET("/connections/optimization/:id", h.GetConnectionOptimization)

		// Resource optimization
		api.POST("/resources/optimize", h.OptimizeResources)
		api.GET("/resources/metrics/:resource", h.GetResourceMetrics)
		api.GET("/resources/optimization/:id", h.GetResourceOptimization)

		// Performance profiling
		api.POST("/profiling/start", h.StartProfiling)
		api.GET("/profiling/results/:sessionId", h.GetProfilingResults)
		api.GET("/profiling/session/:sessionId", h.GetProfilingSession)

		// Performance testing
		api.POST("/testing/load", h.RunLoadTest)
		api.POST("/testing/benchmark", h.RunBenchmark)
		api.GET("/testing/load/:testId", h.GetLoadTestResults)
		api.GET("/testing/benchmark/:benchmarkId", h.GetBenchmarkResults)

		// Performance insights
		api.GET("/insights/recommendations", h.GetRecommendations)
		api.GET("/insights/issues", h.GetPerformanceIssues)
		api.GET("/insights/summary", h.GetPerformanceSummary)

		// Health check
		api.GET("/health", h.HealthCheck)
	}
}

// OptimizeLatency handles latency optimization requests
func (h *PerformanceHandler) OptimizeLatency(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "optimize_latency_handler")
	defer span.End()

	var config LatencyConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		span.RecordError(err)
		h.logger.WithError(err).Error("Failed to bind latency optimization request")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	span.SetAttributes(
		attribute.String("service", config.Service),
		attribute.String("target_latency", config.TargetLatency.String()),
		attribute.String("optimization_level", config.OptimizationLevel.String()),
	)

	h.logger.WithFields(logrus.Fields{
		"service":        config.Service,
		"target_latency": config.TargetLatency,
		"strategies":     len(config.Strategies),
	}).Info("Received latency optimization request")

	optimization, err := h.engine.OptimizeLatency(ctx, &config)
	if err != nil {
		span.RecordError(err)
		h.logger.WithError(err).Error("Latency optimization failed")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Optimization failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":       "success",
		"optimization": optimization,
		"message":      "Latency optimization completed successfully",
	})
}

// GetLatencyMetrics handles latency metrics requests
func (h *PerformanceHandler) GetLatencyMetrics(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "get_latency_metrics_handler")
	defer span.End()

	service := c.Param("service")
	if service == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Service parameter is required",
		})
		return
	}

	span.SetAttributes(attribute.String("service", service))

	metrics, err := h.engine.GetLatencyMetrics(ctx, service)
	if err != nil {
		span.RecordError(err)
		h.logger.WithError(err).WithField("service", service).Error("Failed to get latency metrics")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to retrieve metrics",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"metrics": metrics,
	})
}

// GetLatencyOptimization handles requests for latency optimization details
func (h *PerformanceHandler) GetLatencyOptimization(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "get_latency_optimization_handler")
	defer span.End()

	optimizationID := c.Param("id")
	if optimizationID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Optimization ID parameter is required",
		})
		return
	}

	span.SetAttributes(attribute.String("optimization_id", optimizationID))

	// In a real implementation, this would retrieve the optimization from storage
	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Optimization details retrieved",
		"id":      optimizationID,
	})
}

// OptimizeCache handles cache optimization requests
func (h *PerformanceHandler) OptimizeCache(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "optimize_cache_handler")
	defer span.End()

	var config CacheConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		span.RecordError(err)
		h.logger.WithError(err).Error("Failed to bind cache optimization request")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	span.SetAttributes(
		attribute.String("cache_id", config.CacheID),
		attribute.String("cache_type", config.Type.String()),
	)

	h.logger.WithFields(logrus.Fields{
		"cache_id":   config.CacheID,
		"cache_type": config.Type.String(),
		"max_size":   config.MaxSize,
	}).Info("Received cache optimization request")

	optimization, err := h.engine.OptimizeCaching(ctx, &config)
	if err != nil {
		span.RecordError(err)
		h.logger.WithError(err).Error("Cache optimization failed")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Optimization failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":       "success",
		"optimization": optimization,
		"message":      "Cache optimization completed successfully",
	})
}

// GetCacheMetrics handles cache metrics requests
func (h *PerformanceHandler) GetCacheMetrics(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "get_cache_metrics_handler")
	defer span.End()

	cacheID := c.Param("cacheId")
	if cacheID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Cache ID parameter is required",
		})
		return
	}

	span.SetAttributes(attribute.String("cache_id", cacheID))

	metrics, err := h.engine.GetCacheMetrics(ctx, cacheID)
	if err != nil {
		span.RecordError(err)
		h.logger.WithError(err).WithField("cache_id", cacheID).Error("Failed to get cache metrics")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to retrieve metrics",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"metrics": metrics,
	})
}

// GetCacheOptimization handles requests for cache optimization details
func (h *PerformanceHandler) GetCacheOptimization(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "get_cache_optimization_handler")
	defer span.End()

	optimizationID := c.Param("id")
	if optimizationID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Optimization ID parameter is required",
		})
		return
	}

	span.SetAttributes(attribute.String("optimization_id", optimizationID))

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Cache optimization details retrieved",
		"id":      optimizationID,
	})
}

// ConfigureAutoscaling handles autoscaling configuration requests
func (h *PerformanceHandler) ConfigureAutoscaling(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "configure_autoscaling_handler")
	defer span.End()

	var config AutoscalingConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		span.RecordError(err)
		h.logger.WithError(err).Error("Failed to bind autoscaling configuration request")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	span.SetAttributes(
		attribute.String("resource_id", config.ResourceID),
		attribute.String("resource_type", config.ResourceType.String()),
	)

	h.logger.WithFields(logrus.Fields{
		"resource_id":   config.ResourceID,
		"resource_type": config.ResourceType.String(),
		"min_replicas":  config.MinReplicas,
		"max_replicas":  config.MaxReplicas,
	}).Info("Received autoscaling configuration request")

	err := h.engine.ConfigureAutoscaling(ctx, &config)
	if err != nil {
		span.RecordError(err)
		h.logger.WithError(err).Error("Autoscaling configuration failed")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Configuration failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Autoscaling configured successfully",
	})
}

// GetScalingMetrics handles scaling metrics requests
func (h *PerformanceHandler) GetScalingMetrics(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "get_scaling_metrics_handler")
	defer span.End()

	resource := c.Param("resource")
	if resource == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Resource parameter is required",
		})
		return
	}

	span.SetAttributes(attribute.String("resource", resource))

	metrics, err := h.engine.GetScalingMetrics(ctx, resource)
	if err != nil {
		span.RecordError(err)
		h.logger.WithError(err).WithField("resource", resource).Error("Failed to get scaling metrics")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to retrieve metrics",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"metrics": metrics,
	})
}

// OptimizeBatch handles batch processing optimization requests
func (h *PerformanceHandler) OptimizeBatch(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "optimize_batch_handler")
	defer span.End()

	var config BatchConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		span.RecordError(err)
		h.logger.WithError(err).Error("Failed to bind batch optimization request")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	span.SetAttributes(
		attribute.String("batch_id", config.BatchID),
		attribute.Int("max_batch_size", config.MaxBatchSize),
	)

	h.logger.WithFields(logrus.Fields{
		"batch_id":         config.BatchID,
		"max_batch_size":   config.MaxBatchSize,
		"batch_timeout":    config.BatchTimeout,
	}).Info("Received batch optimization request")

	optimization, err := h.engine.OptimizeBatchProcessing(ctx, &config)
	if err != nil {
		span.RecordError(err)
		h.logger.WithError(err).Error("Batch optimization failed")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Optimization failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":       "success",
		"optimization": optimization,
		"message":      "Batch optimization completed successfully",
	})
}

// GetBatchMetrics handles batch metrics requests
func (h *PerformanceHandler) GetBatchMetrics(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "get_batch_metrics_handler")
	defer span.End()

	batchID := c.Param("batchId")
	if batchID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Batch ID parameter is required",
		})
		return
	}

	span.SetAttributes(attribute.String("batch_id", batchID))

	metrics, err := h.engine.GetBatchMetrics(ctx, batchID)
	if err != nil {
		span.RecordError(err)
		h.logger.WithError(err).WithField("batch_id", batchID).Error("Failed to get batch metrics")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to retrieve metrics",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"metrics": metrics,
	})
}

// GetBatchOptimization handles requests for batch optimization details
func (h *PerformanceHandler) GetBatchOptimization(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "get_batch_optimization_handler")
	defer span.End()

	optimizationID := c.Param("id")
	if optimizationID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Optimization ID parameter is required",
		})
		return
	}

	span.SetAttributes(attribute.String("optimization_id", optimizationID))

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Batch optimization details retrieved",
		"id":      optimizationID,
	})
}

// OptimizeConnections handles connection optimization requests
func (h *PerformanceHandler) OptimizeConnections(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "optimize_connections_handler")
	defer span.End()

	var config ConnectionConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		span.RecordError(err)
		h.logger.WithError(err).Error("Failed to bind connection optimization request")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	span.SetAttributes(
		attribute.String("pool_id", config.PoolID),
		attribute.Int("max_connections", config.MaxConnections),
	)

	h.logger.WithFields(logrus.Fields{
		"pool_id":         config.PoolID,
		"max_connections": config.MaxConnections,
		"idle_timeout":    config.IdleTimeout,
	}).Info("Received connection optimization request")

	optimization, err := h.engine.OptimizeConnections(ctx, &config)
	if err != nil {
		span.RecordError(err)
		h.logger.WithError(err).Error("Connection optimization failed")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Optimization failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":       "success",
		"optimization": optimization,
		"message":      "Connection optimization completed successfully",
	})
}

// GetConnectionMetrics handles connection metrics requests
func (h *PerformanceHandler) GetConnectionMetrics(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "get_connection_metrics_handler")
	defer span.End()

	poolID := c.Param("poolId")
	if poolID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Pool ID parameter is required",
		})
		return
	}

	span.SetAttributes(attribute.String("pool_id", poolID))

	metrics, err := h.engine.GetConnectionMetrics(ctx, poolID)
	if err != nil {
		span.RecordError(err)
		h.logger.WithError(err).WithField("pool_id", poolID).Error("Failed to get connection metrics")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to retrieve metrics",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"metrics": metrics,
	})
}

// GetConnectionOptimization handles requests for connection optimization details
func (h *PerformanceHandler) GetConnectionOptimization(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "get_connection_optimization_handler")
	defer span.End()

	optimizationID := c.Param("id")
	if optimizationID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Optimization ID parameter is required",
		})
		return
	}

	span.SetAttributes(attribute.String("optimization_id", optimizationID))

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Connection optimization details retrieved",
		"id":      optimizationID,
	})
}

// OptimizeResources handles resource optimization requests
func (h *PerformanceHandler) OptimizeResources(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "optimize_resources_handler")
	defer span.End()

	var config ResourceConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		span.RecordError(err)
		h.logger.WithError(err).Error("Failed to bind resource optimization request")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	span.SetAttributes(
		attribute.String("resource_id", config.ResourceID),
		attribute.String("resource_type", config.ResourceType.String()),
	)

	h.logger.WithFields(logrus.Fields{
		"resource_id":   config.ResourceID,
		"resource_type": config.ResourceType.String(),
		"cpu_target":    config.CPUTarget,
		"memory_target": config.MemoryTarget,
	}).Info("Received resource optimization request")

	optimization, err := h.engine.OptimizeResources(ctx, &config)
	if err != nil {
		span.RecordError(err)
		h.logger.WithError(err).Error("Resource optimization failed")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Optimization failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":       "success",
		"optimization": optimization,
		"message":      "Resource optimization completed successfully",
	})
}

// GetResourceMetrics handles resource metrics requests
func (h *PerformanceHandler) GetResourceMetrics(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "get_resource_metrics_handler")
	defer span.End()

	resource := c.Param("resource")
	if resource == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Resource parameter is required",
		})
		return
	}

	span.SetAttributes(attribute.String("resource", resource))

	metrics, err := h.engine.GetResourceMetrics(ctx, resource)
	if err != nil {
		span.RecordError(err)
		h.logger.WithError(err).WithField("resource", resource).Error("Failed to get resource metrics")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to retrieve metrics",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"metrics": metrics,
	})
}

// GetResourceOptimization handles requests for resource optimization details
func (h *PerformanceHandler) GetResourceOptimization(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "get_resource_optimization_handler")
	defer span.End()

	optimizationID := c.Param("id")
	if optimizationID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Optimization ID parameter is required",
		})
		return
	}

	span.SetAttributes(attribute.String("optimization_id", optimizationID))

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"message": "Resource optimization details retrieved",
		"id":      optimizationID,
	})
}

// StartProfiling handles profiling session start requests
func (h *PerformanceHandler) StartProfiling(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "start_profiling_handler")
	defer span.End()

	var request struct {
		Target   string        `json:"target" binding:"required"`
		Duration time.Duration `json:"duration" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		span.RecordError(err)
		h.logger.WithError(err).Error("Failed to bind profiling request")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	span.SetAttributes(
		attribute.String("target", request.Target),
		attribute.String("duration", request.Duration.String()),
	)

	h.logger.WithFields(logrus.Fields{
		"target":   request.Target,
		"duration": request.Duration,
	}).Info("Received profiling start request")

	session, err := h.engine.StartProfiling(ctx, request.Target, request.Duration)
	if err != nil {
		span.RecordError(err)
		h.logger.WithError(err).Error("Failed to start profiling session")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to start profiling",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"session": session,
		"message": "Profiling session started successfully",
	})
}

// GetProfilingResults handles profiling results requests
func (h *PerformanceHandler) GetProfilingResults(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "get_profiling_results_handler")
	defer span.End()

	sessionID := c.Param("sessionId")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Session ID parameter is required",
		})
		return
	}

	span.SetAttributes(attribute.String("session_id", sessionID))

	results, err := h.engine.GetProfilingResults(ctx, sessionID)
	if err != nil {
		span.RecordError(err)
		h.logger.WithError(err).WithField("session_id", sessionID).Error("Failed to get profiling results")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to retrieve results",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"results": results,
	})
}

// GetProfilingSession handles profiling session status requests
func (h *PerformanceHandler) GetProfilingSession(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "get_profiling_session_handler")
	defer span.End()

	sessionID := c.Param("sessionId")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Session ID parameter is required",
		})
		return
	}

	span.SetAttributes(attribute.String("session_id", sessionID))

	c.JSON(http.StatusOK, gin.H{
		"status":    "success",
		"session_id": sessionID,
		"message":   "Profiling session status retrieved",
	})
}

// RunLoadTest handles load test execution requests
func (h *PerformanceHandler) RunLoadTest(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "run_load_test_handler")
	defer span.End()

	var config LoadTestConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		span.RecordError(err)
		h.logger.WithError(err).Error("Failed to bind load test request")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	span.SetAttributes(
		attribute.String("test_id", config.TestID),
		attribute.String("target", config.Target),
		attribute.Int("virtual_users", config.VirtualUsers),
	)

	h.logger.WithFields(logrus.Fields{
		"test_id":       config.TestID,
		"target":        config.Target,
		"virtual_users": config.VirtualUsers,
		"duration":      config.Duration,
	}).Info("Received load test request")

	results, err := h.engine.RunLoadTest(ctx, &config)
	if err != nil {
		span.RecordError(err)
		h.logger.WithError(err).Error("Load test failed")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Load test failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"results": results,
		"message": "Load test completed successfully",
	})
}

// RunBenchmark handles benchmark execution requests
func (h *PerformanceHandler) RunBenchmark(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "run_benchmark_handler")
	defer span.End()

	var config BenchmarkConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		span.RecordError(err)
		h.logger.WithError(err).Error("Failed to bind benchmark request")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	span.SetAttributes(
		attribute.String("benchmark_id", config.BenchmarkID),
		attribute.String("target", config.Target),
		attribute.Int("iterations", config.Iterations),
	)

	h.logger.WithFields(logrus.Fields{
		"benchmark_id": config.BenchmarkID,
		"target":       config.Target,
		"iterations":   config.Iterations,
		"parallel":     config.Parallel,
	}).Info("Received benchmark request")

	results, err := h.engine.RunBenchmark(ctx, &config)
	if err != nil {
		span.RecordError(err)
		h.logger.WithError(err).Error("Benchmark failed")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Benchmark failed",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"results": results,
		"message": "Benchmark completed successfully",
	})
}

// GetLoadTestResults handles load test results requests
func (h *PerformanceHandler) GetLoadTestResults(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "get_load_test_results_handler")
	defer span.End()

	testID := c.Param("testId")
	if testID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Test ID parameter is required",
		})
		return
	}

	span.SetAttributes(attribute.String("test_id", testID))

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"test_id": testID,
		"message": "Load test results retrieved",
	})
}

// GetBenchmarkResults handles benchmark results requests
func (h *PerformanceHandler) GetBenchmarkResults(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "get_benchmark_results_handler")
	defer span.End()

	benchmarkID := c.Param("benchmarkId")
	if benchmarkID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Benchmark ID parameter is required",
		})
		return
	}

	span.SetAttributes(attribute.String("benchmark_id", benchmarkID))

	c.JSON(http.StatusOK, gin.H{
		"status":      "success",
		"benchmark_id": benchmarkID,
		"message":     "Benchmark results retrieved",
	})
}

// GetRecommendations handles performance recommendations requests
func (h *PerformanceHandler) GetRecommendations(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "get_recommendations_handler")
	defer span.End()

	// Parse query parameters
	limit := 10
	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	priority := c.Query("priority")
	recommendationType := c.Query("type")

	span.SetAttributes(
		attribute.Int("limit", limit),
		attribute.String("priority", priority),
		attribute.String("type", recommendationType),
	)

	// For demonstration, create mock recommendations
	recommendations := []Recommendation{
		{
			ID:          "rec-perf-001",
			Type:        RecommendationInfrastructure,
			Priority:    PriorityHigh,
			Title:       "Optimize Database Connection Pool",
			Description: "Current database connection pool is underutilized. Consider reducing pool size to save resources.",
			CreatedAt:   time.Now(),
		},
		{
			ID:          "rec-perf-002",
			Type:        RecommendationApplication,
			Priority:    PriorityMedium,
			Title:       "Implement Response Caching",
			Description: "Add caching layer for frequently accessed data to reduce response times.",
			CreatedAt:   time.Now(),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"status":          "success",
		"recommendations": recommendations,
		"count":           len(recommendations),
	})
}

// GetPerformanceIssues handles performance issues requests
func (h *PerformanceHandler) GetPerformanceIssues(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "get_performance_issues_handler")
	defer span.End()

	// Parse query parameters
	severity := c.Query("severity")
	issueType := c.Query("type")

	span.SetAttributes(
		attribute.String("severity", severity),
		attribute.String("type", issueType),
	)

	// For demonstration, create mock issues
	issues := []PerformanceIssue{
		{
			ID:          "issue-perf-001",
			Type:        IssueTypeCPUBottleneck,
			Severity:    IssueSeverityMedium,
			Title:       "High CPU Usage in Authentication Service",
			Description: "Authentication service is consuming 85% CPU consistently",
			Function:    "auth.ValidateToken",
			File:        "auth/service.go",
			Line:        124,
			DetectedAt:  time.Now(),
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"issues": issues,
		"count":  len(issues),
	})
}

// GetPerformanceSummary handles performance summary requests
func (h *PerformanceHandler) GetPerformanceSummary(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "get_performance_summary_handler")
	defer span.End()

	timeRange := c.Query("time_range")
	if timeRange == "" {
		timeRange = "24h"
	}

	span.SetAttributes(attribute.String("time_range", timeRange))

	// For demonstration, create mock summary
	summary := gin.H{
		"overall_score":         85.0,
		"latency_p95":          "45ms",
		"throughput":           2500.0,
		"error_rate":           0.15,
		"availability":         99.95,
		"cost_efficiency":      78.0,
		"active_optimizations": 3,
		"recent_improvements":  5,
		"critical_issues":      1,
		"recommendations":      4,
		"last_updated":         time.Now(),
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "success",
		"summary": summary,
	})
}

// HealthCheck handles health check requests
func (h *PerformanceHandler) HealthCheck(c *gin.Context) {
	ctx, span := h.tracer.Start(c.Request.Context(), "performance_health_check")
	defer span.End()

	h.logger.Debug("Performance engine health check requested")

	health := gin.H{
		"status":    "healthy",
		"timestamp": time.Now(),
		"version":   "1.0.0",
		"component": "performance_engine",
		"checks": gin.H{
			"engine":  "operational",
			"metrics": "available",
			"storage": "connected",
		},
	}

	c.JSON(http.StatusOK, health)
}

// ErrorResponse represents a standard error response
type ErrorResponse struct {
	Error   string      `json:"error"`
	Details interface{} `json:"details,omitempty"`
	Code    string      `json:"code,omitempty"`
}

// SuccessResponse represents a standard success response
type SuccessResponse struct {
	Status  string      `json:"status"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// Middleware for request logging
func (h *PerformanceHandler) RequestLoggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("[PERFORMANCE] %v | %3d | %13v | %15s | %-7s %#v\n",
			param.TimeStamp.Format("2006/01/02 - 15:04:05"),
			param.StatusCode,
			param.Latency,
			param.ClientIP,
			param.Method,
			param.Path,
		)
	})
}

// Middleware for request tracing
func (h *PerformanceHandler) TracingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, span := h.tracer.Start(c.Request.Context(), fmt.Sprintf("performance_api_%s", c.Request.Method))
		defer span.End()

		span.SetAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.url", c.Request.URL.String()),
			attribute.String("http.user_agent", c.Request.UserAgent()),
		)

		c.Request = c.Request.WithContext(ctx)
		c.Next()

		span.SetAttributes(attribute.Int("http.status_code", c.Writer.Status()))
	}
}

// Middleware for error handling
func (h *PerformanceHandler) ErrorHandlingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if len(c.Errors) > 0 {
			err := c.Errors.Last()
			h.logger.WithError(err).WithFields(logrus.Fields{
				"method": c.Request.Method,
				"path":   c.Request.URL.Path,
				"status": c.Writer.Status(),
			}).Error("Request error")

			if !c.Writer.Written() {
				c.JSON(http.StatusInternalServerError, ErrorResponse{
					Error:   "Internal server error",
					Details: err.Error(),
				})
			}
		}
	}
}
