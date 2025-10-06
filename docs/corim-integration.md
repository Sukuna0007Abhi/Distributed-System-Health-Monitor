# CoRIM Integration Documentation

## Overview

This document describes the Concise Reference Integrity Manifest (CoRIM) integration in the distributed health monitor system. CoRIM provides a standardized way to manage reference integrity values for attestation processes across different environments including TPM, TEE (Trusted Execution Environment), and UEFI systems.

## Architecture

### Component Diagram

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CoRIM Files   │───▶│     Parser      │───▶│   Validator     │
│   (CBOR)        │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  Provisioner    │◄───│      Store      │
                       │                 │    │    (Redis)      │
                       └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   REST API      │
                       │   (Gin)         │
                       └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │  Attestation    │
                       │   Service       │
                       └─────────────────┘
```

### Core Components

1. **Parser** (`internal/corim/parser.go`)
   - Parses CBOR-encoded CoRIM files using the veraison/corim library
   - Validates CBOR structure and extracts reference values
   - Supports file validation and debug logging

2. **Store** (`internal/corim/store.go`)
   - Redis-based storage for CoRIM profiles and reference values
   - Implements caching with TTL support
   - Provides high-performance lookups by environment identifiers

3. **Provisioner** (`internal/corim/provisioner.go`)
   - Orchestrates parsing, validation, and storage operations
   - Manages profile lifecycle (create, update, delete)
   - Provides query interfaces for reference value retrieval

4. **Validator** (`internal/corim/validator.go`)
   - Validates CoRIM structure and integrity
   - Checks measurement formats and environment identifiers
   - Provides detailed validation reports with errors and warnings

5. **REST API Handler** (`internal/corim/handler.go`)
   - RESTful endpoints for CoRIM profile management
   - File upload support for CoRIM files
   - Query endpoints for reference value retrieval

6. **Metrics** (`internal/corim/metrics.go`)
   - Prometheus metrics for monitoring CoRIM operations
   - Performance tracking and error rate monitoring
   - Integration with observability infrastructure

## Data Structures

### Profile
```go
type Profile struct {
    ID          string                    // Unique profile identifier
    Name        string                    // Human-readable name
    Version     string                    // Profile version
    Description string                    // Profile description
    LoadTime    time.Time                 // Profile load timestamp
    RefValues   []*ReferenceValue         // Associated reference values
    Metadata    *ProfileMetadata          // File metadata and checksums
}
```

### ReferenceValue
```go
type ReferenceValue struct {
    Key           string                  // Unique identifier
    Environment   *EnvironmentIdentifier  // Target environment
    Measurements  []*Measurement          // PCR/measurement values
    TagID         string                  // CoMID tag identifier
    CreatedAt     time.Time              // Creation timestamp
    ExpiresAt     *time.Time             // Optional expiration
}
```

### EnvironmentIdentifier
```go
type EnvironmentIdentifier struct {
    Class    string    // Environment class (TPM, TEE, UEFI, Generic)
    Instance string    // Unique instance identifier
    Vendor   string    // Hardware vendor
    Model    string    // Hardware model
    Version  string    // Version information
}
```

## API Endpoints

### CoRIM Profile Management

#### Upload CoRIM Profile
```http
POST /api/v1/corim/profiles
Content-Type: multipart/form-data

Form Data:
- file: CoRIM CBOR file
- name: (optional) Profile name
- description: (optional) Profile description
```

**Response:**
```json
{
  "success": true,
  "profile_id": "tpm-reference-001",
  "message": "CoRIM profile uploaded successfully",
  "validation_summary": {
    "valid": true,
    "total_checks": 15,
    "error_count": 0,
    "warning_count": 2,
    "reference_values_extracted": 8
  }
}
```

#### List Profiles
```http
GET /api/v1/corim/profiles
```

**Response:**
```json
{
  "profiles": [
    {
      "id": "tpm-reference-001",
      "name": "TPM 2.0 Reference Values",
      "ref_count": 8,
      "load_time": "2024-01-15T10:30:00Z",
      "metadata": {
        "file_size": 1024,
        "checksum": "sha256:abcd1234..."
      }
    }
  ]
}
```

#### Get Profile Details
```http
GET /api/v1/corim/profiles/{profile-id}
```

#### Delete Profile
```http
DELETE /api/v1/corim/profiles/{profile-id}
```

### Reference Value Queries

#### Query by Environment
```http
POST /api/v1/corim/reference-values/query
Content-Type: application/json

{
  "environment": {
    "class": "TPM",
    "vendor": "Infineon",
    "model": "SLB9670"
  }
}
```

**Response:**
```json
{
  "reference_values": [
    {
      "key": "pcr-0-bootloader",
      "environment": {
        "class": "TPM",
        "vendor": "Infineon",
        "model": "SLB9670"
      },
      "measurements": [
        {
          "key": "pcr-0",
          "algorithm": "sha256",
          "digest": "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
        }
      ],
      "tag_id": "bootloader-v1.2.3"
    }
  ]
}
```

#### Query PCR Measurements
```http
GET /api/v1/corim/reference-values/pcr/{pcr-number}?environment_class=TPM&vendor=Infineon
```

## Configuration

Add the following configuration to your application config:

```yaml
corim:
  enabled: true
  redis:
    address: "localhost:6379"
    password: ""
    database: 0
    key_prefix: "corim:"
    default_ttl: "24h"
  parser:
    max_file_size: 10485760  # 10MB
    validate_on_load: true
    strict_mode: false
    enable_metrics: true
    enable_debug_logs: false
  provisioner:
    max_profiles: 1000
    enable_bulk_operations: true
    auto_refresh_interval: "1h"
```

## Usage Examples

### Basic Profile Upload

```bash
# Upload a CoRIM profile
curl -X POST http://localhost:8080/api/v1/corim/profiles \
  -F "file=@example-tpm.cbor" \
  -F "name=TPM Reference Values" \
  -F "description=Reference values for TPM 2.0 attestation"
```

### Query Reference Values for Attestation

```go
// Example: Integration with attestation service
func (s *AttestationService) ValidateTPMQuote(quote *TPMQuote) error {
    // Query CoRIM reference values
    env := &corim.EnvironmentIdentifier{
        Class:  corim.EnvClassTPM,
        Vendor: quote.TPMInfo.Vendor,
        Model:  quote.TPMInfo.Model,
    }
    
    refValues, err := s.corimProvisioner.GetReferenceValues(ctx, env)
    if err != nil {
        return fmt.Errorf("failed to get reference values: %w", err)
    }
    
    // Validate PCR measurements against reference values
    for _, measurement := range quote.PCRs {
        expected := findReferenceValue(refValues, measurement.PCR)
        if expected == nil {
            return fmt.Errorf("no reference value found for PCR %d", measurement.PCR)
        }
        
        if !bytes.Equal(measurement.Value, expected.Digest) {
            return fmt.Errorf("PCR %d measurement mismatch", measurement.PCR)
        }
    }
    
    return nil
}
```

### Programmatic Profile Management

```go
// Create provisioner
provisioner := corim.NewProvisioner(store, parser, validator, metrics, logger)

// Load CoRIM profile from file
ctx := context.Background()
profile, err := provisioner.LoadProfileFromFile(ctx, "path/to/profile.cbor")
if err != nil {
    log.Fatalf("Failed to load profile: %v", err)
}

// Query reference values
env := &corim.EnvironmentIdentifier{
    Class: corim.EnvClassTPM,
    Vendor: "Infineon",
}

refValues, err := provisioner.GetReferenceValues(ctx, env)
if err != nil {
    log.Fatalf("Failed to get reference values: %v", err)
}
```

## Monitoring and Metrics

### Prometheus Metrics

The CoRIM integration exposes the following Prometheus metrics:

- `corim_operations_total{operation, status}` - Total CoRIM operations
- `corim_parse_duration_seconds` - CoRIM parsing duration
- `corim_validation_duration_seconds` - Validation duration
- `corim_profiles_active` - Number of active profiles
- `corim_reference_values_total` - Total reference values stored
- `corim_cache_hit_rate` - Redis cache hit rate
- `corim_errors_total{error_type}` - Error counts by type

### Health Checks

```http
GET /api/v1/corim/health
```

**Response:**
```json
{
  "status": "healthy",
  "components": {
    "redis": "healthy",
    "parser": "healthy",
    "validator": "healthy"
  },
  "stats": {
    "profiles_count": 5,
    "reference_values_count": 42,
    "cache_hit_rate": 0.95
  }
}
```

## Security Considerations

### File Upload Security
- Maximum file size limits (configurable, default 10MB)
- CBOR format validation before processing
- Input sanitization for all user-provided fields
- Rate limiting on upload endpoints

### Data Integrity
- SHA-256 checksums for all uploaded files
- Profile versioning and audit trails
- Redis data encryption in transit and at rest
- Secure key generation for profile identifiers

### Access Control
- API key authentication for all endpoints
- Role-based access control (RBAC) integration
- Audit logging for all profile operations
- IP-based access restrictions (configurable)

## Testing

### Unit Tests

Run the complete CoRIM test suite:
```bash
go test ./internal/corim/... -v
```

### Integration Tests

Test with real CoRIM files:
```bash
# Generate example files
go run scripts/generate-simple-corim.go

# Test upload
curl -X POST http://localhost:8080/api/v1/corim/profiles \
  -F "file=@configs/corim-profiles/example-tpm.cbor"
```

### Load Testing

```bash
# Example load test script
for i in {1..100}; do
  curl -X POST http://localhost:8080/api/v1/corim/profiles \
    -F "file=@example-tpm.cbor" \
    -F "name=Load Test Profile $i" &
done
wait
```

## Troubleshooting

### Common Issues

1. **CBOR Parse Errors**
   - Verify file is valid CoRIM CBOR format
   - Check file size limits
   - Enable debug logging for detailed error information

2. **Redis Connection Issues**
   - Verify Redis server accessibility
   - Check authentication credentials
   - Monitor connection pool metrics

3. **Validation Failures**
   - Review validation error details in API response
   - Check environment identifier format
   - Verify measurement digest lengths

### Debug Logging

Enable detailed logging:
```yaml
corim:
  parser:
    enable_debug_logs: true
```

Log levels:
- DEBUG: Detailed parsing and validation steps
- INFO: Profile operations and performance metrics
- WARN: Validation warnings and recoverable errors
- ERROR: Critical failures and system errors

## Performance Optimization

### Redis Configuration
- Use Redis Cluster for high availability
- Configure appropriate memory limits
- Enable Redis persistence for durability
- Monitor key expiration and cleanup

### Caching Strategy
- Profile metadata cached with 24-hour TTL
- Reference values cached with 1-hour TTL
- Environment-based cache partitioning
- Background cache warming for frequently accessed data

### File Processing
- Parallel CBOR parsing for large files
- Streaming upload for large CoRIM files
- Background validation for non-critical operations
- Batch operations for bulk profile management

## Migration and Deployment

### Database Migration
No database schema changes required - uses Redis key-value storage.

### Rolling Deployment
1. Deploy new version with CoRIM support disabled
2. Verify system stability
3. Enable CoRIM functionality via configuration
4. Gradually migrate existing reference values
5. Monitor metrics and performance

### Backup and Recovery
- Regular Redis backups (RDB + AOF)
- Profile file backups to object storage
- Configuration backup and version control
- Disaster recovery procedures documented

## Support and Maintenance

### Monitoring Checklist
- [ ] Profile upload success rates
- [ ] Redis performance and connectivity
- [ ] API response times
- [ ] Validation error rates
- [ ] Cache hit ratios
- [ ] Storage utilization

### Regular Maintenance
- Weekly: Review validation warnings and errors
- Monthly: Clean up expired profiles and reference values
- Quarterly: Performance optimization review
- Annually: Security audit and dependency updates

For support and questions, please refer to the project documentation or contact the development team.