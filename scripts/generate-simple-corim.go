package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/fxamacker/cbor/v2"
)

// This script generates simplified example CoRIM profiles for testing and demonstration purposes
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run generate-simple-corim.go <output-directory>")
		fmt.Println("Example: go run generate-simple-corim.go ./configs/corim-profiles")
		os.Exit(1)
	}

	outputDir := os.Args[1]
	
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Generate different example profiles using simplified structures
	examples := []struct {
		name     string
		filename string
		data     map[string]interface{}
	}{
		{"TPM 2.0 Example", "example-tpm.cbor", generateSimpleTPMExample()},
		{"TEE Example", "example-tee.cbor", generateSimpleTEEExample()},
		{"UEFI Example", "example-uefi.cbor", generateSimpleUEFIExample()},
	}

	for _, example := range examples {
		fmt.Printf("Generating %s...\n", example.name)

		// Encode to CBOR
		cborData, err := cbor.Marshal(example.data)
		if err != nil {
			log.Printf("Failed to encode %s to CBOR: %v", example.name, err)
			continue
		}

		// Write to file
		outputPath := fmt.Sprintf("%s/%s", outputDir, example.filename)
		if err := os.WriteFile(outputPath, cborData, 0644); err != nil {
			log.Printf("Failed to write %s: %v", example.name, err)
			continue
		}

		fmt.Printf("✓ Generated %s (%d bytes)\n", outputPath, len(cborData))
	}

	fmt.Println("\nSimple CoRIM profiles generated successfully!")
	fmt.Println("You can now:")
	fmt.Println("1. Start the health monitor service with CoRIM enabled")
	fmt.Println("2. Upload profiles via the REST API")
	fmt.Println("3. Use them for attestation verification")
}

// generateSimpleTPMExample creates a simplified CoRIM-like structure for TPM 2.0 devices
func generateSimpleTPMExample() map[string]interface{} {
	// Generate some example PCR values
	pcr0Hash := sha256.Sum256([]byte("example_bootloader_measurement"))
	pcr1Hash := sha256.Sum256([]byte("example_firmware_measurement"))
	
	return map[string]interface{}{
		"corim-id": "example-tpm-profile-001",
		"profile": map[string]interface{}{
			"version":     "1.0",
			"description": "Example TPM 2.0 CoRIM Profile",
			"author":      "Health Monitor Demo",
		},
		"tags": []map[string]interface{}{
			{
				"tag-id": "tpm-tag-001",
				"environment": map[string]interface{}{
					"class":    "tpm",
					"instance": "tpm-instance-001",
					"vendor":   "Infineon",
					"model":    "SLB9670",
					"version":  "2.0",
				},
				"measurements": []map[string]interface{}{
					{
						"key":       "pcr-0",
						"algorithm": "sha256",
						"digest":    hex.EncodeToString(pcr0Hash[:]),
						"metadata": map[string]interface{}{
							"description": "Bootloader measurement",
							"component":   "bootloader",
						},
					},
					{
						"key":       "pcr-1", 
						"algorithm": "sha256",
						"digest":    hex.EncodeToString(pcr1Hash[:]),
						"metadata": map[string]interface{}{
							"description": "Firmware measurement",
							"component":   "firmware",
						},
					},
				},
			},
		},
	}
}

// generateSimpleTEEExample creates a simplified CoRIM-like structure for TEE environments
func generateSimpleTEEExample() map[string]interface{} {
	// Generate some example TEE measurements
	runtimeHash := sha256.Sum256([]byte("example_tee_runtime_measurement"))
	kernelHash := sha256.Sum256([]byte("example_tee_kernel_measurement"))
	
	return map[string]interface{}{
		"corim-id": "example-tee-profile-001",
		"profile": map[string]interface{}{
			"version":     "1.0",
			"description": "Example TEE CoRIM Profile",
			"author":      "Health Monitor Demo",
		},
		"tags": []map[string]interface{}{
			{
				"tag-id": "tee-tag-001",
				"environment": map[string]interface{}{
					"class":    "tee",
					"instance": "tee-instance-001",
					"vendor":   "ARM",
					"model":    "TrustZone",
					"version":  "1.0",
				},
				"measurements": []map[string]interface{}{
					{
						"key":       "runtime",
						"algorithm": "sha256",
						"digest":    hex.EncodeToString(runtimeHash[:]),
						"metadata": map[string]interface{}{
							"description": "TEE Runtime measurement",
							"component":   "runtime",
						},
					},
					{
						"key":       "kernel",
						"algorithm": "sha256",
						"digest":    hex.EncodeToString(kernelHash[:]),
						"metadata": map[string]interface{}{
							"description": "TEE Kernel measurement",
							"component":   "kernel",
						},
					},
				},
			},
		},
	}
}

// generateSimpleUEFIExample creates a simplified CoRIM-like structure for UEFI environments
func generateSimpleUEFIExample() map[string]interface{} {
	// Generate some example UEFI measurements
	bootloaderHash := sha256.Sum256([]byte("example_uefi_bootloader_measurement"))
	secureBootHash := sha256.Sum256([]byte("example_uefi_secureboot_measurement"))
	
	return map[string]interface{}{
		"corim-id": "example-uefi-profile-001",
		"profile": map[string]interface{}{
			"version":     "1.0",
			"description": "Example UEFI CoRIM Profile",
			"author":      "Health Monitor Demo",
		},
		"tags": []map[string]interface{}{
			{
				"tag-id": "uefi-tag-001",
				"environment": map[string]interface{}{
					"class":    "uefi",
					"instance": "uefi-instance-001",
					"vendor":   "AMI",
					"model":    "UEFI BIOS",
					"version":  "2.8",
				},
				"measurements": []map[string]interface{}{
					{
						"key":       "bootloader",
						"algorithm": "sha256",
						"digest":    hex.EncodeToString(bootloaderHash[:]),
						"metadata": map[string]interface{}{
							"description": "UEFI Bootloader measurement",
							"component":   "bootloader",
						},
					},
					{
						"key":       "secureboot",
						"algorithm": "sha256",
						"digest":    hex.EncodeToString(secureBootHash[:]),
						"metadata": map[string]interface{}{
							"description": "UEFI Secure Boot measurement",
							"component":   "secureboot",
						},
					},
				},
			},
		},
	}
}