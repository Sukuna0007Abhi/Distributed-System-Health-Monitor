package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
)

// This script generates example CoRIM profiles for testing and demonstration purposes
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run generate-example-corim.go <output-directory>")
		fmt.Println("Example: go run generate-example-corim.go ./configs/corim-profiles")
		os.Exit(1)
	}

	outputDir := os.Args[1]
	
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Generate different example profiles
	examples := []struct {
		name     string
		filename string
		generator func() (*corim.UnsignedCorim, error)
	}{
		{"TPM 2.0 Example", "example-tpm.cbor", generateTPMExample},
		{"TEE Example", "example-tee.cbor", generateTEEExample},
		{"UEFI Example", "example-uefi.cbor", generateUEFIExample},
	}

	for _, example := range examples {
		fmt.Printf("Generating %s...\n", example.name)
		
		corim, err := example.generator()
		if err != nil {
			log.Printf("Failed to generate %s: %v", example.name, err)
			continue
		}

		// Encode to CBOR
		cborData, err := cbor.Marshal(corim)
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

	fmt.Println("\nExample CoRIM profiles generated successfully!")
	fmt.Println("You can now:")
	fmt.Println("1. Start the health monitor service with CoRIM enabled")
	fmt.Println("2. Upload profiles via the REST API")
	fmt.Println("3. Use them for attestation verification")
}

// generateTPMExample creates an example CoRIM profile for TPM 2.0 devices
func generateTPMExample() (*corim.UnsignedCorim, error) {
	// Create CoRIM ID
	corimID := comid.TagID(uuid.New().String())
	
	// Create unsigned CoRIM
	unsignedCorim := corim.UnsignedCorim{}
	unsignedCorim.CorimId = corimID

	// Create a CoMID (Concise Module Identifier) tag
	tag := comid.Comid{}
	
	// Set tag identity
	tagUUID := uuid.New().String()
	tagID := comid.TagID(tagUUID)
	tag.TagIdentity = &tagID

	// Create environment for TPM
	var env comid.Environment
	
	// Set environment class for TPM
	tpmClass := comid.Class{}
	tpmClassID := comid.ClassId{
		Type:  &comid.ClassIdTypeInt,
		Value: comid.ClassIdValueInt(1), // TPM class
	}
	tpmClass.ClassId = &tpmClassID
	env.Class = &tpmClass

	// Create instance identifier
	instanceID := comid.InstanceId{
		Type:  &comid.InstanceIdTypeUuid,
		Value: comid.InstanceIdValueUuid(uuid.New()),
	}
	env.Instance = &instanceID

	// Create measurements for PCRs
	measurements := make(comid.Measurements, 0)
	
	// PCR 0 measurement
	pcr0Measurement := createPCRMeasurement(0, "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2")
	measurements = append(measurements, pcr0Measurement)
	
	// PCR 1 measurement  
	pcr1Measurement := createPCRMeasurement(1, "e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3")
	measurements = append(measurements, pcr1Measurement)

	// Create reference value triple
	triple := comid.Triple{
		Environment:  env,
		Measurements: measurements,
	}

	// Create triples structure
	triples := &comid.Triples{}
	triples.ReferenceValues = append(triples.ReferenceValues, triple)
	tag.Triples = triples

	// Add tag to CoRIM
	unsignedCorim.Tags = append(unsignedCorim.Tags, tag)

	return &unsignedCorim, nil
}

// generateTEEExample creates an example CoRIM profile for TEE environments
func generateTEEExample() (*corim.UnsignedCorim, error) {
	// Create CoRIM ID
	corimID := comid.TagID(uuid.New().String())
	
	// Create unsigned CoRIM
	unsignedCorim := corim.UnsignedCorim{}
	unsignedCorim.CorimId = corimID

	// Create a CoMID tag
	tag := comid.Comid{}
	
	// Set tag identity
	tagUUID := uuid.New().String()
	tagID := comid.TagID(tagUUID)
	tag.TagIdentity = &tagID

	// Create environment for TEE
	var env comid.Environment
	
	// Set environment class for TEE
	teeClass := comid.Class{}
	teeClassID := comid.ClassId{
		Type:  &comid.ClassIdTypeInt,
		Value: comid.ClassIdValueInt(2), // TEE class
	}
	teeClass.ClassId = &teeClassID
	env.Class = &teeClass

	// Create instance identifier
	instanceID := comid.InstanceId{
		Type:  &comid.InstanceIdTypeUuid,
		Value: comid.InstanceIdValueUuid(uuid.New()),
	}
	env.Instance = &instanceID

	// Create TEE measurements
	measurements := make(comid.Measurements, 0)
	
	// Runtime measurement
	runtimeMeasurement := createTEEMeasurement("runtime", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	measurements = append(measurements, runtimeMeasurement)
	
	// Kernel measurement
	kernelMeasurement := createTEEMeasurement("kernel", "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5")
	measurements = append(measurements, kernelMeasurement)

	// Create reference value triple
	triple := comid.Triple{
		Environment:  env,
		Measurements: measurements,
	}

	// Create triples structure
	triples := &comid.Triples{}
	triples.ReferenceValues = append(triples.ReferenceValues, triple)
	tag.Triples = triples

	// Add tag to CoRIM
	unsignedCorim.Tags = append(unsignedCorim.Tags, tag)

	return &unsignedCorim, nil
}

// generateUEFIExample creates an example CoRIM profile for UEFI environments
func generateUEFIExample() (*corim.UnsignedCorim, error) {
	// Create CoRIM ID
	corimID := comid.TagID(uuid.New().String())
	
	// Create unsigned CoRIM
	unsignedCorim := corim.UnsignedCorim{}
	unsignedCorim.CorimId = corimID

	// Create a CoMID tag
	tag := comid.Comid{}
	
	// Set tag identity
	tagUUID := uuid.New().String()
	tagID := comid.TagID(tagUUID)
	tag.TagIdentity = &tagID

	// Create environment for UEFI
	var env comid.Environment
	
	// Set environment class for UEFI
	uefiClass := comid.Class{}
	uefiClassID := comid.ClassId{
		Type:  &comid.ClassIdTypeInt,
		Value: comid.ClassIdValueInt(3), // UEFI class
	}
	uefiClass.ClassId = &uefiClassID
	env.Class = &uefiClass

	// Create instance identifier
	instanceID := comid.InstanceId{
		Type:  &comid.InstanceIdTypeUuid,
		Value: comid.InstanceIdValueUuid(uuid.New()),
	}
	env.Instance = &instanceID

	// Create UEFI measurements
	measurements := make(comid.Measurements, 0)
	
	// Bootloader measurement
	bootloaderMeasurement := createUEFIMeasurement("bootloader", "1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b")
	measurements = append(measurements, bootloaderMeasurement)
	
	// Secure Boot measurement
	secureBootMeasurement := createUEFIMeasurement("secureboot", "9z8y7x6w5v4u9z8y7x6w5v4u9z8y7x6w5v4u9z8y7x6w5v4u9z8y7x6w5v4u9z8y")
	measurements = append(measurements, secureBootMeasurement)

	// Create reference value triple
	triple := comid.Triple{
		Environment:  env,
		Measurements: measurements,
	}

	// Create triples structure
	triples := &comid.Triples{}
	triples.ReferenceValues = append(triples.ReferenceValues, triple)
	tag.Triples = triples

	// Add tag to CoRIM
	unsignedCorim.Tags = append(unsignedCorim.Tags, tag)

	return &unsignedCorim, nil
}

// Helper functions to create measurements

func createPCRMeasurement(pcrIndex int, hexDigest string) comid.Measurement {
	var measurement comid.Measurement
	
	// Create measurement key for PCR
	pcrKey := comid.MeasurementKey{
		Type:  &comid.MeasurementKeyTypeInt,
		Value: comid.MeasurementKeyValueInt(pcrIndex),
	}
	measurement.Key = &pcrKey
	
	// Convert hex digest to bytes
	digestBytes, err := hex.DecodeString(hexDigest)
	if err != nil {
		// Fallback to SHA-256 of the hex string
		hash := sha256.Sum256([]byte(hexDigest))
		digestBytes = hash[:]
	}
	
	// Set measurement value
	measurement.Value = comid.MeasurementValue{
		Digests: &comid.Digests{
			{
				AlgId:  comid.AlgSHA256,
				Value:  digestBytes,
			},
		},
	}
	
	return measurement
}

func createTEEMeasurement(component, hexDigest string) comid.Measurement {
	var measurement comid.Measurement
	
	// Create measurement key for TEE component
	componentKey := comid.MeasurementKey{
		Type:  &comid.MeasurementKeyTypeTextString,
		Value: comid.MeasurementKeyValueTextString(component),
	}
	measurement.Key = &componentKey
	
	// Convert hex digest to bytes
	digestBytes, err := hex.DecodeString(hexDigest)
	if err != nil {
		// Fallback to SHA-256 of the component name + hex string
		hash := sha256.Sum256([]byte(component + hexDigest))
		digestBytes = hash[:]
	}
	
	// Set measurement value
	measurement.Value = comid.MeasurementValue{
		Digests: &comid.Digests{
			{
				AlgId:  comid.AlgSHA256,
				Value:  digestBytes,
			},
		},
	}
	
	return measurement
}

func createUEFIMeasurement(component, hexDigest string) comid.Measurement {
	var measurement comid.Measurement
	
	// Create measurement key for UEFI component
	componentKey := comid.MeasurementKey{
		Type:  &comid.MeasurementKeyTypeTextString,
		Value: comid.MeasurementKeyValueTextString(component),
	}
	measurement.Key = &componentKey
	
	// Convert hex digest to bytes
	digestBytes, err := hex.DecodeString(hexDigest)
	if err != nil {
		// Fallback to SHA-256 of the component name + hex string
		hash := sha256.Sum256([]byte(component + hexDigest))
		digestBytes = hash[:]
	}
	
	// Set measurement value
	measurement.Value = comid.MeasurementValue{
		Digests: &comid.Digests{
			{
				AlgId:  comid.AlgSHA256,
				Value:  digestBytes,
			},
		},
	}
	
	return measurement
}