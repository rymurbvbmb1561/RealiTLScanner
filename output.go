package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ScanResult holds the result of scanning a single IP/host
type ScanResult struct {
	IP          string    `json:"ip"`
	Port        int       `json:"port"`
	IsReality   bool      `json:"is_reality"`
	ServerName  string    `json:"server_name,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Country     string    `json:"country,omitempty"`
	ASN         string    `json:"asn,omitempty"`
	Latency     int64     `json:"latency_ms"`
	ScannedAt   time.Time `json:"scanned_at"`
	Error       string    `json:"error,omitempty"`
}

// OutputWriter handles writing scan results to various formats
type OutputWriter struct {
	mu         sync.Mutex
	format     string
	filePath   string
	file       *os.File
	csvWriter  *csv.Writer
	results    []ScanResult
}

// NewOutputWriter creates a new OutputWriter for the given format and file path.
// Supported formats: "json", "csv", "txt"
func NewOutputWriter(format, filePath string) (*OutputWriter, error) {
	ow := &OutputWriter{
		format:   format,
		filePath: filePath,
		results:  make([]ScanResult, 0),
	}

	if filePath != "" {
		f, err := os.Create(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
		ow.file = f

		if format == "csv" {
			ow.csvWriter = csv.NewWriter(f)
			// Write CSV header
			header := []string{"ip", "port", "is_reality", "server_name", "fingerprint", "country", "asn", "latency_ms", "scanned_at", "error"}
			if err := ow.csvWriter.Write(header); err != nil {
				return nil, fmt.Errorf("failed to write CSV header: %w", err)
			}
			ow.csvWriter.Flush()
		}
	}

	return ow, nil
}

// Write appends a ScanResult to the output
func (ow *OutputWriter) Write(result ScanResult) error {
	ow.mu.Lock()
	defer ow.mu.Unlock()

	ow.results = append(ow.results, result)

	// Print to stdout
	if result.IsReality {
		fmt.Printf("[+] %s:%d | Reality | SNI: %s | %s | %s | %dms\n",
			result.IP, result.Port, result.ServerName, result.Country, result.ASN, result.Latency)
	}

	if ow.file == nil {
		return nil
	}

	switch ow.format {
	case "csv":
		return ow.writeCSV(result)
	case "txt":
		return ow.writeTXT(result)
	}

	return nil
}

func (ow *OutputWriter) writeCSV(result ScanResult) error {
	row := []string{
		result.IP,
		fmt.Sprintf("%d", result.Port),
		fmt.Sprintf("%v", result.IsReality),
		result.ServerName,
		result.Fingerprint,
		result.Country,
		result.ASN,
		fmt.Sprintf("%d", result.Latency),
		result.ScannedAt.Format(time.RFC3339),
		result.Error,
	}
	if err := ow.csvWriter.Write(row); err != nil {
		return err
	}
	ow.csvWriter.Flush()
	return ow.csvWriter.Error()
}

func (ow *OutputWriter) writeTXT(result ScanResult) error {
	line := fmt.Sprintf("%s:%d reality=%v sni=%s country=%s asn=%s latency=%dms\n",
		result.IP, result.Port, result.IsReality, result.ServerName,
		result.Country, result.ASN, result.Latency)
	_, err := ow.file.WriteString(line)
	return err
}

// Close finalizes the output, flushing JSON if needed
func (ow *OutputWriter) Close() error {
	ow.mu.Lock()
	defer ow.mu.Unlock()

	if ow.file != nil && ow.format == "json" {
		enc := json.NewEncoder(ow.file)
		enc.SetIndent("", "  ")
		if err := enc.Encode(ow.results); err != nil {
			return err
		}
	}

	if ow.file != nil {
		return ow.file.Close()
	}
	return nil
}

// Summary prints a brief scan summary to stdout
func (ow *OutputWriter) Summary() {
	total := len(ow.results)
	realityCount := 0
	for _, r := range ow.results {
		if r.IsReality {
			realityCount++
		}
	}
	fmt.Printf("\n[*] Scan complete: %d scanned, %d Reality detected\n", total, realityCount)
}
