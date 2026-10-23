// ammp4 inspects local acquired MP4 structure. It makes no network requests.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	am "github.com/AmarnathCJD/AppleDL"
)

func run() error {
	dir := flag.String("directory", "", "directory containing acquired init-NNNN.bin and segment-NNNNNN.bin files")
	flag.Parse()
	if *dir == "" || flag.NArg() != 0 {
		return errors.New("one acquisition directory is required")
	}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		return errors.New("cannot read acquisition directory")
	}
	names := regexp.MustCompile(`^(init-[0-9]{4}|segment-[0-9]{6})\.bin$`)
	type fileReport struct {
		Name       string            `json:"name"`
		Inspection *am.MP4Inspection `json:"inspection"`
	}
	var reports []fileReport
	total := int64(0)
	for _, entry := range entries {
		if !names.MatchString(entry.Name()) {
			continue
		}
		if !entry.Type().IsRegular() || len(reports) >= 10000 {
			return errors.New("unsupported acquisition directory entry")
		}
		f, e := os.Open(filepath.Join(*dir, entry.Name()))
		if e != nil {
			return errors.New("cannot open acquired file")
		}
		data, e := io.ReadAll(io.LimitReader(f, am.MaxHLSResourceBytes+1))
		closeErr := f.Close()
		total += int64(len(data))
		if e != nil || closeErr != nil || total > am.MaxHLSAcquisitionBytes {
			return errors.New("cannot read bounded acquired file")
		}
		inspected, e := am.InspectMP4(data)
		clear(data)
		if e != nil {
			return fmt.Errorf("MP4 inspection failed at local file index %d: %w", len(reports), e)
		}
		reports = append(reports, fileReport{entry.Name(), inspected})
	}
	if len(reports) == 0 {
		return errors.New("no acquired files found")
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(reports)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
