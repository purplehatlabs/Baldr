package queue

import (
	"archive/zip"
	"bytes"
	"testing"
)

func TestParseOSVJSONFormats(t *testing.T) {
	t.Parallel()

	const maliciousObject = `{
		"id":"MAL-2026-0001",
		"summary":"malicious package",
		"details":"details",
		"affected":[{"package":{"ecosystem":"npm","name":"left-pad"},"versions":["1.0.0"]}]
	}`

	tests := []struct {
		name    string
		payload string
	}{
		{
			name:    "array",
			payload: "[" + maliciousObject + "]",
		},
		{
			name:    "envelope vulns",
			payload: `{"vulns":[` + maliciousObject + `]}`,
		},
		{
			name:    "single object",
			payload: maliciousObject,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			items, err := parseOSVJSON([]byte(tc.payload))
			if err != nil {
				t.Fatalf("parseOSVJSON error: %v", err)
			}
			if len(items) != 1 {
				t.Fatalf("expected 1 item, got %d", len(items))
			}
			if items[0].ExternalID != "MAL-2026-0001" {
				t.Fatalf("unexpected external_id: %s", items[0].ExternalID)
			}
			if items[0].Ecosystem != "npm" || items[0].PackageName != "left-pad" || items[0].PackageVersion != "1.0.0" {
				t.Fatalf("unexpected package tuple: %s/%s@%s", items[0].Ecosystem, items[0].PackageName, items[0].PackageVersion)
			}
		})
	}
}

func TestParseOSVJSONIgnoresNonMaliciousRecords(t *testing.T) {
	t.Parallel()

	payload := `[
		{
			"id":"GHSA-xxxx-yyyy-zzzz",
			"affected":[{"package":{"ecosystem":"npm","name":"safe-package"},"versions":["1.2.3"]}]
		},
		{
			"id":"MAL-2026-0002",
			"affected":[{"package":{"ecosystem":"npm","name":"bad-package"},"versions":["2.0.0"]}]
		}
	]`

	items, err := parseOSVJSON([]byte(payload))
	if err != nil {
		t.Fatalf("parseOSVJSON error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected only MAL records, got %d", len(items))
	}
	if items[0].ExternalID != "MAL-2026-0002" {
		t.Fatalf("unexpected external_id: %s", items[0].ExternalID)
	}
}

func TestParseOSVJSONEmptyDataset(t *testing.T) {
	t.Parallel()

	items, err := parseOSVJSON([]byte("   \n\t"))
	if err != nil {
		t.Fatalf("parseOSVJSON error: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected empty result, got %d items", len(items))
	}
}

func TestParseOSVZipBasicFixtures(t *testing.T) {
	t.Parallel()

	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)

	addFile := func(path, content string) {
		t.Helper()
		file, err := writer.Create(path)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", path, err)
		}
		if _, err := file.Write([]byte(content)); err != nil {
			t.Fatalf("write zip entry %s: %v", path, err)
		}
	}

	addFile("fixtures/osv/malicious/one.json", `{
		"id":"MAL-2026-1000",
		"affected":[{"package":{"ecosystem":"npm","name":"zip-bad"},"versions":["3.1.4"]}]
	}`)
	addFile("fixtures/osv/malicious/ignore.txt", "not-json")
	addFile("fixtures/osv/regular/two.json", `{"id":"MAL-2026-2000"}`)
	if err := writer.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}

	items, err := parseOSVZip(archive.Bytes())
	if err != nil {
		t.Fatalf("parseOSVZip error: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 malicious indicator from zip, got %d", len(items))
	}
	if items[0].ExternalID != "MAL-2026-1000" {
		t.Fatalf("unexpected external_id: %s", items[0].ExternalID)
	}
	if items[0].PackageName != "zip-bad" {
		t.Fatalf("unexpected package_name: %s", items[0].PackageName)
	}
}
