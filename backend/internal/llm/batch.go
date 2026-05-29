package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type BatchStatus string

const (
	BatchStatusValidating BatchStatus = "validating"
	BatchStatusFailed     BatchStatus = "failed"
	BatchStatusInProgress BatchStatus = "in_progress"
	BatchStatusFinalizing BatchStatus = "finalizing"
	BatchStatusCompleted  BatchStatus = "completed"
	BatchStatusExpired    BatchStatus = "expired"
	BatchStatusCancelled  BatchStatus = "cancelled"
)

type BatchClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

func NewBatchClient(s Settings) *BatchClient {
	timeout := time.Duration(s.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &BatchClient{
		baseURL:    strings.TrimRight(s.BaseURL, "/"),
		apiKey:     s.APIKey,
		httpClient: &http.Client{Timeout: timeout},
	}
}

type batchCreateRequest struct {
	InputFileID     string `json:"input_file_id"`
	Endpoint        string `json:"endpoint"`
	CompletionWindow string `json:"completion_window"`
}

type batchCreateResponse struct {
	ID string `json:"id"`
}

type batchRetrieveResponse struct {
	ID           string      `json:"id"`
	Status       BatchStatus `json:"status"`
	OutputFileID string      `json:"output_file_id"`
	ErrorFileID  string      `json:"error_file_id"`
}

type batchLineRequest struct {
	CustomID string         `json:"custom_id"`
	Method   string         `json:"method"`
	URL      string         `json:"url"`
	Body     map[string]any `json:"body"`
}

type batchLineResponse struct {
	CustomID string `json:"custom_id"`
	Response struct {
		StatusCode int `json:"status_code"`
		Body       struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		} `json:"body"`
	} `json:"response"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (c *BatchClient) SubmitTranslation(ctx context.Context, customID, model, systemPrompt, userPrompt string) (string, error) {
	line := batchLineRequest{
		CustomID: customID,
		Method:   "POST",
		URL:      "/v1/chat/completions",
		Body: map[string]any{
			"model": model,
			"messages": []map[string]string{
				{"role": "system", "content": systemPrompt},
				{"role": "user", "content": userPrompt},
			},
			"temperature":     0.1,
			"response_format": map[string]string{"type": "json_object"},
		},
	}
	lineBytes, err := json.Marshal(line)
	if err != nil {
		return "", fmt.Errorf("marshal batch line: %w", err)
	}

	fileID, err := c.uploadBatchFile(ctx, lineBytes)
	if err != nil {
		return "", err
	}

	body, err := json.Marshal(batchCreateRequest{
		InputFileID:      fileID,
		Endpoint:         "/v1/chat/completions",
		CompletionWindow: "24h",
	})
	if err != nil {
		return "", fmt.Errorf("marshal batch create: %w", err)
	}

	respBody, status, err := c.doRequest(ctx, http.MethodPost, "/v1/batches", body)
	if err != nil {
		return "", err
	}
	if status >= 400 {
		return "", fmt.Errorf("batch create returned %d: %s", status, truncate(string(respBody), 500))
	}

	var created batchCreateResponse
	if err := json.Unmarshal(respBody, &created); err != nil {
		return "", fmt.Errorf("parse batch create: %w", err)
	}
	if created.ID == "" {
		return "", fmt.Errorf("batch create returned empty id")
	}
	return created.ID, nil
}

func (c *BatchClient) GetStatus(ctx context.Context, batchID string) (BatchStatus, string, error) {
	respBody, status, err := c.doRequest(ctx, http.MethodGet, "/v1/batches/"+batchID, nil)
	if err != nil {
		return "", "", err
	}
	if status >= 400 {
		return "", "", fmt.Errorf("batch retrieve returned %d: %s", status, truncate(string(respBody), 500))
	}

	var batch batchRetrieveResponse
	if err := json.Unmarshal(respBody, &batch); err != nil {
		return "", "", fmt.Errorf("parse batch retrieve: %w", err)
	}
	return batch.Status, batch.OutputFileID, nil
}

func (c *BatchClient) GetTranslationResult(ctx context.Context, outputFileID, customID string) (*AnalysisTranslationResult, error) {
	respBody, status, err := c.doRequest(ctx, http.MethodGet, "/v1/files/"+outputFileID+"/content", nil)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, fmt.Errorf("batch output returned %d: %s", status, truncate(string(respBody), 500))
	}

	for _, line := range bytes.Split(respBody, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var entry batchLineResponse
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		if entry.CustomID != customID {
			continue
		}
		if entry.Error != nil {
			return nil, fmt.Errorf("batch line error: %s", entry.Error.Message)
		}
		if entry.Response.StatusCode >= 400 {
			return nil, fmt.Errorf("batch line returned %d", entry.Response.StatusCode)
		}
		if len(entry.Response.Body.Choices) == 0 {
			return nil, fmt.Errorf("batch line empty response")
		}
		return parseAnalysisTranslationResult(entry.Response.Body.Choices[0].Message.Content)
	}
	return nil, fmt.Errorf("batch output missing custom_id %s", customID)
}

func (c *BatchClient) uploadBatchFile(ctx context.Context, line []byte) (string, error) {
	var buf bytes.Buffer
	writer := multipartWriter(&buf)
	if err := writer.WriteField("purpose", "batch"); err != nil {
		return "", err
	}
	if err := writer.WriteFile("requests.jsonl", line); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/files", &buf)
	if err != nil {
		return "", fmt.Errorf("create file upload request: %w", err)
	}
	req.Header.Set("Content-Type", writer.ContentType())
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("upload batch file: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read file upload response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("file upload returned %d: %s", resp.StatusCode, truncate(string(respBody), 500))
	}

	var uploaded struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(respBody, &uploaded); err != nil {
		return "", fmt.Errorf("parse file upload: %w", err)
	}
	if uploaded.ID == "" {
		return "", fmt.Errorf("file upload returned empty id")
	}
	return uploaded.ID, nil
}

func (c *BatchClient) doRequest(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	respBody, status, err := doChatCompletionWithRetry(ctx, c.httpClient, req)
	return respBody, status, err
}
