package llm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
)

func newChatCompletionRequest(ctx context.Context, baseURL, apiKey string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	return req, nil
}

func doChatCompletion(httpClient *http.Client, req *http.Request) ([]byte, int, error) {
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("call litellm: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}
	return respBody, resp.StatusCode, nil
}
