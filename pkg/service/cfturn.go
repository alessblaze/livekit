package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/livekit/livekit-server/pkg/config"
	"github.com/livekit/protocol/livekit"
	"github.com/livekit/protocol/logger"
)

// cfTurnDebug checks if CF TURN debug logging is enabled
func cfTurnDebug() bool {
	return os.Getenv("LIVEKIT_CF_TURN_DEBUG") == "true"
}

// cfTurnLog logs CF TURN messages only if debug is enabled, except for errors which always log
func cfTurnLog(level string, msg string, args ...interface{}) {
	if !cfTurnDebug() && level != "error" {
		return
	}
	switch level {
	case "debug":
		logger.Debugw(msg, args...)
	case "info":
		logger.Infow(msg, args...)
	case "warn":
		logger.Warnw(msg, nil, args...)
	case "error":
		logger.Errorw(msg, nil, args...)
	}
}

type CloudflareTurnResponse struct {
	IceServers []struct {
		URLs       []string `json:"urls"`
		Username   string   `json:"username"`
		Credential string   `json:"credential"`
	} `json:"iceServers"`
}

func FetchCloudflareCredentials(turnConf *config.TURNConfig) ([]config.TURNServer, error) {
	cfTurnLog("debug", "CF TURN: Starting credential fetch", "turn_key_id", turnConf.CFTurnKeyID)

	if !turnConf.CloudflareEnabled {
		cfTurnLog("debug", "CF TURN: Cloudflare TURN disabled")
		return nil, fmt.Errorf("Cloudflare TURN not enabled")
	}

	if turnConf.CFTurnKeyID == "" || turnConf.CFAPIToken == "" {
		cfTurnLog("error", "CF TURN: Missing credentials", "has_key_id", turnConf.CFTurnKeyID != "", "has_token", turnConf.CFAPIToken != "")
		return nil, fmt.Errorf("CF TURN key ID and API token required")
	}

	url := fmt.Sprintf("https://rtc.live.cloudflare.com/v1/turn/keys/%s/credentials/generate-ice-servers", turnConf.CFTurnKeyID)
	tokenPrefix := "<empty>"
	if len(turnConf.CFAPIToken) > 8 {
		tokenPrefix = turnConf.CFAPIToken[:8] + "..."
	} else if turnConf.CFAPIToken != "" {
		tokenPrefix = turnConf.CFAPIToken
	}
	cfTurnLog("debug", "CF TURN: Making API request", "url", url, "token_prefix", tokenPrefix)

	payload := map[string]interface{}{
		"ttl": 86400, // 24 hours
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		cfTurnLog("error", "CF TURN: Failed to marshal payload", "error", err)
		return nil, err
	}
	cfTurnLog("debug", "CF TURN: Request payload", "payload", string(jsonData))

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		cfTurnLog("error", "CF TURN: Failed to create request", "error", err)
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+turnConf.CFAPIToken)
	req.Header.Set("Content-Type", "application/json")
	cfTurnLog("debug", "CF TURN: Request headers set", "content_type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	cfTurnLog("debug", "CF TURN: Sending HTTP request")
	resp, err := client.Do(req)
	if err != nil {
		cfTurnLog("error", "CF TURN: HTTP request failed", "error", err)
		return nil, err
	}
	defer resp.Body.Close()

	cfTurnLog("debug", "CF TURN: Received response", "status_code", resp.StatusCode, "status", resp.Status)

	// Read response body with 10KB limit to prevent memory exhaustion
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024))
	if err != nil {
		cfTurnLog("error", "CF TURN: Failed to read response body", "error", err)
		return nil, fmt.Errorf("failed to read CF API response body: %v", err)
	}

	// Check HTTP status code first (200 OK or 201 Created are both success)
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		cfTurnLog("error", "CF TURN: HTTP error", "status_code", resp.StatusCode, "status", resp.Status)
		return nil, fmt.Errorf("CF API HTTP error %d: %s", resp.StatusCode, resp.Status)
	}

	var cfResp CloudflareTurnResponse
	if err := json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(&cfResp); err != nil {
		cfTurnLog("error", "CF TURN: Failed to decode response", "error", err, "status_code", resp.StatusCode)
		return nil, fmt.Errorf("failed to decode CF API response (status %d): %v", resp.StatusCode, err)
	}

	cfTurnLog("debug", "CF TURN: Decoded response", "ice_servers_count", len(cfResp.IceServers))

	var turnServers []config.TURNServer
	cfTurnLog("debug", "CF TURN: Processing ICE servers", "total_ice_servers", len(cfResp.IceServers))

	for i, server := range cfResp.IceServers {
		cfTurnLog("debug", "CF TURN: Processing ICE server", "index", i, "urls_count", len(server.URLs), "username", previewCredential(server.Username), "credential", previewCredential(server.Credential))

		for j, url := range server.URLs {
			cfTurnLog("debug", "CF TURN: Processing URL", "ice_server_index", i, "url_index", j, "url", url)

			if strings.HasPrefix(url, "turn:") || strings.HasPrefix(url, "turns:") {
				cfTurnLog("debug", "CF TURN: Found TURN URL, parsing", "url", url)
				turnServer := parseTurnURL(url, server.Username, server.Credential)
				if turnServer != nil {
					cfTurnLog("debug", "CF TURN: Successfully parsed TURN server", "host", turnServer.Host, "port", turnServer.Port, "protocol", turnServer.Protocol)
					turnServers = append(turnServers, *turnServer)
				} else {
					cfTurnLog("warn", "CF TURN: Failed to parse TURN URL", "url", url)
				}
			} else {
				cfTurnLog("debug", "CF TURN: Skipping non-TURN URL", "url", url)
			}
		}
	}

	cfTurnLog("info", "CF TURN: Successfully fetched credentials", "total_turn_servers", len(turnServers))
	for i, server := range turnServers {
		cfTurnLog("debug", "CF TURN: Final server config", "index", i, "host", server.Host, "port", server.Port, "protocol", server.Protocol)
	}
	return turnServers, nil
}

// RevokeCloudflareCredentials revokes TURN credentials when participant leaves
func RevokeCloudflareCredentials(turnConf *config.TURNConfig, username string) error {
	cfTurnLog("debug", "CF TURN: Starting credential revocation", "username", previewCredential(username))

	if !turnConf.CloudflareEnabled {
		cfTurnLog("debug", "CF TURN: Cloudflare TURN disabled, skipping revocation")
		return nil
	}

	if turnConf.CFTurnKeyID == "" || turnConf.CFAPIToken == "" {
		cfTurnLog("error", "CF TURN: Missing credentials for revocation")
		return fmt.Errorf("CF TURN key ID and API token required")
	}

	if username == "" {
		cfTurnLog("warn", "CF TURN: Empty username, skipping revocation")
		return nil
	}

	url := fmt.Sprintf("https://rtc.live.cloudflare.com/v1/turn/keys/%s/credentials/%s/revoke", turnConf.CFTurnKeyID, username)
	cfTurnLog("debug", "CF TURN: Making revocation request", "url", url)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		cfTurnLog("error", "CF TURN: Failed to create revocation request", "error", err)
		return err
	}

	req.Header.Set("Authorization", "Bearer "+turnConf.CFAPIToken)
	cfTurnLog("debug", "CF TURN: Revocation headers set")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		cfTurnLog("error", "CF TURN: Revocation request failed", "error", err)
		return err
	}
	defer resp.Body.Close()

	cfTurnLog("debug", "CF TURN: Revocation response", "status_code", resp.StatusCode, "status", resp.Status)

	// 200 OK, 204 No Content, or 404 Not Found are all acceptable (credential revoked/expired)
	if resp.StatusCode != 200 && resp.StatusCode != 204 && resp.StatusCode != 404 {
		cfTurnLog("warn", "CF TURN: Revocation failed", "status_code", resp.StatusCode, "status", resp.Status)
		return fmt.Errorf("CF TURN revocation failed: %d %s", resp.StatusCode, resp.Status)
	}

	cfTurnLog("info", "CF TURN: Credentials revoked", "username", previewCredential(username))
	return nil
}

// previewCredential safely previews credential strings for logging
func previewCredential(credential string) string {
	if credential == "" {
		return "<empty>"
	}
	if len(credential) > 8 {
		return credential[:8] + "..."
	}
	return credential
}

func parseTurnURL(url, username, credential string) *config.TURNServer {
	cfTurnLog("debug", "CF TURN: Parsing URL", "url", url)

	var protocol string
	var host string
	var port int = 3478

	if strings.HasPrefix(url, "turns:") {
		protocol = "tls"
		port = 5349
		host = strings.TrimPrefix(url, "turns:")
		cfTurnLog("debug", "CF TURN: Detected TURNS protocol", "host_with_port", host, "default_port", port)
	} else if strings.HasPrefix(url, "turn:") {
		protocol = "udp"
		host = strings.TrimPrefix(url, "turn:")
		cfTurnLog("debug", "CF TURN: Detected TURN protocol", "host_with_port", host, "default_port", port)
	} else {
		cfTurnLog("warn", "CF TURN: Unknown protocol in URL", "url", url)
		return nil
	}

	// Parse host:port if present
	if colonIndex := strings.LastIndex(host, ":"); colonIndex != -1 {
		portStr := host[colonIndex+1:]
		originalHost := host
		host = host[:colonIndex]
		cfTurnLog("debug", "CF TURN: Found port in URL", "original", originalHost, "host", host, "port_str", portStr)

		var parsedPort int
		if p, err := fmt.Sscanf(portStr, "%d", &parsedPort); err == nil && p == 1 && parsedPort > 0 && parsedPort <= 65535 {
			port = parsedPort
			cfTurnLog("debug", "CF TURN: Successfully parsed port", "port", port)
		} else {
			cfTurnLog("warn", "CF TURN: Invalid port, using default", "port_str", portStr, "parsed", parsedPort, "default_port", port)
		}
	} else {
		cfTurnLog("debug", "CF TURN: No port specified, using default", "host", host, "default_port", port)
	}

	// Skip port 53 (DNS) as it may cause connectivity issues
	if port == 53 {
		cfTurnLog("debug", "CF TURN: Skipping port 53 (DNS)", "host", host, "port", port)
		return nil
	}

	server := &config.TURNServer{
		Host:       host,
		Port:       port,
		Protocol:   protocol,
		Username:   username,
		Credential: credential,
	}

	cfTurnLog("debug", "CF TURN: Created TURN server config", "host", server.Host, "port", server.Port, "protocol", server.Protocol, "username_len", len(server.Username), "credential_len", len(server.Credential))
	return server
}

// CFTurnManager manages Cloudflare TURN credentials
type CFTurnManager struct {
	accountID  string
	apiToken   string
	httpClient *http.Client
}

func NewCFTurnManager(accountID, apiToken string) *CFTurnManager {
	return &CFTurnManager{
		accountID:  accountID,
		apiToken:   apiToken,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (m *CFTurnManager) GetICEServers() ([]*livekit.ICEServer, error) {
	servers, err := FetchCloudflareCredentials(&config.TURNConfig{
		CFTurnKeyID: m.accountID,
		CFAPIToken:  m.apiToken,
	})
	if err != nil {
		return nil, err
	}

	var iceServers []*livekit.ICEServer
	for _, server := range servers {
		var url string
		if server.Protocol == "tls" {
			url = fmt.Sprintf("turns:%s:%d", server.Host, server.Port)
		} else {
			url = fmt.Sprintf("turn:%s:%d", server.Host, server.Port)
		}
		iceServer := &livekit.ICEServer{
			Urls:       []string{url},
			Username:   server.Username,
			Credential: server.Credential,
		}
		iceServers = append(iceServers, iceServer)
	}

	return iceServers, nil
}
