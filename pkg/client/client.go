package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type RpcRequest struct {
	Method string      `json:"method"`
	Params interface{} `json:"params"`
	Token  string      `json:"token,omitempty"`
}

type RpcResponse struct {
	Error   interface{} `json:"error"`
	Message string      `json:"message"`
	Result  interface{} `json:"result"`
}

type Client struct {
	baseURL string
	token   string
	client  *http.Client
}

func resolveToken(flagToken string) string {
	if flagToken != "" {
		return flagToken
	}

	if envToken := os.Getenv("KILOVAULT_USER_TOKEN"); envToken != "" {
		return envToken
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	tokenPath := filepath.Join(home, ".config", "kilovault", "user_token.jwt")
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(data))
}

func ensureConfigDir() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configDir := filepath.Join(home, ".config", "kilovault")
	return os.MkdirAll(configDir, 0700)
}

type Config struct {
	Endpoint  string `json:"endpoint,omitempty"`
	Token     string `json:"token,omitempty"`
	JWTSecret string `json:"jwt_secret,omitempty"`
}

func LoadConfigFile() (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	configPath := filepath.Join(home, ".config", "kilovault", "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func SaveConfig(cfg *Config) error {
	if err := ensureConfigDir(); err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configPath := filepath.Join(home, ".config", "kilovault", "config.json")
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0600)
}

func resolveEndpoint(flagEndpoint string) string {
	if flagEndpoint != "" {
		return flagEndpoint
	}

	if envEndpoint := os.Getenv("KILOVAULT_URL"); envEndpoint != "" {
		return envEndpoint
	}

	cfg, err := LoadConfigFile()
	if err == nil && cfg.Endpoint != "" {
		return cfg.Endpoint
	}

	return "http://localhost:5096"
}

func SaveToken(token string) error {
	if err := ensureConfigDir(); err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	tokenPath := filepath.Join(home, ".config", "kilovault", "user_token.jwt")
	return os.WriteFile(tokenPath, []byte(token), 0600)
}

func New(baseURL string) *Client {
	return &Client{
		baseURL: resolveEndpoint(baseURL),
		client:  &http.Client{},
	}
}

func NewWithToken(baseURL, token string) *Client {
	c := New(baseURL)
	c.token = resolveToken(token)
	return c
}

func (c *Client) SetToken(token string) {
	c.token = token
}

func (c *Client) call(method string, params interface{}) (*RpcResponse, error) {
	req := RpcRequest{
		Method: method,
		Params: params,
		Token:  c.token,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", c.baseURL+"/rpc", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rpcResp RpcResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, err
	}

	return &rpcResp, nil
}

// Vault.Get
type VaultGetParams struct {
	Key string `json:"key"`
}

type VaultGetResult struct {
	Value string `json:"value"`
}

func (c *Client) VaultGet(key string) (*VaultGetResult, error) {
	resp, err := c.call("vault.get", VaultGetParams{Key: key})
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("error - %s", resp.Message)
	}

	data, _ := json.Marshal(resp.Result)
	var result VaultGetResult
	json.Unmarshal(data, &result)
	return &result, nil
}

// Vault.Set
type VaultSetParams struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (c *Client) VaultSet(key, value string) error {
	resp, err := c.call("vault.set", VaultSetParams{Key: key, Value: value})
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("error - %s", resp.Message)
	}

	return nil
}

// System.Alive
type SystemAliveResult struct {
	Timestamp string `json:"timestamp"`
}

func (c *Client) SystemAlive() (*SystemAliveResult, error) {
	resp, err := c.call("system.alive", map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("error - %s", resp.Message)
	}

	data, _ := json.Marshal(resp.Result)
	var result SystemAliveResult
	json.Unmarshal(data, &result)
	return &result, nil
}

// Auth.GetToken
type AuthGetTokenParams struct {
	Secret      string                 `json:"secret"`
	UserID      string                 `json:"userId"`
	Permissions interface{}            `json:"permissions,omitempty"`
	ExpiresIn   *int                   `json:"expiresIn,omitempty"`
}

type AuthGetTokenResult struct {
	Token string `json:"token"`
}

func (c *Client) AuthGetToken(secret, userID string, permissions interface{}, expiresIn *int) (*AuthGetTokenResult, error) {
	resp, err := c.call("auth.getToken", AuthGetTokenParams{
		Secret:      secret,
		UserID:      userID,
		Permissions: permissions,
		ExpiresIn:   expiresIn,
	})
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("error - %s", resp.Message)
	}

	data, _ := json.Marshal(resp.Result)
	var result AuthGetTokenResult
	json.Unmarshal(data, &result)
	return &result, nil
}

// Admin.List
type VaultAdminListParams struct {
	UserID *string `json:"userId,omitempty"`
}

type VaultKey struct {
	Key    string `json:"key"`
	UserID string `json:"userId"`
}

type VaultAdminListResult struct {
	Keys []VaultKey `json:"keys"`
}

func (c *Client) VaultAdminList(userID *string) (*VaultAdminListResult, error) {
	resp, err := c.call("vault.admin.list", VaultAdminListParams{UserID: userID})
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("error - %s", resp.Message)
	}

	data, _ := json.Marshal(resp.Result)
	var result VaultAdminListResult
	json.Unmarshal(data, &result)
	return &result, nil
}

// Admin.Get
type VaultAdminGetParams struct {
	UserID string `json:"userId"`
	Key    string `json:"key"`
}

type VaultAdminGetResult struct {
	Value string `json:"value"`
}

func (c *Client) VaultAdminGet(userID, key string) (*VaultAdminGetResult, error) {
	resp, err := c.call("vault.admin.get", VaultAdminGetParams{UserID: userID, Key: key})
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("error - %s", resp.Message)
	}

	data, _ := json.Marshal(resp.Result)
	var result VaultAdminGetResult
	json.Unmarshal(data, &result)
	return &result, nil
}

// Admin.Set
type VaultAdminSetParams struct {
	UserID string `json:"userId"`
	Key    string `json:"key"`
	Value  string `json:"value"`
}

func (c *Client) VaultAdminSet(userID, key, value string) error {
	resp, err := c.call("vault.admin.set", VaultAdminSetParams{UserID: userID, Key: key, Value: value})
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("error - %s", resp.Message)
	}

	return nil
}

// Admin.Delete
type VaultAdminDeleteParams struct {
	UserID string `json:"userId"`
	Key    string `json:"key"`
}

type VaultAdminDeleteResult struct {
	Deleted bool `json:"deleted"`
}

func (c *Client) VaultAdminDelete(userID, key string) (*VaultAdminDeleteResult, error) {
	resp, err := c.call("vault.admin.delete", VaultAdminDeleteParams{UserID: userID, Key: key})
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("error - %s", resp.Message)
	}

	data, _ := json.Marshal(resp.Result)
	var result VaultAdminDeleteResult
	json.Unmarshal(data, &result)
	return &result, nil
}

// History.Get
type HistoryGetParams struct {
	UserID *string `json:"userId,omitempty"`
}

type HistoryEntry struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	UserID    string `json:"userId"`
	Key       string `json:"key"`
	Action    string `json:"action"`
}

type HistoryGetResult struct {
	History []HistoryEntry `json:"history"`
}

func (c *Client) HistoryGet(userID *string) (*HistoryGetResult, error) {
	resp, err := c.call("history.get", HistoryGetParams{UserID: userID})
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("error - %s", resp.Message)
	}

	data, _ := json.Marshal(resp.Result)
	var result HistoryGetResult
	json.Unmarshal(data, &result)
	return &result, nil
}

// History.Cleanup
type HistoryCleanupResult struct {
	Count int `json:"count"`
}

func (c *Client) HistoryCleanup() (*HistoryCleanupResult, error) {
	resp, err := c.call("history.cleanup", map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("error - %s", resp.Message)
	}

	data, _ := json.Marshal(resp.Result)
	var result HistoryCleanupResult
	json.Unmarshal(data, &result)
	return &result, nil
}
