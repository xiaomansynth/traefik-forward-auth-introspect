package introspection

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"

	"encoding/json"
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/mesosphere/traefik-forward-auth/internal/configuration"
	internallog "github.com/mesosphere/traefik-forward-auth/internal/log"
)

type Introspection struct {
	log logrus.FieldLogger

	config *configuration.Config

	introspectionEndpoint string
}

func NewIntrospection(config *configuration.Config) *Introspection {
	resp, err := http.Get(config.ProviderURI)
	if err != nil {
		logrus.Fatalf("Failed to get provider URI: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Fatalf("Failed to read response body: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		logrus.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	introspectionEndpoint, ok := result["introspection_endpoint"].(string)
	if !ok {
		logrus.Warnf("Introspection endpoint not found in discovery response %s, will fail all validation", body)
	}
	logrus.Infof("Called into %s and found introspection to be %s", config.ProviderURI, introspectionEndpoint)
	// query config.ProviderURI to get introspection URI
	return &Introspection{
		log:                   internallog.NewDefaultLogger(config.LogLevel, config.LogFormat),
		config:                config,
		introspectionEndpoint: introspectionEndpoint,
	}
}

func (i *Introspection) Validate(bearerToken string) bool {
	if i.introspectionEndpoint == "" {
		i.log.Warnf("There is no introspection endpoint found so bearer token %s will be considered invalid", bearerToken)
		return false
	}
	// Prepare the request payload
	payload := fmt.Sprintf("token=%s", bearerToken)

	// Create the request
	req, err := http.NewRequest("POST", i.introspectionEndpoint, bytes.NewBuffer([]byte(payload)))
	if err != nil {
		i.log.Errorf("Failed to create request: %v", err)
		return false
	}
	// introspect do not expect json payload. Don't do below
	// req.Header.Set("Content-Type", "application/json")

	// Set Basic Auth header
	basicAuthToken := base64.StdEncoding.EncodeToString([]byte(i.config.ClientID + ":" + i.config.ClientSecret))
	req.Header.Set("Authorization", "Basic "+basicAuthToken)

	// Perform the request
	client := &http.Client{}
	// Read and log the request body
	reqBody, err := io.ReadAll(req.Body)
	if err != nil {
		i.log.Errorf("Failed to read request body: %v", err)
		return false
	}
	i.log.Infof("Request body: %s", string(reqBody))

	// Create a new reader with the same content
	req.Body = io.NopCloser(bytes.NewBuffer(reqBody))
	resp, err := client.Do(req)
	if err != nil {
		i.log.Errorf("Failed to perform request: %v", err)
		return false
	}
	defer resp.Body.Close()

	// Read and parse the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		i.log.Errorf("Failed to read response body: %v", err)
		return false
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		i.log.Errorf("Failed to unmarshal response: %v", err)
		return false
	}

	// Check if the token is active
	active, ok := result["active"].(bool)
	if !ok || !active {
		i.log.Warnf("Token %s is not active. Result is %s", bearerToken, body)
		return false
	}
	i.log.Info("Token validated for %s. It is active", bearerToken)
	return true
}
