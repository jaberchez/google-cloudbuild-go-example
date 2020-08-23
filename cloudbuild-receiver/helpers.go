/*
	Helper functions
*/

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
)

// Check if request comes from GitHub
// Receive the remote ip address as parameter
// Return true if come from GitHub, otherwise false and error
func isRequestFromGitHub(ip string) (bool, error) {
	var result = make(map[string]interface{})

	currentIP := net.ParseIP(ip)

	// Request the ip ranges from GitHub
	//
	// Notes: GitHub returns a json. We use the "hooks" key
	resp, err := http.Get("https://api.github.com/meta")

	if err != nil {
		return false, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return false, err
	}

	err = json.Unmarshal(body, &result)

	if err != nil {
		return false, err
	}

	if val, ok := result["hooks"]; ok {
		var ipFromGitHub bool = false

		for _, d := range val.([]interface{}) {
			i := d.(string)

			if strings.Contains(i, "/") {
				// Network
				_, ipv4Net, err := net.ParseCIDR(i)

				if err != nil {
					return false, err
				}

				if ipv4Net.Contains(currentIP) {
					// OK, request from GitHub
					return true, nil
				}

			} else {
				// IP
				if ip == i {
					ipFromGitHub = true
					break
				}
			}
		}

		return ipFromGitHub, nil
	}

	return false, errors.New("Data not found from GitHub")
}

// Send error to HTTP client
// Received http.ResponseWriter, message an httpStatus as parameters
func sendError(w http.ResponseWriter, msg string, httpStatus int) {
	jsonMessage := fmt.Sprintf("{\"message\": \"%s\"}", msg)

	w.Header().Set("Content-Type", "application/json")
	http.Error(w, jsonMessage, httpStatus)
}
