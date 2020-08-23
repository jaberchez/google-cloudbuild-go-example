/*
	- Example Google Cloud Run to received events from GitHub webhooks
	- Publish the payload from GitHub in a topic of PubSub

	Notes: - This component does not run CloudBuild directly because GitHub has a short timeout to answer
	       - For this example only push events are allowed from GitHub
*/

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/pubsub"
	"github.com/gorilla/mux"
	"google.golang.org/api/option"
)

var (
	warningLogger *log.Logger
	infoLogger    *log.Logger
	errorLogger   *log.Logger

	port         string
	gcpSaKey     string
	gcpProjectID string
	topicName    string
	gitHubSecret string
)

// Main HTTP route
func homeHandler(w http.ResponseWriter, r *http.Request) {
	var attr = make(map[string]string)
	var remoteIP string

	defer r.Body.Close()

	// Get the event from GitHub
	gitHubEvent := r.Header.Get("X-GitHub-Event")

	if len(gitHubEvent) == 0 {
		warningLogger.Println("Header X-GitHub-Event not found")

		//w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		//http.Error(w, "Bad request", http.StatusBadRequest)

		sendError(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Implement Ping
	if strings.ToLower(gitHubEvent) == "ping" {
		infoLogger.Println("Received ping event")

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("\"msg\": \"pong\""))

		return
	}

	attr["github_event"] = gitHubEvent

	// Get the signature
	gitHubSignature := r.Header.Get("X-Hub-Signature")

	if len(gitHubSignature) == 0 {
		warningLogger.Println("Header X-Hub-Signature not found")

		sendError(w, "Forbidden", http.StatusForbidden)
		return
	}

	gotHash := strings.SplitN(gitHubSignature, "=", 2)

	if gotHash[0] != "sha1" {
		warningLogger.Println("Not sha1 signature: " + gotHash[0])

		sendError(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Check if request come from GitHub
	forwarded := r.Header.Get("X-FORWARDED-FOR")

	if len(forwarded) > 0 {
		remoteIP = forwarded
	} else {
		remoteIP = strings.Split(r.RemoteAddr, ":")[0]
	}

	ok, err := isRequestFromGitHub(remoteIP)

	if err != nil {
		warningLogger.Println(err)

		// We don't specify the error
		sendError(w, "Internal Server error", http.StatusInternalServerError)
		return
	}

	if !ok {
		infoLogger.Println("IP not allowed: " + remoteIP)

		sendError(w, "Forbidden", http.StatusForbidden)
		return
	}

	// OK request comes from GitHub
	//
	// Get the payload
	payload, err := ioutil.ReadAll(r.Body)

	if err != nil {
		warningLogger.Println(err)

		sendError(w, "Internal Server error", http.StatusInternalServerError)
		return
	}

	// Check the signature
	hash := hmac.New(sha1.New, []byte(gitHubSecret))

	if _, err := hash.Write(payload); err != nil {
		warningLogger.Printf("Cannot compute the HMAC for request: %s\n", err)

		sendError(w, "Forbidden", http.StatusForbidden)
		return
	}

	expectedHash := hex.EncodeToString(hash.Sum(nil))

	if gotHash[1] != expectedHash {
		warningLogger.Println("Hash does not match")

		sendError(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Publish the payload into the PubSub topic
	ctx := context.Background()
	client, err := pubsub.NewClient(ctx, gcpProjectID, option.WithCredentialsJSON([]byte(gcpSaKey)))

	if err != nil {
		warningLogger.Println(err)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.Error(w, "Internal Server error", http.StatusInternalServerError)

		return
	}

	topic := client.Topic(topicName)
	defer topic.Stop()

	res := topic.Publish(ctx, &pubsub.Message{
		Data:       payload,
		Attributes: attr,
	})

	id, err := res.Get(ctx)

	if err != nil {
		warningLogger.Println(err)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.Error(w, "Internal Server error", http.StatusInternalServerError)

		return
	}

	infoLogger.Printf("OK: Published a message with a message ID: %s\n", id)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{ \"message\": \"OK: Message ID queued " + id + "\"}"))
}

func init() {
	//infoLogger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	//warningLogger = log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	//errorLogger = log.New(os.Stdout, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)

	infoLogger = log.New(os.Stdout, "[INFO] ", log.Ldate|log.Ltime)
	warningLogger = log.New(os.Stdout, "[WARNING] ", log.Ldate|log.Ltime)
	errorLogger = log.New(os.Stdout, "[ERROR] ", log.Ldate|log.Ltime)
}

func main() {
	port = os.Getenv("SERVER_PORT")
	gcpSaKey = os.Getenv("GCP_SA_KEY")
	gcpProjectID = os.Getenv("GCP_PROJECT_ID")
	topicName = os.Getenv("PUBSUB_TOPIC_NAME")
	gitHubSecret = os.Getenv("GITHUB_SECRET")

	if len(port) == 0 {
		port = "8080"
	}

	// Check mandatory environment variables
	if len(gcpSaKey) == 0 {
		errorLogger.Println("\"GCP_SA_KEY\" environment variable not defined or empty")
		os.Exit(1)
	}

	if len(gcpProjectID) == 0 {
		errorLogger.Println("\"GCP_PROJECT_ID\" environment variable not defined or empty")
		os.Exit(1)
	}

	if len(topicName) == 0 {
		errorLogger.Println("\"PUBSUB_TOPIC_NAME\" environment variable not defined or empty")
		os.Exit(1)
	}

	if len(gitHubSecret) == 0 {
		errorLogger.Println("\"GITHUB_SECRET\" environment variable not defined or empty")
		os.Exit(1)
	}

	r := mux.NewRouter()
	r.HandleFunc("/", homeHandler).Methods("POST")

	server := &http.Server{
		Handler:      r,
		Addr:         "0.0.0.0:" + port,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	infoLogger.Println("Listening on port " + port)
	err := server.ListenAndServe()

	if err != nil {
		errorLogger.Println(err)
		os.Exit(1)
	}
}
