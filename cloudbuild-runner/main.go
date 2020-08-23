/*
	- Example of Google Cloud Run for execute a cloudbuild.yaml file from a GitHub repo
	- The cloudbuild.yaml must exist in the root of the repo. This Cloud Run is triggered by
	  a suscription to PubSub
	- The message of PubSub topic is the payload sended by GitHub

	Notes: For this example only push events are allowed from GitHub
*/

package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/ghodss/yaml"
	"github.com/gorilla/mux"
	"google.golang.org/api/cloudbuild/v1"
	"google.golang.org/api/option"
)

var (
	warningLogger *log.Logger
	infoLogger    *log.Logger
	errorLogger   *log.Logger

	port string

	gcpSaKey            string
	gcpProjectID        string
	gcpCloudBuildBucket string
)

const dirDownload string = "/tmp"

// Source: https://cloud.google.com/run/docs/triggering/pubsub-push
type PubSubMessage struct {
	Message struct {
		Data       []byte            `json:"data,omitempty"`
		ID         string            `json:"messageId"`
		Attributes map[string]string `json:"attributes"`
	} `json:"message"`
	Subscription string `json:"subscription"`
}

// We only need a few fields from the Github's payload
type GitHubPush struct {
	HeadCommit struct {
		ID string `json:"id"`
	} `json:"head_commit"`

	Repository struct {
		Name    string `json:"name"`
		HtmlUrl string `json:"html_url"`
	} `json:"repository"`

	Branch string `json:"ref"`
}

// Main HTTP route
func homeHandler(w http.ResponseWriter, r *http.Request) {
	var pubSubMsg PubSubMessage

	defer r.Body.Close()

	// Get the PubSub message
	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		warningLogger.Println(err)

		sendError(w, "Internal Server error", http.StatusInternalServerError)
		return
	}

	if err := json.Unmarshal(body, &pubSubMsg); err != nil {
		warningLogger.Printf("json.Unmarshal: %v", err)

		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Notes: For this example only handle push events
	if strings.ToLower(pubSubMsg.Message.Attributes["github_event"]) != "push" {
		warningLogger.Println("No push event")

		sendError(w, "Only push events allowed", http.StatusBadRequest)
		return
	}

	dirTmp, err := ioutil.TempDir(dirDownload, "github_repo_")

	if err != nil {
		warningLogger.Println(err)

		sendError(w, "Internal Server error", http.StatusInternalServerError)
		return
	}

	defer os.RemoveAll(dirTmp)

	dirRepo, repoZipFile, err := downloadRepo(pubSubMsg.Message.Data, dirTmp)

	if err != nil {
		warningLogger.Println(err)

		sendError(w, "Internal Server error", http.StatusInternalServerError)
		return
	}

	err = runCloudBuild(dirRepo, getNameFile(repoZipFile))

	if err != nil {
		warningLogger.Println(err)

		sendError(w, "Internal Server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{ \"message\": \"OK\"}"))
}

// Download the repo from GitHub which trigger the push event
// Return the local path to the repo downloaded, the name of the zip file and error
// Notes: Download the repo in zip format from a particular commit, specifically that of head_commit
func downloadRepo(payload []byte, dirTmp string) (string, string, error) {
	var gitHubPush GitHubPush

	if err := json.Unmarshal(payload, &gitHubPush); err != nil {
		return "", "", err
	}

	nameFile := fmt.Sprintf("%s.zip", gitHubPush.HeadCommit.ID)

	url := fmt.Sprintf("%s/archive/%s", gitHubPush.Repository.HtmlUrl, nameFile)

	response, err := http.Get(url)

	if err != nil {
		return "", "", err
	}

	defer response.Body.Close()

	pathFile := dirDownload + "/" + nameFile

	// Create the file
	out, err := os.Create(pathFile)

	if err != nil {
		return "", "", err
	}

	defer out.Close()

	// Write the body to the file
	_, err = io.Copy(out, response.Body)

	if err != nil {
		return "", "", err
	}

	// Unzip the file
	err = unzipFile(pathFile, dirTmp)

	if err != nil {
		return "", "", err
	}

	// OK unzip the file, return the correct path
	// Notes: Zip file contains a folder which name is namerepo-headcommitid
	// Example: test-cloudbuild-4be3bf100b7d2076bcc1b3814a16c573b9875a17
	return fmt.Sprintf("%s/%s-%s", dirTmp, gitHubPush.Repository.Name, gitHubPush.HeadCommit.ID), pathFile, nil
}

// Unzip the file downloaded from GitHub
// Return error
func unzipFile(src, dest string) error {
	totalFiles := 0

	r, err := zip.OpenReader(src)

	if err != nil {
		return err
	}

	defer r.Close()

	for f := range r.File {
		dstpath := filepath.Join(dest, r.File[f].Name)

		if !strings.HasPrefix(dstpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("%s: illegal file path", src)
		}

		if r.File[f].FileInfo().IsDir() {
			if err := os.MkdirAll(dstpath, os.ModePerm); err != nil {
				return err
			}
		} else {
			if rc, err := r.File[f].Open(); err != nil {
				return err
			} else {
				defer rc.Close()

				if of, err := os.OpenFile(dstpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, r.File[f].Mode()); err != nil {
					return err
				} else {
					defer of.Close()
					if _, err = io.Copy(of, rc); err != nil {
						return err
					} else {
						of.Close()
						rc.Close()

						totalFiles++
					}
				}
			}
		}
	}

	if totalFiles == 0 {
		return fmt.Errorf("zip file is empty")
	}

	return nil
}

// Save the zip file to a GCP bucket
// Return error
func saveRepoToBucket(pathFile string) error {
	defer os.Remove(pathFile)

	ctx := context.Background()
	client, err := storage.NewClient(ctx, option.WithCredentialsJSON([]byte(gcpSaKey)))

	if err != nil {
		return err
	}

	defer client.Close()

	// Open the repo's file
	f, err := os.Open(pathFile)

	if err != nil {
		return err
	}

	defer f.Close()

	ctx, cancel := context.WithTimeout(ctx, time.Second*50)
	defer cancel()

	// Upload zip file
	wc := client.Bucket(gcpCloudBuildBucket).Object(getNameFile(pathFile)).NewWriter(ctx)

	if _, err = io.Copy(wc, f); err != nil {
		return err
	}

	if err := wc.Close(); err != nil {
		return err
	}

	return nil
}

// Execute CloudBuild
// Return error
func runCloudBuild(dirRepo string, repoZipFile string) error {
	var cloudBuildFile string
	var fileInfo os.FileInfo
	var cloudBuildData cloudbuild.Build
	var source cloudbuild.Source
	var storageSource cloudbuild.StorageSource

	// Check if file cloudbuild exists in repo
	// Notes: Check both extensions: yaml and yml
	for _, f := range []string{"cloudbuild.yaml", "cloudbuild.yml"} {
		if info, err := os.Stat(filepath.Join(dirRepo, f)); !os.IsNotExist(err) {
			// File exists
			cloudBuildFile = f
			fileInfo = info
			break
		}
	}

	if len(cloudBuildFile) == 0 {
		return fmt.Errorf("cloudbuild.(yaml|yml) file not found in repo")
	}

	// File exists, check the size
	if fileInfo.Size() == 0 {
		return fmt.Errorf("%s file found in repo but it is empty", cloudBuildFile)
	}

	// Store the downloaded repo zip to a GCP bucket
	err := saveRepoToBucket(dirDownload + "/" + repoZipFile)

	if err != nil {
		return err
	}

	// Convert YAML to JSON
	jsonData, err := convertYAMLtoJSON(dirRepo + "/" + cloudBuildFile)

	if err != nil {
		return err
	}

	err = json.Unmarshal(jsonData, &cloudBuildData)

	if err != nil {
		return err
	}

	// Fill in the data cloudBuildData needs before run
	storageSource.Bucket = gcpCloudBuildBucket
	storageSource.Object = repoZipFile
	source.StorageSource = &storageSource
	cloudBuildData.Source = &source

	// Create CloudBuild build
	ctx := context.Background()
	cloudbuildService, err := cloudbuild.NewService(ctx, option.WithCredentialsJSON([]byte(gcpSaKey)))

	if err != nil {
		return err
	}

	createBuild := cloudbuildService.Projects.Builds.Create(gcpProjectID, &cloudBuildData)

	// Run CloudBuild build
	_, err = createBuild.Do()

	if err != nil {
		return err
	}

	return nil
}

// Convert file cloudbuild.yaml to JSON
// Return []byte with the JSON and error
func convertYAMLtoJSON(fileYaml string) ([]byte, error) {
	yamlData, err := ioutil.ReadFile(fileYaml)

	if err != nil {
		return []byte(""), err
	}

	jsonData, err := yaml.YAMLToJSON(yamlData)

	if err != nil {
		return []byte(""), err
	}

	return jsonData, nil
}

// Get the basename of a path to a file
// Return basename
func getNameFile(pathFile string) string {
	var nameFile string

	pos := strings.LastIndex(pathFile, "/")

	if pos == -1 {
		nameFile = pathFile
	} else {
		nameFile = pathFile[pos+1:]
	}

	return nameFile
}

// Send error to HTTP client
func sendError(w http.ResponseWriter, msg string, httpStatus int) {
	jsonMessage := fmt.Sprintf("{\"message\": \"%s\"}", msg)

	w.Header().Set("Content-Type", "application/json")
	http.Error(w, jsonMessage, httpStatus)
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
	gcpCloudBuildBucket = os.Getenv("GCP_CLOUDBUILD_BUCKET")

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

	if len(gcpCloudBuildBucket) == 0 {
		errorLogger.Println("\"GCP_CLOUDBUILD_BUCKET\" environment variable not defined or empty")
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
