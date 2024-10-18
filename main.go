package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
	"sync"

	"golang.org/x/oauth2"
	"github.com/alexedwards/scs/v2"
)

var (
	oauth2Config *oauth2.Config
	state        = "random-string" // In a real app, generate this dynamically
)

var sessionManager *scs.SessionManager

var tokenStore = NewTokenStore()

// TokenStore manages token storage securely in memory
type TokenStore struct {
	tokens map[string]*oauth2.Token
	mutex  sync.RWMutex
}

// NewTokenStore creates a new TokenStore
func NewTokenStore() *TokenStore {
	return &TokenStore{
		tokens: make(map[string]*oauth2.Token),
	}
}

// StoreToken stores a token and returns a unique ID
func (ts *TokenStore) StoreToken(token *oauth2.Token) (string, error) {
	id := generateRandomID(32)

	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	ts.tokens[id] = token
	return id, nil
}

// GetToken retrieves a token by its ID
func (ts *TokenStore) GetToken(id string) (*oauth2.Token, bool) {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()
	token, exists := ts.tokens[id]
	return token, exists
}


func main() {
	// Initialize a new session manager and configure it to use in-memory storage
	sessionManager = scs.New()
	// sessionManager.Store = scs.NewMemoryStore()
	sessionManager.Lifetime = 24 * time.Hour
	sessionManager.IdleTimeout = 20 * time.Minute
	sessionManager.Cookie.Secure = true

	oauth2Config = &oauth2.Config{
		ClientID:     os.Getenv("AUTHLETE_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTHLETE_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:8081/callback",
		Scopes:       []string{"openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://localhost:8080/authorize", // Your auth server's authorize endpoint
			TokenURL: "http://localhost:8080/token",     // Your auth server's token endpoint
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/callback", callbackHandler)
	mux.HandleFunc("/profile", profileHandler)

	log.Println("Client is running at http://localhost:8081")
	log.Fatal(http.ListenAndServe(":8081", sessionManager.LoadAndSave(mux)))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `<h1>OAuth 2.0 Client</h1><a href="/login">Log In</a>`)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	codeVerifier := oauth2.GenerateVerifier()

	http.SetCookie(w, &http.Cookie{
		Name:     "code_verifier",
		Value:    codeVerifier,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	url := oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(codeVerifier))
	http.Redirect(w, r, url, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("state") != state {
		http.Error(w, "State invalid", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie("code_verifier")
	if err != nil {
		http.Error(w, "Code verifier not found", http.StatusBadRequest)
		return
	}
	codeVerifier := cookie.Value

	token, err := oauth2Config.Exchange(context.Background(), r.FormValue("code"), oauth2.VerifierOption(codeVerifier))
	if err != nil {
		if e, ok := err.(*oauth2.RetrieveError); ok {
			fmt.Println("Error response:", string(e.Body), e.Response.StatusCode) // Print the response body for debugging
		}

		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Store the token securely
	tokenID, err := tokenStore.StoreToken(token)
	if err != nil {
		http.Error(w, "Failed to secure token", http.StatusInternalServerError)
		return
	}

	// Store only the token ID in the session
	sessionManager.Put(r.Context(), "token_id", tokenID)

	http.Redirect(w, r, "/profile", http.StatusFound)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {

	// Retrieve the token ID from the session
	tokenID := sessionManager.GetString(r.Context(), "token_id")
	if tokenID == "" {
		http.Error(w, "No valid session", http.StatusUnauthorized)
		return
	}

	// Get the actual token using the ID
	token, exists := tokenStore.GetToken(tokenID)
	if !exists {
		http.Error(w, "Token not found", http.StatusUnauthorized)
		return
	}

	client := oauth2Config.Client(context.Background(), token)
	resp, err := client.Get("http://localhost:8080/userinfo") // Your auth server's userinfo endpoint
	if err != nil {
		http.Error(w, "Failed to get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var profile map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		http.Error(w, "Failed to parse user info: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "User Profile: %+v", profile)
}

func generateRandomID(length int) string {
    bytes := make([]byte, length)
    _, err := rand.Read(bytes)
    if err != nil {
        // This is generally safe as rand.Read only fails in exceptional circumstances.
        log.Fatalf("Error generating random bytes: %v", err)
    }
    return base64.URLEncoding.EncodeToString(bytes)[:length]
}
