package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
	"github.com/alexedwards/scs/v2"
)

var (
	oauth2Config *oauth2.Config
	state        = "random-string" // In a real app, generate this dynamically
)

var sessionManager *scs.SessionManager

func main() {
    // Initialize a new session manager and configure it to use in-memory storage
    sessionManager = scs.New()
    // sessionManager.Store = scs.NewMemoryStore()
    sessionManager.Lifetime = 24 * time.Hour
    sessionManager.IdleTimeout = 20 * time.Minute
    sessionManager.Cookie.Secure = true

	oauth2Config = &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
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

	// Store the token in the session or encrypt and store in a cookie
	sessionManager.Put(r.Context(), "message", token.AccessToken)
	// For this example, we'll just display it
	fmt.Fprintf(w, `<p>Access Token: %s</p><br><a href="/profile">Fetch Profile</a>`, token.AccessToken)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	// In a real app, get the token from the session or cookie
	msg := sessionManager.GetString(r.Context(), "message")

	token := &oauth2.Token{AccessToken: msg}

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
