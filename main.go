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
	"sync"

	"golang.org/x/oauth2"
)

var (
	oauth2Config *oauth2.Config
	tokenStore   = NewTokenStore()
)

type TokenStore struct {
	tokens map[string]*oauth2.Token
	mutex  sync.RWMutex
}

func NewTokenStore() *TokenStore {
	return &TokenStore{
		tokens: make(map[string]*oauth2.Token),
	}
}

func (ts *TokenStore) StoreToken(token *oauth2.Token) (string, error) {
	id := generateRandomString(32)
	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	ts.tokens[id] = token
	return id, nil
}

func (ts *TokenStore) GetToken(id string) (*oauth2.Token, bool) {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()
	token, exists := ts.tokens[id]
	return token, exists
}

func (ts *TokenStore) DeleteToken(id string) {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()
	delete(ts.tokens, id)
}

func main() {
	oauth2Config = &oauth2.Config{
		ClientID:     os.Getenv("AUTH_SERVER_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTH_SERVER_CLIENT_SECRET"),
		RedirectURL:  "http://localhost:8081/callback",
		Scopes:       []string{"openid", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://localhost:8080/authorize",
			TokenURL: "http://localhost:8080/token",
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/callback", callbackHandler)
	mux.HandleFunc("/profile", profileHandler)
	mux.HandleFunc("/logout", logoutHandler)

	log.Println("Client is running at http://localhost:8081")
	log.Fatal(http.ListenAndServe(":8081", mux))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<h1>OAuth 2.0 Client</h1><a href="/login">Log In</a>`)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	state := generateRandomString(32)
	codeVerifier := oauth2.GenerateVerifier()

	// Store state and code verifier in cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "state",
		Value:    state,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "code_verifier",
		Value:    codeVerifier,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	url := oauth2Config.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		oauth2.S256ChallengeOption(codeVerifier),
	)
	http.Redirect(w, r, url, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	stateCookie, err := r.Cookie("state")
	if err != nil || stateCookie.Value != r.FormValue("state") {
		http.Error(w, "State invalid", http.StatusBadRequest)
		return
	}

	verifierCookie, err := r.Cookie("code_verifier")
	if err != nil {
		http.Error(w, "Code verifier not found", http.StatusBadRequest)
		return
	}

	token, err := oauth2Config.Exchange(
		context.Background(),
		r.FormValue("code"),
		oauth2.VerifierOption(verifierCookie.Value),
	)
	if err != nil {
		log.Printf("Token exchange error: %v", err)
		http.Error(w, "Authentication failed", http.StatusInternalServerError)
		return
	}

	tokenID, err := tokenStore.StoreToken(token)
	if err != nil {
		http.Error(w, "Failed to store token", http.StatusInternalServerError)
		return
	}

	// Clear OAuth flow cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "state",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Path:     "/",
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "code_verifier",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Path:     "/",
	})

	// Set token ID cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token_id",
		Value:    tokenID,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	http.Redirect(w, r, "/profile", http.StatusFound)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token_id")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	token, exists := tokenStore.GetToken(cookie.Value)
	if !exists {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	client := oauth2Config.Client(context.Background(), token)
	resp, err := client.Get("http://localhost:8080/userinfo")
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var profile map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		http.Error(w, "Failed to parse user info", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
		<h1>Profile</h1>
		<pre>%+v</pre>
		<p><a href="/logout">Logout</a></p>
	`, profile)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("token_id"); err == nil {
		tokenStore.DeleteToken(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token_id",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Path:     "/",
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}
