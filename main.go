package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/L-chaCon/go_server/internal/auth"
	"github.com/L-chaCon/go_server/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	jwtSecret      string
	polkaKey       string
}

const (
	ExpiresAccessTokenTime  time.Duration = 60 * 60 * time.Second
	ExpiresRefreshTokenTime time.Duration = 60 * 24 * time.Hour
	UserUpdateEvent         string        = "user.upgraded"
)

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Printf("Unable to connect to database: %s", err)
		return
	}
	dbQueries := database.New(db)

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Print("Not jwtSecret found")
		return
	}
	polkaKey := os.Getenv("POLKA_KEY")
	if polkaKey == "" {
		log.Print("Not polkaKey found")
		return
	}
	apiCfg := apiConfig{
		fileserverHits: atomic.Int32{},
		db:             dbQueries,
		jwtSecret:      jwtSecret,
		polkaKey:       polkaKey,
	}
	mux := http.NewServeMux()
	mux.Handle(
		"/app/",
		apiCfg.middlewareMetricsInc(
			http.StripPrefix(
				"/app/",
				http.FileServer(http.Dir(".")),
			),
		),
	)
	mux.HandleFunc("GET /api/healthz", healthzHandler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("POST /api/users", apiCfg.createUserHandler)
	mux.HandleFunc("PUT /api/users", apiCfg.updateUserHandler)
	mux.HandleFunc("POST /api/login", apiCfg.loginHandler)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeHandler)
	mux.HandleFunc("POST /api/chirps", apiCfg.createChirpHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{id}", apiCfg.getChirpHandler)
	mux.HandleFunc("DELETE /api/chirps/{id}", apiCfg.deleteChirpHandler)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.upgradeUser)

	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}
	server.ListenAndServe()
}

type User struct {
	ID          uuid.UUID `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Email       string    `json:"email"`
	IsChirpyRed bool      `json:"is_chirpy_red"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, req)
	})
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	response := fmt.Sprintf(`
<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`,
		cfg.fileserverHits.Load())
	w.Write([]byte(response))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, req *http.Request) {
	if os.Getenv("PLATFORM") != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	cfg.fileserverHits.Store(0)
	cfg.db.DeleteAllUsers(req.Context())
	w.WriteHeader(http.StatusOK)
}

func (cfg *apiConfig) createUserHandler(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type response struct {
		User
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error decoding parameters", err)
		return
	}
	hashPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error hashing password", err)
		return
	}

	user, err := cfg.db.CreateUser(
		req.Context(),
		database.CreateUserParams{
			Email:          sql.NullString{String: params.Email, Valid: true},
			HashedPassword: hashPassword,
		},
	)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Not able to creare User", err)
		return
	}
	respondWithJSON(w, http.StatusCreated, response{
		User: User{
			ID:          user.ID,
			CreatedAt:   user.CreatedAt.Time,
			UpdatedAt:   user.UpdatedAt.Time,
			Email:       user.Email.String,
			IsChirpyRed: user.IsChirpyRed,
		},
	})
}

func (cfg *apiConfig) updateUserHandler(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type response struct {
		User
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Error decoding parameters", err)
		return
	}

	accessToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "No token send", err)
		return
	}

	userID, err := auth.ValidateJWT(accessToken, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Error ValidateJWT", err)
		return
	}

	hashPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error hashing password", err)
		return
	}

	user, err := cfg.db.UpdateUser(req.Context(), database.UpdateUserParams{
		ID:             userID,
		HashedPassword: hashPassword,
		Email: sql.NullString{
			String: params.Email,
			Valid:  true,
		},
	})
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Error finding user", err)
		return
	}

	respondWithJSON(w, http.StatusOK, response{
		User: User{
			ID:          user.ID,
			Email:       user.Email.String,
			IsChirpyRed: user.IsChirpyRed,
		},
	})
}

func (cfg *apiConfig) upgradeUser(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Event string            `json:"event"`
		Data  map[string]string `json:"data"`
	}
	type response struct {
		User
	}

	// Check polka key
	apiKey, err := auth.GetAPIKey(req.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Error getting the apiKey", err)
		return
	}

	if cfg.polkaKey != apiKey {
		respondWithError(w, http.StatusUnauthorized, "Not the same apiKey for polka", err)
		return
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Error decoding parameters", err)
		return
	}

	if params.Event != UserUpdateEvent {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	userID, err := uuid.Parse(params.Data["user_id"])
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Incorrect user ID format", err)
		return
	}
	err = cfg.db.UpgradeUser(req.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Not able to upgrade user", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type response struct {
		User
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusCreated, "Error decoding parameters", err)
		return
	}

	user, err := cfg.db.GetUserByEmail(
		req.Context(),
		sql.NullString{String: params.Email, Valid: true},
	)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password", nil)
	}
	err = auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password", nil)
	}

	token, err := auth.MakeJWT(
		user.ID,
		cfg.jwtSecret,
		ExpiresAccessTokenTime,
	)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error creating JWT", err)
	}

	refreshToken, err := cfg.db.CreateRefreshToken(
		req.Context(),
		database.CreateRefreshTokenParams{
			Token:     auth.MakeRefreshToken(),
			ExpiresAt: time.Now().Add(ExpiresRefreshTokenTime),
			UserID:    user.ID,
		},
	)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error creating RefreshToken", err)
	}

	respondWithJSON(w, http.StatusOK, response{
		User: User{
			ID:          user.ID,
			CreatedAt:   user.CreatedAt.Time,
			UpdatedAt:   user.UpdatedAt.Time,
			Email:       user.Email.String,
			IsChirpyRed: user.IsChirpyRed,
		},
		Token:        token,
		RefreshToken: refreshToken.Token,
	})
}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, req *http.Request) {
	type response struct {
		Token string `json:"token"`
	}

	refreshToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "No token send", err)
		return
	}

	userID, err := cfg.db.GetUserFromRefreshToken(req.Context(), refreshToken)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "No user found", err)
		return
	}

	accessToken, err := auth.MakeJWT(
		userID,
		cfg.jwtSecret,
		ExpiresAccessTokenTime,
	)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error creating JWT", err)
	}

	respondWithJSON(w, http.StatusOK, response{
		Token: accessToken,
	})
}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, req *http.Request) {
	refreshToken, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "No token send", err)
		return
	}

	err = cfg.db.RevokeRefreshToken(req.Context(), refreshToken)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "No token found", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	type response struct {
		Chirp
	}

	decoder := json.NewDecoder(req.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error decoding parameters", err)
		return
	}

	// Check if th token is correct.
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "No token send", err)
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Error ValidateJWT", err)
		return
	}

	// The body can't be over 140 characters
	if len(params.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long", nil)
		return
	}
	cleanBody := cleanResponse(params.Body)

	chirp, err := cfg.db.CreateChirp(
		req.Context(),
		database.CreateChirpParams{
			Body:   cleanBody,
			UserID: userID,
		},
	)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Not able to creare chirp", err)
		return
	}

	respondWithJSON(w, http.StatusCreated, response{
		Chirp: Chirp{
			ID:        chirp.ID,
			Body:      chirp.Body,
			CreatedAt: chirp.CreatedAt.Time,
			UpdatedAt: chirp.UpdatedAt.Time,
			UserID:    chirp.UserID,
		},
	})
}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, req *http.Request) {
	chirps, err := cfg.db.GetChirps(req.Context())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Not able to get chirps", err)
		return
	}

	authorID := uuid.Nil
	authorIDStr := req.URL.Query().Get("author_id")
	if authorIDStr != "" {
		authorID, err = uuid.Parse(authorIDStr)
		if err != nil {
			respondWithError(w, http.StatusNotFound, "Incorrect user ID format", err)
			return
		}
	}

	var chirpList []Chirp
	for _, chirp := range chirps {
		if authorID != uuid.Nil && chirp.UserID != authorID {
			continue
		}

		chirpList = append(chirpList, Chirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt.Time,
			UpdatedAt: chirp.UpdatedAt.Time,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		})
	}

	isSorted := req.URL.Query().Get("sort")
	if isSorted == "desc" {
		for i, j := 0, len(chirpList)-1; i < j; {
			chirpList[i], chirpList[j] = chirpList[j], chirpList[i]
			i++
			j--
		}
		respondWithJSON(w, http.StatusOK, chirpList)
		return
	}
	respondWithJSON(w, http.StatusOK, chirpList)
}

func (cfg *apiConfig) getChirpHandler(w http.ResponseWriter, req *http.Request) {
	type response struct {
		Chirp
	}
	chirpIDStr := req.PathValue("id")
	if chirpIDStr == "" {
		respondWithError(w, http.StatusNotFound, "Missing user ID", nil)
		return
	}
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Incorrect user ID format", err)
		return
	}

	chirp, err := cfg.db.GetChirp(req.Context(), chirpID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Not able to get chirps", err)
		return
	}
	respondWithJSON(w, http.StatusOK, response{
		Chirp: Chirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt.Time,
			UpdatedAt: chirp.UpdatedAt.Time,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		},
	})
}

func (cfg *apiConfig) deleteChirpHandler(w http.ResponseWriter, req *http.Request) {
	// Check if th token is correct.
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "No token send", err)
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Error ValidateJWT", err)
		return
	}

	// get chirp
	chirpIDStr := req.PathValue("id")
	if chirpIDStr == "" {
		respondWithError(w, http.StatusNotFound, "Missing user ID", nil)
		return
	}
	chirpID, err := uuid.Parse(chirpIDStr)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Incorrect user ID format", err)
		return
	}

	chirp, err := cfg.db.GetChirp(req.Context(), chirpID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Not able to get chirps", err)
		return
	}

	if chirp.UserID != userID {
		respondWithError(w, http.StatusForbidden, "Not your chirp", err)
		return
	}

	// Delete chirp
	err = cfg.db.DeleteChirp(req.Context(), chirpID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Not able to get chirps", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func healthzHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func cleanResponse(body string) string {
	var cleanBody []string
	listBadWords := []string{"kerfuffle", "sharbert", "fornax"}
	for word := range strings.SplitSeq(body, " ") {
		if slices.Contains(listBadWords, strings.ToLower(word)) {
			cleanBody = append(cleanBody, "****")
		} else {
			cleanBody = append(cleanBody, word)
		}
	}
	return strings.Join(cleanBody, " ")
}
