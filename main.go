package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/google/go-github/v75/github"
	"golang.org/x/crypto/ssh"
)

//go:embed index.html
var index string

const DEFAULT_HOST_PORT string = ":8080"
const DEFAULT_CERT_DURATION_HOURS uint64 = 24 * 17

type AppConfig struct {
	HostPort          string
	GithubToken       string
	GithubOrg         string
	GithubTeam        string
	CertDurationHours uint64
	PrivateKey        string
	PublicKey         string
}

func NewAppConfigFromFile(filename string) (*AppConfig, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("faild to read file: %w", err)
	}
	config := &AppConfig{
		HostPort:          DEFAULT_HOST_PORT,
		CertDurationHours: DEFAULT_CERT_DURATION_HOURS,
	}
	_, err = toml.Decode(string(b), config)
	if err != nil {
		return nil, fmt.Errorf("faild to parse config: %w", err)
	}
	return config, nil
}

type App struct {
	config *AppConfig
	mux    *http.ServeMux

	ghClient *github.Client
	signer   ssh.Signer
	public   ssh.PublicKey

	cacheMu sync.Mutex
	// map user:keys
	cache map[string][]ssh.PublicKey
}

func NewApp(config AppConfig) (*App, error) {
	app := &App{
		config: &config,
		mux:    http.NewServeMux(),
	}

	var err error

	app.signer, err = ssh.ParsePrivateKey([]byte(config.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse PRIVATE_KEY: %w", err)
	}
	app.public, _, _, _, err = ssh.ParseAuthorizedKey([]byte(config.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse PUBLIC_KEY: %w", err)
	}
	app.ghClient = github.NewClient(nil).WithAuthToken(config.GithubToken)

	app.mux.HandleFunc("GET /", app.index)
	app.mux.HandleFunc("GET /api/v1/pub", app.pub)
	app.mux.HandleFunc("GET /api/v1/{user}/allowed", app.allowed)
	app.mux.HandleFunc("GET /api/v1/{user}/keys", app.keys)
	app.mux.HandleFunc("GET /api/v1/{user}/keys/{id}", app.keys)
	app.mux.HandleFunc("GET /api/v1/{user}/certs", app.certs)
	app.mux.HandleFunc("GET /api/v1/{user}/certs/{id}", app.certs)

	app.mux.HandleFunc("GET /api/v1/debug/cache", app.cacheHandler)

	return app, nil
}

func (a *App) index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(index))
}

func (a *App) pub(w http.ResponseWriter, r *http.Request) {
	w.Write(ssh.MarshalAuthorizedKey(a.public))
}

func (a *App) allowed(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()

	_, ok := a.cache[user]
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
	}
}

func (a *App) keys(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	ctx := context.WithValue(r.Context(), "user", user)

	var id int = -1
	idRaw := r.PathValue("id")
	if idRaw != "" {
		i, err := strconv.ParseInt(idRaw, 10, 32)
		if err != nil {
			slog.ErrorContext(ctx, "failed to parse id", "err", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		id = int(i)
	}

	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()

	keys, ok := a.cache[user]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	for idx, key := range keys {
		if id != -1 && idx != id {
			continue
		}
		w.Write(ssh.MarshalAuthorizedKey(key))
	}

}

func (a *App) certs(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	ctx := context.WithValue(r.Context(), "user", user)

	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()

	keys, ok := a.cache[user]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var id int = -1
	idRaw := r.PathValue("id")
	if idRaw != "" {
		i, err := strconv.ParseInt(idRaw, 10, 32)
		if err != nil {
			slog.ErrorContext(ctx, "failed to parse id", "err", err.Error())
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		id = int(i)
	}

	for idx, key := range keys {
		if id != -1 && idx != id {
			continue
		}

		cert, err := a.sign(key)
		if err != nil {
			slog.ErrorContext(ctx, "failed to sign key", "err", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(ssh.MarshalAuthorizedKey(cert))
	}

}

func (a *App) cacheHandler(w http.ResponseWriter, r *http.Request) {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()

	b, _ := json.Marshal(a.cache)
	w.Write(b)
}

func (a *App) refreshCache() {
	slog.Info("starting cache refresh")
	start := time.Now()
	defer func() {
		slog.Info("finished cache refresh", "duration", time.Since(start))
	}()

	ctx := context.Background()
	newCache := make(map[string][]ssh.PublicKey)
	members, _, err := a.ghClient.Teams.ListTeamMembersBySlug(
		ctx,
		a.config.GithubOrg,
		a.config.GithubTeam,
		nil,
	)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get team", "err", err)
	}
	for _, member := range members {
		login := member.GetLogin()
		ctx = context.WithValue(ctx, "user", login)
		keys, _, err := a.ghClient.Users.ListKeys(ctx, login, nil)
		if err != nil {
			slog.ErrorContext(ctx, "failed to get keys", "err", err)
		}
		for _, key := range keys {
			sshKey, _, _, _, err := ssh.ParseAuthorizedKey(
				[]byte(key.GetKey()))
			if err != nil {
				slog.ErrorContext(ctx, "failed to parse key",
					"key", key.GetKey(),
					"err", err,
				)
				continue
			}
			newCache[login] = append(newCache[login], sshKey)
		}
	}

	a.cacheMu.Lock()
	a.cache = newCache
	a.cacheMu.Unlock()
}

func (a *App) sign(key ssh.PublicKey) (*ssh.Certificate, error) {
	duration := time.Hour * time.Duration(a.config.CertDurationHours)
	certificate := ssh.Certificate{
		Key:         key,
		CertType:    ssh.UserCert,
		ValidBefore: uint64(time.Now().Add(duration).Unix()),
	}
	if err := certificate.SignCert(rand.Reader, a.signer); err != nil {
		return nil, fmt.Errorf("failed to sign cert: %w", err)
	}
	return &certificate, nil
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	slog.Info("request", "method", r.Method, "url", r.URL)
	a.mux.ServeHTTP(w, r)
}

func main() {
	if len(os.Args) < 2 {
		slog.Error("No config file provided")
		return
	}
	configFile := os.Args[1]
	config, err := NewAppConfigFromFile(configFile)
	app, err := NewApp(*config)
	if err != nil {
		slog.Error("failed to start", "err", err)
		return
	}

	app.refreshCache()

	go func() {
		for {
			app.refreshCache()
			time.Sleep(time.Minute)
		}
	}()

	slog.Info("Listening", "hostPort", app.config.HostPort)
	err = http.ListenAndServe(config.HostPort, app)
	slog.Error("exited server", "err", err)
}
