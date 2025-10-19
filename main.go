package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/google/go-github/v75/github"
	"golang.org/x/crypto/ssh"
)

//go:embed index.html
var index string

const DEFAULT_HTTP_ADDR string = ""
const DEFAULT_HTTP_PORT uint16 = 8080
const DEFAULT_CERT_DURATION_HOURS uint64 = 24 * 17

type AppConfig struct {
	GithubToken       string
	GithubOrg         string
	GithubTeam        string
	CertDurationHours uint64
	Addr              string
	Port              uint16

	ghClient  *github.Client
	signer    ssh.Signer
	publicKey ssh.PublicKey
}

func NewAppConfigFromEnv() (*AppConfig, error) {
	ghOrg := os.Getenv("GITHUB_ORG")
	if ghOrg == "" {
		return nil, fmt.Errorf("No GITHUB_ORG provided")
	}

	ghTeam := os.Getenv("GITHUB_TEAM")
	if ghTeam == "" {
		return nil, fmt.Errorf("No GITHUB_TEAM provided")
	}

	privateKeyRaw := os.Getenv("PRIVATE_KEY")
	if privateKeyRaw == "" {
		return nil, fmt.Errorf("No PRIVATE_KEY provided")
	}
	signer, err := ssh.ParsePrivateKey([]byte(privateKeyRaw))
	if err != nil {
		return nil, fmt.Errorf("failed to parse PRIVATE_KEY: %w", err)
	}

	publicKeyRaw := os.Getenv("PUBLIC_KEY")
	if publicKeyRaw == "" {
		return nil, fmt.Errorf("No PUBLIC_KEY provided")
	}
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKeyRaw))
	if err != nil {
		return nil, fmt.Errorf("failed to parse PUBLIC_KEY: %w", err)
	}

	ghToken := os.Getenv("GITHUB_TOKEN")
	if ghToken == "" {
		return nil, fmt.Errorf("No GITHUB_TOKEN provided")
	}
	ghClient := github.NewClient(nil).WithAuthToken(ghToken)

	var certDuration uint64 = DEFAULT_CERT_DURATION_HOURS
	certDurationEnv := os.Getenv("CERT_DURATION_HOURS")
	if certDurationEnv != "" {
		certDuration, err = strconv.ParseUint(certDurationEnv, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("Bad CERT_DURATION_HOURS provided: %w", err)
		}
	} else {
		slog.Info("CERT_DURATION_HOURS not provided using default",
			"default", DEFAULT_CERT_DURATION_HOURS)
	}

	var port = DEFAULT_HTTP_PORT
	portRaw := os.Getenv("HTTP_PORT")
	if portRaw != "" {
		p, err := strconv.ParseUint(portRaw, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("failed to parse HTTP_PORT: %w", err)
		}
		port = uint16(p)
	}

	var addr = DEFAULT_HTTP_ADDR
	addrRaw := os.Getenv("HTTP_ADDR")
	if addrRaw != "" {
		addr = addrRaw
	}

	return &AppConfig{
		GithubOrg:         ghOrg,
		GithubTeam:        ghTeam,
		CertDurationHours: certDuration,
		Addr:              addr,
		Port:              port,

		ghClient:  ghClient,
		signer:    signer,
		publicKey: publicKey,
	}, nil
}

type App struct {
	config *AppConfig
	mux    *http.ServeMux
}

func NewApp(config AppConfig) *App {
	app := &App{
		config: &config,
		mux:    http.NewServeMux(),
	}

	app.mux.HandleFunc("GET /", app.index)
	app.mux.HandleFunc("GET /api/v1/{user}/allowed", app.allowed)
	app.mux.HandleFunc("GET /api/v1/{user}/keys", app.keys)
	app.mux.HandleFunc("GET /api/v1/{user}/keys/{id}", app.keys)
	app.mux.HandleFunc("GET /api/v1/{user}/certs", app.certs)
	app.mux.HandleFunc("GET /api/v1/{user}/certs/{id}", app.certs)

	return app
}

func (a *App) index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(index))
}

func (a *App) allowed(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	ctx := context.WithValue(r.Context(), "user", user)

	allowed, err := a.userIsAllowed(ctx, user)
	if err != nil {
		slog.ErrorContext(ctx, "failed to authorize", "err", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	}
	if !allowed {
		w.WriteHeader(http.StatusUnauthorized)
	}
	io.WriteString(w, fmt.Sprint(allowed))
}

func (a *App) keys(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	ctx := context.WithValue(r.Context(), "user", user)

	keys, err := a.getUserPublicKeys(ctx, user)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user keys", "err", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var id int = -1
	idRaw := r.PathValue("id")
	if idRaw != "" {
		id, err = strconv.Atoi(idRaw)
		if err != nil {
			slog.ErrorContext(ctx, "failed to parse id", "err", err)
		}
	}

	for idx, key := range keys {
		if id != -1 && idx != id {
			continue
		}
		_, err := w.Write(ssh.MarshalAuthorizedKey(key))
		if err != nil {
			slog.ErrorContext(ctx, "failed to write reponse", "err", err.Error())
		}
	}

}

func (a *App) certs(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	ctx := context.WithValue(r.Context(), "user", user)

	allowed, err := a.userIsAllowed(ctx, user)
	if err != nil {
		slog.ErrorContext(ctx, "failed to authorize", "err", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !allowed {
		slog.InfoContext(ctx, "not allowed")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	keys, err := a.getUserPublicKeys(ctx, user)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user key", "err", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	}

	var id int = -1
	idRaw := r.PathValue("id")
	if idRaw != "" {
		i, err := strconv.ParseInt(idRaw, 10, 32)
		if err != nil {
			slog.ErrorContext(ctx, "failed to parse id", "err", err.Error())
			w.WriteHeader(http.StatusBadRequest)
			_, err := io.WriteString(w, "failed to parse id")
			if err != nil {
				slog.ErrorContext(ctx, "failed to write reponse", "err", err.Error())
			}
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
			_, err := io.WriteString(w, "failed to sign key")
			if err != nil {
				slog.ErrorContext(ctx, "failed to write reponse", "err", err.Error())
			}
			return
		}
		_, err = w.Write(ssh.MarshalAuthorizedKey(cert))
		if err != nil {
			slog.ErrorContext(ctx, "failed to write reponse", "err", err.Error())
		}
	}

}

func (a *App) userIsAllowed(ctx context.Context, user string) (bool, error) {
	org := a.config.GithubOrg
	team := a.config.GithubTeam
	membership, res, err := a.config.ghClient.Teams.
		GetTeamMembershipBySlug(ctx, org, team, user)
	if err != nil {
		if res.StatusCode == http.StatusNotFound {
			err = nil
		}
		return false, err
	}
	allowed := membership.State != nil && *membership.State == "active"
	return allowed, nil
}

func (a *App) sign(key ssh.PublicKey) (*ssh.Certificate, error) {
	duration := time.Hour * time.Duration(a.config.CertDurationHours)
	certificate := ssh.Certificate{
		Key:         key,
		CertType:    ssh.UserCert,
		ValidBefore: uint64(time.Now().Add(duration).Unix()),
	}
	if err := certificate.SignCert(rand.Reader, a.config.signer); err != nil {
		return nil, fmt.Errorf("failed to sign cert: %w", err)
	}
	return &certificate, nil
}

func (a *App) getUserPublicKeys(ctx context.Context, githubHandle string) ([]ssh.PublicKey, error) {
	keys, _, err := a.config.ghClient.Users.ListKeys(ctx, githubHandle, nil)
	if err != nil {
		return nil, err
	}

	var sshKeys []ssh.PublicKey
	for _, key := range keys {
		sshKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key.GetKey()))
		if err != nil {
			slog.Error("failed to parse key", "err", err, "key", key)
			continue
		}
		sshKeys = append(sshKeys, sshKey)
	}
	return sshKeys, nil
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	slog.Info("request", "method", r.Method, "url", r.URL)
	a.mux.ServeHTTP(w, r)
}

func main() {
	config, err := NewAppConfigFromEnv()
	if err != nil {
		slog.Error("failed to parse config", "err", err)
		return
	}
	app := NewApp(*config)
	slog.Info("Listening", "port", app.config.Port)
	addr := fmt.Sprintf("%s:%d", config.Addr, config.Port)
	err = http.ListenAndServe(addr, app)
	slog.Error("exited server", "err", err)
}
