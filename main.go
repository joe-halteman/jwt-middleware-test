package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"context"
	"errors"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
)

// Cfg configuration structure
type Cfg struct {
	Port int `env:"PORT,default=8001" short:"p" long:"port" description:"HTTP Port"`
	// DbURL                string `env:"DBURL,default=postgres://root@localhost:26257/tnes?sslmode=disable" long:"dbUrl" description:"Database connection URL"`
	JwksCertRenewMinutes int    `env:"JWKS_RENEW_MINUTES,default=60" description:"Number of minutes to wait before renewing JWKS certificates"`
	JWTIssuer            string `env:"JWT_ISSUER" description:"The URL to the JWT issuing server"`
	// AuditTrailURL        string `env:"AUDIT_TRAIL_URL,default=http://localhost:8080" description:"Audit trail app URL"`
	// AuditTrailAPIKey     string `env:"AUDIT_TRAIL_API_KEY" description:"API key will be used to create audit records"`
	// InteliquentBasePath  string `env:"INTELIQUENT_BASE_PATH" default:"https://services.inteliquent.com/Services/1.0.0/" description:"Inteliquent API service endpoint"`
	// InteliquentAPIKey    string `env:"INTELIQUENT_API_KEY" description:"API key for Inteliquent service"`
	// InteliquentSecretKey string `env:"INTELIQUENT_SECRET_KEY" description:"SECRET_KEY for Inteliquent service"`
}

type server struct {
	// db         models.TNOperations
	httpClient *http.Client
	// iqnt       iqnt.API
	config *Cfg
	root   http.Handler
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.root.ServeHTTP(w, r)
}

// var issuer = "https://auth.magna5.cloud/auth/realms/Telecom"

// var authHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 	// issuer := s.config.JWTIssuer

// 	if issuer != "" {
// 		jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
// 			// ErrorHandler: JWTErrorHandler,
// 			// Debug:        true,
// 			ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
// 				// Verify 'iss' claim
// 				checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(issuer, false)
// 				if !checkIss {
// 					return token, errors.New("invalid issuer")
// 				}

// 				publicKey, err := getPemCert(token)
// 				if err != nil {
// 					return nil, err
// 				}

// 				r = setUser(token, r)

// 				r = getRole(token, r)

// 				result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))

// 				return result, nil
// 			},
// 			SigningMethod: jwt.SigningMethodRS256,
// 		})

// 		err := jwtMiddleware.CheckJWT(w, r)

// 		// If there was an error, do not continue.
// 		if err != nil {
// 			return
// 		}
// 	}
// })
var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Entering handler\n")
	user := r.Context().Value("user")
	role := r.Context().Value("role")
	fmt.Fprintf(w, "This is an authenticated request\n")
	fmt.Fprintf(w, "Claim content:\n")
	fmt.Fprintf(w, "User: %#v\n", user)
	fmt.Fprintf(w, "Role: %#v\n", role)
	// for k, v := range user.(*jwt.Token).Claims.(jwt.MapClaims) {
	// 	fmt.Fprintf(w, "%s :\t%#v\n", k, v)
	// }
})

// Jwks struct
type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

// JSONWebKeys struct
type JSONWebKeys struct {
	Kty string   `json:"kty"` // Key Type
	Kid string   `json:"kid"` // Key ID
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"` // x.509 Certificate Chain
}

var jwks = Jwks{}

// RefreshJWTKS refreshes jwt key set from the server
func RefreshJWTKS(cfg *Cfg) {
	refreshInterval := cfg.JwksCertRenewMinutes
	if refreshInterval != 0 {
		duration := time.Duration(refreshInterval) * time.Minute

		shutdown := make(chan os.Signal, 1)
		signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

		go func(d time.Duration) {
			ticker := time.NewTicker(d)
			defer ticker.Stop()
		refreshLoop:
			for {
				select {
				case <-ticker.C:
					FetchJWTKeySet(cfg)
				case <-shutdown:
					break refreshLoop
				}
			}
		}(duration)
	}
}

// FetchJWTKeySet stores keycloak jwt key set
func FetchJWTKeySet(cfg *Cfg) error {
	log.Info().Msg("Updating JWT Key set from the server...")
	resp, err := http.Get(cfg.JWTIssuer + "/protocol/openid-connect/certs")

	if err != nil {
		log.Error().Msg(err.Error())
		// ErrorCounter.Inc()
		return err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		log.Error().Msg(err.Error())
		// ErrorCounter.Inc()
		return err
	}

	log.Info().Msg("JWT Key set loaded successfully.")
	// log.Printf("JWT Keys v: %v\n", jwks.Keys[0])
	// log.Printf("JWT Keys +v: %+v\n", jwks.Keys[0])
	// log.Printf("JWT Keys #v: %#v\n", jwks.Keys[0])
	// jwks.Keys[0].
	return nil
}

// JWTAuthentication middleware
func (s *server) JWTAuthentication(next http.Handler) http.Handler {
	log.Print("Entering JWTAuthentication\n")
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Print("Entering JWTAuthentication Handler\n")
		issuer := s.config.JWTIssuer

		if issuer != "" {
			log.Print("JWTAuthentication Handler Issuer not empty\n")
			jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
				// ErrorHandler: JWTErrorHandler,
				// Debug:        true,
				ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
					log.Print("JWTAuthentication Handler Entering ValidationKeyGetter\n")
					// log.Printf("JWTAuthentication Handler ValidationKeyGetter Token: %+v", token)
					// Verify 'iss' claim
					checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(issuer, false)
					if !checkIss {
						return token, errors.New("invalid issuer")
					}

					publicKey, err := getPemCert(token)
					if err != nil {
						return nil, err
					}

					r = setUser(token, r)

					r = getRole(token, r)

					result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))

					return result, nil
				},
				SigningMethod: jwt.SigningMethodRS256,
			})
			log.Print("JWTAuthentication Handler jwtMiddleware.CheckJWT\n")
			err := jwtMiddleware.CheckJWT(w, r)

			// If there was an error, do not continue.
			if err != nil {

				return
			}
		}

		next.ServeHTTP(w, r)
	})

	return fn
}

func getPemCert(token *jwt.Token) (string, error) {
	cert := ""
	for k := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("unable to find appropriate key")
		return cert, err
	}

	return cert, nil
}

func setUser(token *jwt.Token, r *http.Request) *http.Request {
	claims := token.Claims.(jwt.MapClaims)
	// log.Printf("setUser claims[\"email\"]: %+v", claims["email"])
	log.Printf("setUser Claims: %+v", claims)
	ctx := context.WithValue(r.Context(), "user", claims["email"])
	return r.WithContext(ctx)
}

func getRole(token *jwt.Token, r *http.Request) *http.Request {
	claims := token.Claims.(jwt.MapClaims)
	// log.Printf("setUser claims[\"role\"]: %+v", claims["role"])
	log.Printf("getRole Claims: %+v", claims)
	ctx := context.WithValue(r.Context(), "role", claims["role"])
	return r.WithContext(ctx)
}

// NewServer func
func NewServer(ctx context.Context, cfg *Cfg) (*server, error) {
	s := &server{
		config: cfg,
	}

	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	log.Logger = log.Logger.With().Timestamp().Caller().Logger()

	// configure http client for global usage
	s.httpClient = &http.Client{
		Timeout: time.Second * 10,
	}
	// routers, middlewares
	r := chi.NewRouter()

	r.Use(cors.New(cors.Options{
		AllowedOrigins:     []string{"*"},
		AllowedMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:     []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:     []string{"Link"},
		AllowCredentials:   true,
		OptionsPassthrough: false,
		MaxAge:             3599, // Maximum value not ignored by any of major browsers
	}).Handler)

	r.Use(middleware.Recoverer)
	r.Use(hlog.NewHandler(log.Logger))
	r.Use(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Info().
			Str("method", r.Method).
			Str("url", r.URL.String()).
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Msg("")
	}))
	r.Use(hlog.RequestIDHandler("req_id", "Request-Id"))
	r.Use(hlog.RemoteAddrHandler("ip"))
	r.Use(hlog.UserAgentHandler("user_agent"))
	r.Use(hlog.RefererHandler("referer"))
	r.Use(s.JWTAuthentication)
	r.Handle("/", myHandler)

	s.root = r

	return s, nil
}

// func main001() {
// 	// jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
// 	// 	ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
// 	// 		return []byte("My Secret"), nil
// 	// 	},
// 	// 	// When set, the middleware verifies that tokens are signed with the specific signing algorithm
// 	// 	// If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
// 	// 	// Important to avoid security issues described here: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
// 	// 	SigningMethod: jwt.SigningMethodHS256,
// 	// })
// 	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
// 		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
// 			fmt.Printf("Verifying Issuer %s\n", issuer)
// 			// Verify 'iss' claim
// 			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(issuer, false)
// 			if !checkIss {
// 				return token, errors.New("invalid issuer")
// 			}

// 			publicKey, err := getPemCert(token)
// 			if err != nil {
// 				return nil, err
// 			}

// 			// r = setUser(token, r)

// 			// r = getRole(token, r)

// 			result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))

// 			return result, nil
// 		},
// 		SigningMethod: jwt.SigningMethodRS256,
// 	})
// 	app := jwtMiddleware.Handler(myHandler)
// 	fmt.Printf("Server starting\n")
// 	http.ListenAndServe(":8080", app)
// }
func main() {
	cfg := &Cfg{JWTIssuer: "https://auth.magna5.cloud/auth/realms/Telecom", JwksCertRenewMinutes: 5, Port: 8001}
	err := FetchJWTKeySet(cfg)
	if err != nil {
		// log.Fatal("failed to fetch JWT Key Set ", err)
		log.Fatal().Err(err).Msg("failed to fetch JWT Key Set ")
	}
	RefreshJWTKS(cfg)

	// create server instance
	s, err := NewServer(context.Background(), cfg)

	if err != nil {
		log.Fatal().Err(err)
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: s,
	}

	log.Printf("starting %s", server.Addr)
	log.Print(server.ListenAndServe())
}
