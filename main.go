package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
)

var (
	store = sessions.NewCookieStore([]byte("some-secret-key"))
)

type User struct {
	Email string
}

func init() {
	err := godotenv.Load()

	gothic.Store = store

	if err != nil {
		log.Fatal("error loading .env file")
	}

	goth.UseProviders(
		google.New(
			os.Getenv("GOOGLE_CLIENT_ID"),
			os.Getenv("GOOGLE_CLIENT_SECRET"),
			"http://localhost:3000/auth/google/callback",
		),
	)
}

func main() {
	r := chi.NewRouter()

	// gothic.Store = store

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/", homeHandler)
	r.Get("/login", loginHandler)
	r.Get("/logout", logoutHandler)

	r.Route("/auth", func(r chi.Router) {
		r.Get("/", authHandler)
		r.Get("/{provider}/callback", callbackHandler)
	})

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(requireAuth)
		r.Get("/profile", profileHandler)
	})

	log.Fatal(http.ListenAndServe(":3000", r))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	t, _ := template.ParseFiles("templates/layout.html", "templates/home.html")
	t.Execute(w, nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	t, _ := template.ParseFiles("templates/layout.html", "templates/login.html")
	t.Execute(w, nil)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth-session")

	// Clear session data
	session.Values = make(map[interface{}]interface{})
	session.Options.MaxAge = -1 // Invalidate the session
	session.Save(r, w)

	// Redirect to home page after logout
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	p := chi.URLParam(r, "provider")
	fmt.Println(p)
	gothic.BeginAuthHandler(w, r)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	gothUser, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create user...

	session, _ := store.Get(r, "auth-session")
	session.Values["user_id"] = gothUser.Email
	session.Save(r, w)

	http.Redirect(w, r, "/profile", http.StatusTemporaryRedirect)
}

func requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "auth-session")
		userID, ok := session.Values["user_id"].(string)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}

		user := User{
			Email: userID,
		}

		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(User)
	if !ok {
		http.Error(w, "user not found", http.StatusUnauthorized)
		return
	}

	// Parse the layout and profile templates
	t, _ := template.ParseFiles("templates/layout.html", "templates/profile.html")
	t.Execute(w, user)
}
