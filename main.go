package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	echomw "github.com/labstack/echo-jwt/v4"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	db        *sql.DB
	jwtSecret []byte
	upgrader  = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	clients = make(map[*websocket.Conn]bool)
	mu      sync.Mutex
)

type Template struct {
	tmpl *template.Template
}

type User struct {
	Username string
	Pass     string
}

type Res struct {
	Errors []string
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.tmpl.ExecuteTemplate(w, name, data)
}

func initDB() error {
	var err error
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return fmt.Errorf("DATABASE_URL not set")
	}
	db, err = sql.Open("postgres", dbURL)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(10)
	db.SetConnMaxLifetime(time.Minute * 5)
	return db.Ping()
}

func createTable() error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		name TEXT,
		email TEXT UNIQUE,
		password TEXT
	)`)
	return err
}

func showLogin(c echo.Context) error {
	return c.Render(http.StatusOK, "login.html", nil)
}

func showSignup(c echo.Context) error {
	return c.Render(http.StatusOK, "signup.html", nil)
}

func signup(c echo.Context) error {
	name := c.FormValue("signup-name")
	email := c.FormValue("signup-email")
	password := c.FormValue("signup-password")
	confirm := c.FormValue("signup-confirm")

	if password != confirm {
		return c.Render(http.StatusBadRequest, "errors", Res{Errors: []string{"Passwords do not match"}})
	}

	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	_, err := db.Exec(`INSERT INTO users (name, email, password) VALUES ($1, $2, $3)`, name, email, string(hashed))
	if err != nil {
		return c.Render(http.StatusBadRequest, "errors", Res{Errors: []string{"User already exists or invalid"}})
	}

	c.Response().Header().Set("HX-Redirect", "/login")
	return c.NoContent(http.StatusOK)
}

func login(c echo.Context) error {
	email := c.FormValue("email")
	pass := c.FormValue("password")

	var u User
	err := db.QueryRow(`SELECT name, password FROM users WHERE email = $1`, email).Scan(&u.Username, &u.Pass)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(u.Pass), []byte(pass)) != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": u.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})
	t, _ := token.SignedString(jwtSecret)

	c.SetCookie(&http.Cookie{
		Name:     "auth_token",
		Value:    t,
		Path:     "/",
		HttpOnly: true,
	})

	c.Response().Header().Set("HX-Redirect", "/dashboard")
	return c.NoContent(http.StatusOK)
}

func showDashboard(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	username := claims["username"].(string)
	return c.Render(http.StatusOK, "dashboard.html", map[string]string{
		"Username": username,
	})
}

func sendJSON(kind string, data interface{}) {
	payload := map[string]interface{}{
		"type": kind,
		"data": data,
	}
	msg, _ := json.Marshal(payload)

	mu.Lock()
	defer mu.Unlock()
	for conn := range clients {
		err := conn.WriteMessage(websocket.TextMessage, msg)
		if err != nil {
			conn.Close()
			delete(clients, conn)
		}
	}
}

func handleWS(c echo.Context) error {
	conn, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		return err
	}

	mu.Lock()
	clients[conn] = true
	mu.Unlock()

	go func() {
		defer func() {
			mu.Lock()
			delete(clients, conn)
			mu.Unlock()
			conn.Close()
		}()

		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	}()

	go func() {
		for {
			time.Sleep(1 * time.Second)
			sendJSON("timer", time.Now().Format("15:04:05"))
		}
	}()

	return nil
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) == 0 {
		log.Fatal("JWT_SECRET is not set")
	}
	if err := initDB(); err != nil {
		log.Fatal(err)
	}
	if err := createTable(); err != nil {
		log.Fatal(err)
	}

	e := echo.New()
	e.Use(middleware.Logger(), middleware.Recover())
	e.Static("/static", "static")
	e.Renderer = &Template{
		tmpl: template.Must(template.ParseGlob("templates/*.html")),
	}

	e.GET("/", showLogin)
	e.GET("/signup", showSignup)
	e.POST("/signup", signup)
	e.POST("/login", login)
	e.GET("/ws", handleWS)
	e.GET("/favicon.ico", func(c echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})

	d := e.Group("/dashboard")
	d.Use(echomw.WithConfig(echomw.Config{
		SigningKey:  jwtSecret,
		TokenLookup: "cookie:auth_token",
	}))
	d.GET("", showDashboard)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	e.Logger.Fatal(e.Start(":" + port))
}
