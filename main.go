package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/google/go-github/v57/github"
	"golang.org/x/oauth2"
	githuboauth "golang.org/x/oauth2/github"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// User model
type User struct {
	gorm.Model
	GithubID    int64  `gorm:"uniqueIndex"`
	Username    string `gorm:"unique"`
	AccessToken string
}

var (
	oauthConf        *oauth2.Config
	db               *gorm.DB
)

func generateState() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatalf("Failed to generate secure state: %v", err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Failed to load env file: %v", err)
	}

	clientID := os.Getenv("GITHUB_CLIENT_ID")
	clientSecret := os.Getenv("GITHUB_CLIENT_SECRET")
	redirectURL := os.Getenv("GITHUB_REDIRECT_URL")
	postgresDSN := os.Getenv("POSTGRES_DSN")

	log.Println("PostgreSQL DSN: ", postgresDSN)

	oauthConf = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"user:email"},
		Endpoint:     githuboauth.Endpoint,
	}

	dbConn, err := sql.Open("postgres", postgresDSN)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	db, err = gorm.Open(postgres.New(postgres.Config{Conn: dbConn}), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	db.AutoMigrate(&User{})
}

func main() {
	r := gin.Default()
	store := cookie.NewStore([]byte("super-secret-key"))
	r.Use(sessions.Sessions("mysession", store))

	r.GET("/", func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get("userID")
		if userID != nil {
			user := &User{}
			db.First(user, userID)
			c.JSON(http.StatusOK, gin.H{"message": "Logged in", "user": user})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Not logged in"})
	})

	r.GET("/auth/github/", func(c *gin.Context) {
		state := generateState()
		session := sessions.Default(c)
		session.Set("oauthState", state)
		session.Save()

		url := oauthConf.AuthCodeURL(state, oauth2.AccessTypeOnline)
		c.Redirect(http.StatusTemporaryRedirect, url)
	})

	r.GET("/auth/github/callback", func(c *gin.Context) {
		session := sessions.Default(c)
		storedState := session.Get("oauthState")
		if storedState == nil || storedState.(string) != c.Query("state") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid OAuth state"})
			return
		}

		code := c.Query("code")
		token, err := oauthConf.Exchange(context.Background(), code)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange token"})
			return
		}

		oauthClient := oauthConf.Client(context.Background(), token)
		client := github.NewClient(oauthClient)

		githubUser, _, err := client.Users.Get(context.Background(), "")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get GitHub user info"})
			return
		}

		user := &User{
			GithubID:    githubUser.GetID(),
			Username:    githubUser.GetLogin(),
			AccessToken: token.AccessToken,
		}

		err = db.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "github_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"access_token"}),
		}).Create(user).Error

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store user", "message": err.Error()})
			return
		}

		session.Set("userID", user.ID)
		session.Save()

		c.Redirect(http.StatusTemporaryRedirect, "/")
	})

	r.GET("/logout", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Clear()
		session.Save()
		c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
	})

	r.Run(":8080")
}
