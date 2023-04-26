package main

import (
	"database/sql"
	"fmt"
	"log"
	"time"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/lib/pq"
)

var db *sql.DB

func init() { //  Подключение к PostgreSQL базе данных.

	const (
		host     = "localhost"
		port     = 5432
		user     = "postgres"
		password = "93381022"
		dbname   = "go_todo_gin"
	)


	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	var err error
	db, err = sql.Open("postgres", psqlInfo)



	if err != nil {
		log.Fatal(err)
	}
	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}
}



func signUp(c *gin.Context) { // Cоздание нового пользователя
	var user struct {
		Username string `json:"username" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not hash password"})
		return
	}

	_, err = db.Exec("INSERT INTO users (username, email, password) VALUES ($1, $2, $3)", user.Username, user.Email, hashedPassword)
	if err != nil {
	    log.Println(err)
	    c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create user"})
	    return
	}


	c.JSON(http.StatusCreated, gin.H{"message": "user created"})
}


func signIn(c *gin.Context) { // Аутентификацию пользователя
	var user struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	row := db.QueryRow("SELECT id, password FROM users WHERE username = $1", user.Username)
	var id int
	var hashedPassword string
	err := row.Scan(&id, &hashedPassword)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(user.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token, err := createToken(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}



var jwtKey = []byte("secret_key")

type Claims struct {
	ID int `json:"id"`
	jwt.StandardClaims
}

func createToken(id int) (string, error) { // Создает JWT-токен на основе переданного идентификатора пользователя
	claims := &Claims{
		ID: id,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    "your-issuer-name",
			Subject:   "jwt-subject",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}


/*

 Проверяет наличие JWT-токена в заголовке запроса и его корректность.
 Если токен прошел проверку, то идентификатор пользователя извлекается 
 из токена и сохраняется в контексте запроса.

*/

func authMiddleware() gin.HandlerFunc { 
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization header required"})
			return
		}

		tokenString := authHeader[len("Bearer "):]
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtKey, nil
		})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		if claims, ok := token.Claims.(*Claims); ok && token.Valid {
			c.Set("userID", claims.ID)
			c.Next()
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
	}
}


func secretEndpoint(c *gin.Context) { // Доступна только аутентифицированным пользователям
	userID := c.GetInt("userID")
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("You are authenticated as user %d", userID)})
}

func main() { 
	r := gin.Default()


	r.POST("/signup", signUp)
	r.POST("/signin", signIn)

	secret := r.Group("/secret")
	secret.Use(authMiddleware())
	{
		secret.GET("/", secretEndpoint)
	}

	err := r.Run()
	if err != nil {
		panic(err)
	}
}
