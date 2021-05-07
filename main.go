package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var (
	router    *mux.Router
	secretkey string = "secretkeyJWT"
)

type Authentication struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Token struct {
	Role        string `json:"role"`
	Email       string `json:"email"`
	TokenString string `json:"tokenString"`
}

func GenerateJWT(email, role string) (string, error) {
	var mySigningKey = []byte(secretkey)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["email"] = email
	claims["role"] = role
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		log.Fatalf("Something when wrong: %s", err.Error())
		return "", err
	}

	return tokenString, nil
}

func CreateRouter() {
	router = mux.NewRouter()
}

func InitializeRoute() {
	router.HandleFunc("/signup", SignUp).Methods("POST")
	router.HandleFunc("/sigin", SignIn).Methods("POST")
	router.HandleFunc("/admin", IsAuthorized(AdminIndex)).Methods("GET")
	router.HandleFunc("/user", IsAuthorized(UserIndex)).Methods("GET")
}

func AdminIndex(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Role") != "admin" {
		w.Write([]byte("Not Authorized"))
		return
	}
	w.Write([]byte("Welcome, Admin."))
}

func UserIndex(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Role") != "user" {
		w.Write([]byte("Not Authorized"))
		return
	}
	w.Write([]byte("Welcome, User."))
}

func SignUp(w http.ResponseWriter, r *http.Request) {
	db := GetDatabase()
	defer db.Close()

	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(err)
		return
	}

	user.Password, err = GenerateHashPassword(user.Password)
	if err != nil {
		log.Fatalln("error in password hash")
	}

	// TODO save new user
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)

}

func GetDatabase() *sql.DB {
	db, err := sql.Open("sqlite3", "data/jwt.db")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Conected to Database")

	return db
}

func GenerateHashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	db := GetDatabase()
	defer db.Close()

	var authDetail Authentication
	err := json.NewDecoder(r.Body).Decode(&authDetail)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(err)
		return
	}

	var authUser User
	// TODO: select user
	if strings.TrimSpace(authUser.Email) == "" {
		w.Header().Set("Content-Type", "application/json")
		err := errors.New("Username or Password is incorrect")
		json.NewEncoder(w).Encode(err)
		return
	}

	check := CheckPasswordHash(authDetail.Password, authUser.Password)
	if !check {
		err := errors.New("Username or Password is incorrect")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(err)
		return
	}

	validToken, err := GenerateJWT(authUser.Email, authUser.Role)
	if err != nil {
		err := errors.New("Failed to generate token")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(err)
		return
	}

	token := Token{
		Email:       authUser.Email,
		Role:        authUser.Role,
		TokenString: validToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(token)
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err != nil
}

func IsAuthorized(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header["Token"] == nil {
			err := errors.New("Token not found")
			json.NewEncoder(w).Encode(err)
			return
		}

		var mySigningKey = []byte(secretkey)
		token, err := jwt.Parse(r.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("There was an error in parssing")
			}
			return mySigningKey, nil
		})
		if err != nil {
			err = errors.New("Your Token has been expired")
			json.NewEncoder(w).Encode(err)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			switch claims["role"] {
			case "admin":
				r.Header.Set("Role", "admin")
			case "user":
				r.Header.Set("Role", "user")
			}
			handler.ServeHTTP(w, r)
			return
		}

		reserr := errors.New("Not Authorized")
		json.NewEncoder(w).Encode(reserr)

	}
}

func main() {
	CreateRouter()
	InitializeRoute()

	http.Handle("/", router)
	svr := &http.Server{
		Addr:    ":8080",
		Handler: http.DefaultServeMux,
	}
	err := svr.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
