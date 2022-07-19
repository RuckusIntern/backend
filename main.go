package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/handlers"
)

type User struct {
	ID          int    `json:"id"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

var db *sql.DB
var err error

func main() {
	db, err = sql.Open("mysql", "root:ruckus1234@tcp(172.17.0.2:3306)/espp?parseTime=true")

	if err != nil {
		panic(err.Error())
	}

	defer db.Close()

	fmt.Println("Successfully connected to MySQL database")

	router := mux.NewRouter()

	headers := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	methods := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "DELETE"})
	origins := handlers.AllowedOrigins([]string{"*"})

	// router.HandleFunc("/signup", signUp).Methods("POST")
	// router.HandleFunc("/login", login).Methods("POST")
	// router.HandleFunc("/profiles", getProfiles).Methods("GET", "OPTIONS")
	// router.HandleFunc("/profiles/{id}", getProfile).Methods("GET", "OPTIONS")
	// router.HandleFunc("/profiles/{id}", updateProfile).Methods("PUT")
	// router.HandleFunc("/profiles/{id}", deleteProfile).Methods("DELETE")
	// router.HandleFunc("/posts", getPosts).Methods("GET", "OPTIONS")
	// router.HandleFunc("/posts/{id}", getPost).Methods("GET", "OPTIONS")
	// router.HandleFunc("/posts", createPost).Methods("POST")
	// router.HandleFunc("/posts/{id}", updatePost).Methods("PUT")
	// router.HandleFunc("/posts/{id}", deletePost).Methods("DELETE")
	// router.HandleFunc("/likes", getLikes).Methods("GET")
	// router.HandleFunc("/likes", createLike).Methods("POST")
	// router.HandleFunc("/likes/{id}", getLike).Methods("GET")
	// router.HandleFunc("/likes/{id}", deleteLike).Methods("DELETE")

	fmt.Println("Server started on port 9000")
	log.Fatal(http.ListenAndServe(":9000", handlers.CORS(headers, methods, origins)(router)))
}