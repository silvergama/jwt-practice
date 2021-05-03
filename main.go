package main

type User struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type Authentication struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Token struct {
	Role        string `json:"role"`
	Email       string `json:"email"`
	TokenString string `json:"tokenString"`
}

func GetDatabase() *sql.DB {

	db, err := sql.Open("sqlite3", "data/jwt.db")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Conected to Database")

	return db
}
