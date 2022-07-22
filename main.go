package main

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"

)

type AffectedPackageStatus struct {
	Affected_package_name   string `json:"affected_package_name"`
	Package       			string `json:"package"`
	Package_name    		string `json:"package_name"`
	Product_name        	string `json:"product_name"`
	Fix_status 				string `json:"fix_status"`
	Impact 					string `json:"impact"`
	Cpe 					string `json:"cpe"`
}

type Errata struct {
	Errata_product_name     string `json:"errata_product_name"`
	Release_date       		string `json:"release_date"`
	Advisory    			string `json:"advisory"`
	Fkpackage        		string `json:"fkpackage"`
	Package 				string `json:"package"`
	Product_name 			string `json:"product_name"`
	Cpe 					string `json:"cpe"`
}

type CVE struct {
	Package          		string `json:"package"`
	Cve_name       			string `json:"cve_name"`
	Cvss_score    			sql.NullString `json:"cvss_score"`
	Cvss_status        		string `json:"cvss_status"`
	Cve_url 				string `json:"cve_url"`
	Severity 				string `json:"severity"`
	Vulnerabilities_status 	string `json:"vulnerabilities_status"`
	Vulnerabilities_url 	string `json:"vulnerabilities_url"`
	Platform 				string `json:"platform"`
	Release_image_name 		string `json:"release_image_name"`
	Package_name 			string `json:"package_name"`
	Package_version 		string `json:"package_version"`
	Package_release 		string `json:"package_release"`
	Comment 				sql.NullString `json:"comment"`
	Solution 				sql.NullString `json:"solution"`
	Date 					sql.NullString `json:"date"`
	Commentator 			sql.NullString `json:"commentator"`
}


var db *sql.DB
var err error

func main() {
	db, err = sql.Open("mysql", "test:1@tcp(172.17.0.2:3306)/espp?parseTime=true")

	if err != nil {
		panic(err.Error())
	}

	defer db.Close()

	fmt.Println("Successfully connected to MySQL database")

	app:=fiber.New()
	app.Use(cors.New())
	app.Get("/get", getCve)
	app.Get("/update", updateCve)
	log.Fatal(app.Listen(":"+"7000"))
	
}


func getCve(c *fiber.Ctx) error{
	var cves []CVE

	result, err := db.Query("SELECT * FROM CVE")

	if err != nil {
		panic(err.Error())
	}

	defer result.Close()

	for result.Next() {
		var cve CVE

		err := result.Scan(&cve.Package, &cve.Cve_name, &cve.Cvss_score, &cve.Cvss_status, &cve.Cve_url, &cve.Severity, &cve.Vulnerabilities_status, &cve.Vulnerabilities_url, &cve.Platform, &cve.Release_image_name, &cve.Package_name, &cve.Package_version, &cve.Package_release, &cve.Comment, &cve.Solution, &cve.Date, &cve.Commentator)

		if err != nil {
			panic(err.Error())
		}

		cves = append(cves, cve)
	}

	return c.JSON(cves)
}

func updateCve(c *fiber.Ctx) error{
	localtime := time.Now()
	result, err := db.Query("UPDATE CVE SET comment = ?, solution = 'werew', commentator = 'intern' WHERE package = 'acl-2.2.51-14.el7'",localtime)

	if err != nil {
		panic(err.Error())
	}

	defer result.Close()

	return c.JSON(fiber.Map{
		"message" : "success",
	})
}

// func updateComment(w http.ResponseWriter, r *http.Request) {
// 	params := mux.Vars(r)

// 	statement, err := db.Prepare("UPDATE CVE SET comment = ?, solution = ?, commentator = ? WHERE package = ?")

// 	if err != nil {
// 		panic(err.Error())
// 	}

// 	body, err := ioutil.ReadAll(r.Body)

// 	if err != nil {
// 		panic(err.Error())
// 	}

// 	keyVal := make(map[string]string)
// 	json.Unmarshal(body, &keyVal)

// 	newComment := keyVal["comment"]
// 	newSolution := keyVal["solution"]
// 	newCommentator := keyVal["commentator"]

// 	if newComment == "" {
// 		w.WriteHeader(http.StatusBadRequest)
// 		json.NewEncoder(w).Encode("Comment cannot be blank")
// 		return
// 	}

// 	if newSolution == "" {
// 		w.WriteHeader(http.StatusBadRequest)
// 		json.NewEncoder(w).Encode("Solution cannot be blank")
// 		return
// 	}

// 	if newCommentator == "" {
// 		w.WriteHeader(http.StatusBadRequest)
// 		json.NewEncoder(w).Encode("Commentator cannot be blank")
// 		return
// 	}

// 	_, err = statement.Exec(newComment, newSolution, newCommentator, params["package"])

// 	if err != nil {
// 		panic(err.Error())
// 	}

// 	fmt.Fprintf(w, "Package = %s was updated", params["package"])
// }
