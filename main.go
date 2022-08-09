package main

import (
	"database/sql"
	"fmt"
	"log"
	"io/ioutil"
	"time"
	"encoding/json"
	"gopkg.in/yaml.v2"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

type Config struct{
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Host string `yaml:"host"`
	Port string `yaml:"port"`
}



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
	Severity 				string `json:"severity"`
	Cvss_score    			float32 `json:"cvss_score"`
	Cvss_status        		string `json:"cvss_status"`
	Cve_url 				string `json:"cve_url"`
	Vulnerabilities_status 	string `json:"vulnerabilities_status"`
	Vulnerabilities_url 	string `json:"vulnerabilities_url"`
	Platform 				string `json:"platform"`
	Release_image_name 		string `json:"release_image_name"`
	Package_name 			string `json:"package_name"`
	Package_version 		string `json:"package_version"`
	Package_release 		string `json:"package_release"`
	Comment 				string `json:"comment"`
	Solution 				string `json:"solution"`
	Date 					string `json:"date"`
	Commentator 			string `json:"commentator"`
}


var db *sql.DB
var err error

func main() {
	yamlFile, err := ioutil.ReadFile("./config/config.yml")
	if err != nil {
		fmt.Println(err.Error())
	}
	var config Config
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		fmt.Println(err.Error())
	}

	db, err = sql.Open("mysql", config.Username+":"+config.Password+"@tcp("+config.Host+":"+config.Port+")/espp?parseTime=true")

	if err != nil {
		panic(err.Error())
	}

	defer db.Close()

	fmt.Println("Successfully connected to MySQL database")

	app:=fiber.New()
	app.Use(cors.New())
	app.Get("/get", getCve)
	app.Get("/get/a/:package", getAPackage)
	app.Get("/get/e/:fkpackage", getEPackage)
	app.Put("/update/:package", updateCve)
	log.Fatal(app.Listen(":"+"7000"))
	
}


func getCve(c *fiber.Ctx) error{
	rows, err := db.Query("SELECT * FROM CVE")

	if err != nil {
		panic(err.Error())
	}

	defer rows.Close()
	var cves []CVE

	for rows.Next() {
		var cve CVE

		err := rows.Scan(&cve.Package, &cve.Cve_name, &cve.Severity, &cve.Cvss_score, &cve.Cvss_status, &cve.Cve_url, &cve.Vulnerabilities_status, &cve.Vulnerabilities_url, &cve.Platform, &cve.Release_image_name, &cve.Package_name, &cve.Package_version, &cve.Package_release, &cve.Comment, &cve.Solution, &cve.Date, &cve.Commentator)

		if err != nil {
			panic(err.Error())
		}
		cves = append(cves, cve)
	}
	
	return c.JSON(cves)
}

func updateCve(c *fiber.Ctx) error{
	localtime := time.Now()
	statement, err := db.Prepare("UPDATE CVE SET comment = ?, solution = ?, date = ?, commentator = ? WHERE package = ?")
	params := c.AllParams()
	if err != nil {
		panic(err.Error())
	}
	body := c.Body()
	keyVal := make(map[string]string)
	json.Unmarshal(body, &keyVal)

	newComment := keyVal["comment"]
	newSolution := keyVal["solution"]
	newCommentator := keyVal["commentator"]

	if newComment == "" {
		return c.JSON(fiber.Map{"message": "Comment cannot be blank"})
	}

	if newSolution == "" {
		return c.JSON(fiber.Map{"message": "Solution cannot be blank"})
	}

	if newCommentator == "" {
		return c.JSON(fiber.Map{"message": "Commentator cannot be blank"}) 
	}
	

	_, err = statement.Exec(newComment, newSolution, localtime, newCommentator, params["package"])

	if err != nil {
		panic(err.Error())
	}

	return c.JSON(fiber.Map{"message": "successfully", "content": body})
}

func getAPackage(c *fiber.Ctx) error{
	
	params := c.AllParams()

	rows, err := db.Query("select * from AffectedPackageStatus where package = ?", params["package"])
	if err != nil {
		panic(err.Error())
	}
	defer rows.Close()
	var apss []AffectedPackageStatus

	for rows.Next() {
		var aps AffectedPackageStatus

		err := rows.Scan(&aps.Affected_package_name, &aps.Package, &aps.Package_name, &aps.Product_name, &aps.Fix_status, &aps.Impact, &aps.Cpe)

		if err != nil {
			panic(err.Error())
		}
		apss = append(apss, aps)
	}
	
	return c.JSON(apss)
}

func getEPackage(c *fiber.Ctx) error{
	
	params := c.AllParams()

	rows, err := db.Query("select * from Errata where fkpackage = ?", params["fkpackage"])
	if err != nil {
		panic(err.Error())
	}
	defer rows.Close()
	var erratas []Errata

	for rows.Next() {
		var errata Errata

		err := rows.Scan(&errata.Errata_product_name, &errata.Release_date, &errata.Advisory, &errata.Fkpackage, &errata.Package, &errata.Product_name, &errata.Cpe)

		if err != nil {
			panic(err.Error())
		}

		erratas = append(erratas, errata)

	}
	
	return c.JSON(erratas)
}
