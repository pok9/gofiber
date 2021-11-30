package main

import (
	"fmt"
	"strconv"
	"time"

	// "github.com/dgrijalva/jwt-go/v4"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/go-sql-driver/mysql"
	jwtware "github.com/gofiber/jwt/v3"
)

var db *sqlx.DB

const jwtSecret = "infinitas"

func main() {

	var err error
	//go get github.com/go-sql-driver/mysql
	db, err = sqlx.Open("mysql", "root:P@ssw0rd@tcp(13.76.163.73:3306)/techcoach")
	if err != nil {
		panic(err)
	}

	fmt.Println("5555")
	fmt.Println(db)

	app := fiber.New()

	app.Use("/hello",jwtware.New(jwtware.Config{
		SigningMethod: "HS256",
		SigningKey: []byte(jwtSecret),
		SuccessHandler: func(c *fiber.Ctx) error {
			return c.Next()
		},
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			return fiber.ErrUnauthorized
		},
	}))

	//curl localhost:8000/signup -H content-type:application/json -d '{"username":"pok","password":"pok"}' -i
	app.Post("/signup", Signup)
	//curl localhost:8000/login -H content-type:application/json -d '{"username":"pok","password":"pok"}' -i
	app.Post("/login", Login)
	//curl localhost:8000/hello -H "Authorization:Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoxLCJpYXQiOjE2MTYzMjkxODR9.wfBG1gZP8aQqkAuIImz3NXIWpsNfGZRSWaSdR4nu7sU" 
	app.Get("/hello", Hello)

	app.Listen(":8000")
}

func Signup(c *fiber.Ctx) error {
	request := SignupRequest{}
	err := c.BodyParser(&request)
	if err != nil {
		return err
	}

	if request.Username == "" || request.Password == "" {
		return fiber.ErrUnprocessableEntity
	}

	//go get golang.org/x/crypto/bcrypt
	password, err := bcrypt.GenerateFromPassword([]byte(request.Password), 10)
	if err != nil {
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}

	//go get github.com/jmoiron/sqlx
	query := "insert user (username,password) values (?,?)"
	result, err := db.Exec(query, request.Username, string(password))
	if err != nil {
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}

	user := User{
		Id:       int(id),
		Username: request.Username,
		Password: string(password),
	}

	return c.Status(fiber.StatusCreated).JSON(user)
}
func Login(c *fiber.Ctx) error {

	request := LoginRequest{}
	err := c.BodyParser(&request)
	if err != nil {
		return err
	}

	user := User{}
	query := "select id,username,password from user where username=?"
	err = db.Get(&user, query, query)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Incorrect username or password")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password))
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Incorrect username or password")
	}

	cliams := jwt.StandardClaims{
		Issuer:    strconv.Itoa(user.Id),
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	}

	jwtToKen := jwt.NewWithClaims(jwt.SigningMethodHS256, cliams)
	token, err := jwtToKen.SignedString([]byte(jwtSecret))
	if err != nil {
		return fiber.ErrInternalServerError
	}

	//go get -u github.com/gofiber/jwt/v3
	return c.JSON(fiber.Map{
		"jwtToken": token,
	})
}

//import jwt
//go get github.com/dgrijalva/jwt-go/v4
func Hello(c *fiber.Ctx) error {
	return nil
}

type User struct {
	Id       int    `db:"id" json:"id"`
	Username string `db:"username" json:"username"`
	Password string `db:"password" json:"password"`
}

type SignupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func Fiber() {
	app := fiber.New(fiber.Config{
		Prefork: true,
	})

	//Middleware
	app.Use("/hello", func(c *fiber.Ctx) error {
		c.Locals("name", "pok")
		fmt.Println("before")
		// err := c.Next()
		c.Next()
		fmt.Println("after")
		// return err
		return nil
	})

	app.Use(requestid.New())
	//Default Config
	// var ConfigDefault = Config{
	// 	Next:       nil,
	// 	Header:     fiber.HeaderXRequestID,
	// 	Generator:  func() string {
	// 		return utils.UUID()
	// 	},
	// 	ContextKey: "requestid"
	// }
	//ถ้าจะ config ใหม่
	// app.Use(requestid.New(requestid.Config{
	// 	Header: ,
	// }))

	app.Use(cors.New())
	//Default Config
	// var ConfigDefault = Config{
	// 	Next:             nil,
	// 	AllowOrigins:     "*",
	// 	AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH",
	// 	AllowHeaders:     "",
	// 	AllowCredentials: false,
	// 	ExposeHeaders:    "",
	// 	MaxAge:           0,
	// }
	//ถ้าจะ config ใหม่
	// app.Use(cors.New(cors.Config{
	// 	AllowOrigins:     "*",
	// 	AllowMethods:     "*",
	// 	AllowHeaders:     "*",
	// }))

	app.Use(logger.New(logger.Config{
		TimeZone: "Asia/Bangkok",
	}))

	//GET
	//curl localhost:8000/hello
	app.Get("/hello", func(c *fiber.Ctx) error {
		name := c.Locals("name") //รับข้อมูลมาจาก middleware
		fmt.Println("hello")
		return c.SendString(fmt.Sprintf("GET: Hello %v", name))
	})

	//POST
	//curl localhost:8000/hello -X POST
	app.Post("/hello", func(c *fiber.Ctx) error {
		return c.SendString("POST: Hello World")
	})

	//Parameters
	//curl localhost:8000/hello/pok
	app.Get("/hello/:name", func(c *fiber.Ctx) error {
		name := c.Params("name") //ดีง parameters -name-
		return c.SendString("name: " + name)
	})

	//Parameters Optional 	*:surname? จะใส่ surname หรือไม่ก็ได้
	//curl localhost:8000/hello/pok/chanchai -หรือ- curl localhost:8000/hello/pok
	app.Get("/hello/:name/:surname?", func(c *fiber.Ctx) error {
		name := c.Params("name") //ดีง parameters -name-
		surname := c.Params("surname")
		return c.SendString("name: " + name + ", surname: " + surname)
	})

	//ParamsInt curl localhost:8000/checknumber/123
	app.Get("/checknumber/:id", func(c *fiber.Ctx) error {
		id, err := c.ParamsInt("id")
		if err != nil {
			return fiber.ErrBadRequest
		}

		return c.SendString(fmt.Sprintf("ID = %v", id))
	})

	//Query curl "localhost:8000/query1?name=pok&surname=ditthapan"
	app.Get("/query1", func(c *fiber.Ctx) error {
		name := c.Query("name")
		surename := c.Query("surname")
		return c.SendString("name: " + name + " surname: " + surename)
	})

	//Query curl "localhost:8000/query2?id=1&name=pok"
	app.Get("/query2", func(c *fiber.Ctx) error {
		person := Person{}
		c.QueryParser(&person)
		return c.JSON(person)
	})

	//Wildcards curl localhost:8000/wildcards/hello/world
	app.Get("/wildcards/*", func(c *fiber.Ctx) error {
		wildcard := c.Params("*")
		return c.SendString(wildcard)
	})

	//Static file  curl http://localhost:8000/
	app.Static("/", "./wwwroot", fiber.Static{
		Index:         "index.html",
		CacheDuration: time.Second * 10,
	})

	//NewError 	curl http://localhost:8000/error
	app.Get("/error", func(c *fiber.Ctx) error {
		return fiber.NewError(fiber.StatusNotFound, "content not found")
	})

	//Group	curl http://localhost:8000/v1/hello
	v1 := app.Group("/v1", func(c *fiber.Ctx) error {
		c.Set("Version", "v1")
		return c.Next()
	})
	v1.Get("/hello", func(c *fiber.Ctx) error {
		return c.SendString("Hello v1")
	})

	//Group curl http://localhost:8000/v2/hello
	v2 := app.Group("/v2", func(c *fiber.Ctx) error {
		c.Set("Version", "v2")
		return c.Next()
	})
	v2.Get("/hello", func(c *fiber.Ctx) error {
		return c.SendString("Hello v2")
	})

	//*******-Mount-*******
	userApp := fiber.New()
	userApp.Get("/login", func(c *fiber.Ctx) error {
		return c.SendString("Login")
	})
	// curl http://localhost:8000/user/login
	app.Mount("/user", userApp)
	//*******-Mount-*******

	//Server curl http://localhost:8000/server
	app.Server().MaxConnsPerIP = 1
	app.Get("/server", func(c *fiber.Ctx) error {
		time.Sleep(time.Second * 30)
		return c.SendString("Server")
	})

	//Environment curl http://localhost:8000/env | jq  หรือ curl "localhost:8000/env?name=bond" | jq
	app.Get("/env", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"BaseURL":     c.BaseURL(),
			"Hostname":    c.Hostname(),
			"IP":          c.IP(),
			"IPs":         c.IPs(),
			"OriginalURL": c.OriginalURL(),
			"Path":        c.Path(),
			"Protocal":    c.Protocol(),
			"Subdomains":  c.Subdomains(),
		})
	})

	//Body curl localhost:8000/body -d 'hello' หรือ curl localhost:8000/body -d '{"name":"pok"}' หรือ curl localhost:8000/body -d '{"name":"pok"}' -H content-type:application/json
	//curl localhost:8000/body -d '{"id":1,"name":"pok"}' -H content-type:application/json
	app.Post("/body", func(c *fiber.Ctx) error {
		fmt.Printf("IsJson: %v\n", c.Is("json"))
		fmt.Println(string(c.Body()))

		person := Person{}
		err := c.BodyParser(&person)
		if err != nil {
			return err
		}

		fmt.Println(person)
		return nil
	})

	//Body ทำแบบ map *curl localhost:8000/body2 -d 'id=1&name=pok' -H content-type:application/x-www-form-urlencaded
	app.Post("/body2", func(c *fiber.Ctx) error {
		fmt.Printf("IsJson: %v\n", c.Is("json"))
		fmt.Println(string(c.Body()))

		data := map[string]interface{}{}
		err := c.BodyParser(&data)
		if err != nil {
			return err
		}

		fmt.Println(data)
		return nil
	})

	app.Listen(":8000")
}

type Person struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}
