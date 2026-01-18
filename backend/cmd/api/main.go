package main

import (
	"log"
	"testMM/backend/internal/app"
	"testMM/backend/internal/config"

	"github.com/joho/godotenv"
)

func init() {
	// optional .env loading
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file found")
	}
}

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	application, err := app.Wire(cfg)
	if err != nil {
		log.Fatal(err)
	}

	if err := application.Run(); err != nil {
		log.Fatal(err)
	}
}
