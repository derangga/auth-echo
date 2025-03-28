package main

import (
	"auth-echo/app/api/di"
	"auth-echo/server/config"
	"log"
)

func main() {
	config := config.BuildConfig()
	httpServer := di.InitHttpServer(config)
	err := httpServer.ListenAndServe()
	if err != nil {
		log.Fatal("failed to serve http:", err.Error())
	}
}
