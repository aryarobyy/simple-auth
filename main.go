package main

import (
	"auth/main/app"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("ENV LOAD ERROR:", err)
	}

	db := app.InitDb()
	print(db)
	app := app.New()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := app.Start(ctx); err != nil {
		fmt.Errorf("failed to start app: ", err)
	}
}
