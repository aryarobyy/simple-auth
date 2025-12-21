package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"auth/internal/controller"
	"auth/internal/repository"
	"auth/internal/router"
	"auth/internal/service"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jmoiron/sqlx"
	"github.com/redis/go-redis/v9"
)

type App struct {
	router http.Handler
	db     *sqlx.DB
	rdb    *redis.Client
}

type Controllers struct {
	User *controller.UserController
	Auth *controller.AuthController
}

func New() *App {
	db := InitDb()

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})

	userRepo := repository.NewUserRepo(db)
	authRepo := repository.NewAuthRepo(db)

	userService := service.NewUserService(userRepo)
	authService := service.NewAuthService(authRepo, userRepo, redisClient)

	controllers := &Controllers{
		User: controller.NewUserController(userService),
		Auth: controller.NewAuthController(authService),
	}

	router := initRoutes(controllers)

	return &App{
		router: router,
		db:     db,
		rdb:    redisClient,
	}
}

func initRoutes(ctrl *Controllers) *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Server is running!"))
	})

	r.Route("/user", func(r chi.Router) {
		router.UserRoutes(r, *ctrl.User)
	})
	r.Route("/auth", func(r chi.Router) {
		router.AuthRoutes(r, *ctrl.Auth)
	})

	return r
}

func (a *App) Start(ctx context.Context) error {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:    port,
		Handler: a.router,
	}

	err := a.rdb.Ping(ctx).Err()
	if err != nil {
		return fmt.Errorf("failed to connect to redis: %w", err)
	}

	fmt.Println("Starting server on:", port)

	ch := make(chan error, 1)

	go func() {
		err = server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			ch <- fmt.Errorf("failed to start server: %w", err)
		}
		close(ch)
	}()

	fmt.Println("Server started successfully")

	select {
	case err = <-ch:
		return err
	case <-ctx.Done():
		timeout, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		return server.Shutdown(timeout)
	}
}
