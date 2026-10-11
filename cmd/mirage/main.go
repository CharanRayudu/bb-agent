package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/bb-agent/mirage/internal/config"
	"github.com/bb-agent/mirage/internal/database"
	"github.com/bb-agent/mirage/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	if err := cfg.ValidateProduction(); err != nil {
		log.Fatalf("Refusing to start: %v", err)
	}

	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := database.RunMigrations(db); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}
	if n, err := database.NewQueries(db).FailInterruptedFlows(); err != nil {
		log.Printf("[startup] could not reconcile interrupted flows: %v", err)
	} else if n > 0 {
		log.Printf("[startup] marked %d interrupted flow(s) failed after restart", n)
	}

	srv := server.New(cfg, db)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
	}()

	log.Printf("[startup] %s", cfg.ExecutionModeStatus())
	log.Printf("[startup] %s", cfg.DecisionRoutingStatus())
	if _, err := os.Stat("frontend/dist/index.html"); err != nil {
		log.Printf("[startup] frontend/dist is not in this process; the UI is served by the frontend container or npm run dev")
	}
	addr := fmt.Sprintf("%s:%d", cfg.ServerHost, cfg.ServerPort)
	log.Printf("[startup] mirage server starting on %s", addr)

	if err := srv.Start(ctx, addr); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
