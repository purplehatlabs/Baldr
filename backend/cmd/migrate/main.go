package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/purplehatlabs/Baldr/internal/config"
	"github.com/purplehatlabs/Baldr/internal/db"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "up":
		err = runUp()
	case "down":
		err = runDown()
	case "force":
		err = runForce(os.Args[2:])
	case "create":
		err = runCreate(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  migrate up
  migrate down
  migrate force <version>
  migrate create -ext sql -dir ./internal/db/migrations -seq <name>
`)
}

func runUp() error {
	cfg := config.Load()
	if err := db.RunMigrations(cfg.DatabaseURL, "./internal/db/migrations"); err != nil {
		return err
	}
	fmt.Println("migrations applied")
	return nil
}

func runDown() error {
	cfg := config.Load()
	m, err := migrate.New("file://./internal/db/migrations", cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}
	defer m.Close()

	if err := m.Steps(-1); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("run down: %w", err)
	}
	fmt.Println("rolled back one migration")
	return nil
}

func runForce(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: migrate force <version>")
	}
	version, err := strconv.Atoi(args[0])
	if err != nil || version < 0 {
		return fmt.Errorf("invalid version %q", args[0])
	}

	cfg := config.Load()
	m, err := migrate.New("file://./internal/db/migrations", cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}
	defer m.Close()

	if err := m.Force(version); err != nil {
		return fmt.Errorf("force version: %w", err)
	}
	fmt.Printf("forced schema version to %d (clears dirty flag)\n", version)
	return nil
}

var seqFilePattern = regexp.MustCompile(`^(\d+)_.*\.up\.sql$`)

func runCreate(args []string) error {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	ext := fs.String("ext", "sql", "file extension")
	dir := fs.String("dir", "./internal/db/migrations", "migrations directory")
	useSeq := fs.Bool("seq", false, "use sequential numbering")
	if err := fs.Parse(args); err != nil {
		return err
	}

	name := strings.TrimSpace(strings.Join(fs.Args(), "_"))
	if name == "" {
		return fmt.Errorf("migration name required")
	}
	name = strings.ReplaceAll(name, " ", "_")

	prefix := name
	if *useSeq {
		next, err := nextSequence(*dir)
		if err != nil {
			return err
		}
		prefix = fmt.Sprintf("%06d_%s", next, name)
	}

	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return fmt.Errorf("create migrations dir: %w", err)
	}

	upPath := filepath.Join(*dir, prefix+"."+*ext)
	downPath := filepath.Join(*dir, prefix+".down."+*ext)
	for _, path := range []string{upPath, downPath} {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("file already exists: %s", path)
		}
	}

	if err := os.WriteFile(upPath, []byte("-- write up migration\n"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(downPath, []byte("-- write down migration\n"), 0o644); err != nil {
		return err
	}

	fmt.Printf("Created %s\nCreated %s\n", upPath, downPath)
	return nil
}

func nextSequence(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 1, nil
		}
		return 0, err
	}

	maxSeq := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		matches := seqFilePattern.FindStringSubmatch(entry.Name())
		if len(matches) != 2 {
			continue
		}
		seq, err := strconv.Atoi(matches[1])
		if err != nil {
			continue
		}
		if seq > maxSeq {
			maxSeq = seq
		}
	}
	return maxSeq + 1, nil
}
