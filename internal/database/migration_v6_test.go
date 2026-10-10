package database

import "testing"

func TestAuthorizationMigrationPresent(t *testing.T) {
	for _, migration := range VersionedMigrations() {
		if migration.Version == 6 && migration.SQL != "" {
			return
		}
	}
	t.Fatal("version 6 authorization migration is missing")
}
