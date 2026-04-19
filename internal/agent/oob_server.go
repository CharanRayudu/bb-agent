package agent

import (
	"github.com/bb-agent/mirage/internal/agent/base"
)

// GlobalOOBServer is the package-level singleton in-process OOB HTTP callback server.
// The underlying implementation lives in internal/agent/base so that specialist
// agents (which cannot import this package due to circular deps) can reach it via
// base.GlobalOOBServer.
var GlobalOOBServer = base.GlobalOOBServer
