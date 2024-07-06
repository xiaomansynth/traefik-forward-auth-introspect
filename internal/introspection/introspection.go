package introspection

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/mesosphere/traefik-forward-auth/internal/configuration"
	internallog "github.com/mesosphere/traefik-forward-auth/internal/log"
)

type Introspection struct {
	log logrus.FieldLogger

	config *configuration.Config
	// token and its last validated time
	validatedTokens map[string]time.Time
}

func NewIntrospection(config *configuration.Config) *Introspection {
	return &Introspection{
		log:             internallog.NewDefaultLogger(config.LogLevel, config.LogFormat),
		config:          config,
		validatedTokens: make(map[string]time.Time),
	}
}

func (i *Introspection) Validate(bearerToken string) bool {
	return true
}
