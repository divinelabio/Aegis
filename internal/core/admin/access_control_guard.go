package admin

import (
	"net/http"
)

func (s *AdminServer) guardAccessControlSection(next http.Handler) http.Handler {
	return next
}

