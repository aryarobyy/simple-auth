package helper

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

func Pagination(r *http.Request) (int, int, error) {
	limitStr := chi.URLParam(r, "limit")
	limit, limErr := strconv.Atoi(limitStr)
	if limErr != nil {
		return 0, 0, fmt.Errorf("failed getting limit: %w", limErr)
	}
	if limit == 0 {
		limit = 20
	}

	offsetStr := chi.URLParam(r, "offset")
	offset, offsErr := strconv.Atoi(offsetStr)
	if offsErr != nil {
		return 0, 0, fmt.Errorf("failed getting limit: %w", limErr)
	}

	return limit, offset, nil
}
