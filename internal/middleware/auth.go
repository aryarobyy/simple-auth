package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"auth/internal/helper"
)

func JwtAuth(n http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			helper.RespondError(w, http.StatusUnauthorized, fmt.Errorf("Authorization header is empty"))
			return
		}

		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			helper.RespondError(w, http.StatusUnauthorized, fmt.Errorf("Invalid Authorization header format"))
			return
		}

		tokenString := tokenParts[1]
		claims, err := helper.ValidateAccessToken(tokenString)
		if err != nil {
			helper.RespondError(w, http.StatusUnauthorized, err)
			return
		}

		ctx := context.WithValue(r.Context(), "userId", claims.UserId)
		r = r.WithContext(ctx)
		n.ServeHTTP(w, r)
	})
}
