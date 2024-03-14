package auth

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Auth0Config struct {
	Audience string
	Issuer   string
	JWKSURL  string
	Claims   map[string]interface{}
}

type CustomClaims struct {
	Roles []string `json:"http://echo-with-sql.com/roles"`
}

func (c CustomClaims) HasRole(roles []string) bool {
	for _, role := range c.Roles {
		for _, r := range roles {
			if role == r {
				return true
			}
		}
	}
	return false
}

func JwtMiddleware(config Auth0Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {

			// Get Token from Authorization Header
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return echo.NewHTTPError(http.StatusUnauthorized, "Authorization header is required")
			}

			tokenString := authHeader[len("Bearer "):]

			// Get JWKS
			keySet, err := fetchJWKS(config.JWKSURL)
			if err != nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "Failed to fetch JWKS")
			}

			// 標準のJWT検証
			token, err := jwt.ParseSigned(tokenString)
			if err != nil {
				fmt.Println(err)
				return echo.NewHTTPError(http.StatusUnauthorized, "Failed to parse JWT")
			}

			claims := jwt.Claims{}
			customClaims := CustomClaims{}
			for _, key := range keySet.Keys {
				if key.Algorithm == "RS256" {
					if err := token.Claims(key.Public(), &claims, &customClaims); err == nil {
						break
					}
				}
			}

			// Verify Audience
			if !claims.Audience.Contains(config.Audience) {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid audience")
			}

			// Verify Issuer
			if claims.Issuer != config.Issuer {
				return echo.NewHTTPError(http.StatusUnauthorized, "Invalid issuer")
			}

			// Verify Custom Claims
			if !customClaims.HasRole(config.Claims["roles"].([]string)) {
				return echo.NewHTTPError(http.StatusForbidden, "Insufficient permissions")
			}

			fmt.Println("JWT Verified!")

			return next(c)
		}
	}
}

func fetchJWKS(jwksURL string) (*jose.JSONWebKeySet, error) {
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "Failed to fetch JWKS")
	}

	var keySet jose.JSONWebKeySet
	err = json.NewDecoder(resp.Body).Decode(&keySet)
	if err != nil {
		return nil, err
	}

	return &keySet, nil
}
