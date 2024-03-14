package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	auth "github.com/Watson-Sei/echo-to-auth0/middleware"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func main() {

	// Check Load .env File
	err := godotenv.Load()
	if err != nil {
		panic("Error loading .env file")
	}

	e := echo.New()

	// Recover And Logger Middleware
	e.Use(middleware.Recover())
	e.Use(middleware.Logger())

	// Static Files Stream
	t := &Template{
		templates: template.Must(template.ParseGlob("templates/*.html")),
	}
	e.Renderer = t

	// Routes
	e.GET("/login", loginHandler)
	e.GET("/callback", callbackHandler)
	v1 := e.Group("/api/v1", auth.JwtMiddleware(auth.Auth0Config{
		Audience: os.Getenv("AUTH0_AUDIENCE"),
		Issuer:   fmt.Sprintf("https://%s/", os.Getenv("AUTH0_DOMAIN")),
		JWKSURL:  fmt.Sprintf("https://%s/.well-known/jwks.json", os.Getenv("AUTH0_DOMAIN")),
		Claims: map[string]interface{}{
			"roles": []string{"default_role"},
		},
	}))
	v1.GET("/hello", helloHandler)

	e.Logger.Fatal(e.Start(":8080"))
}

func helloHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, "Hello World")
}

func loginHandler(c echo.Context) error {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", os.Getenv("AUTH0_CLIENT_ID"))
	params.Set("redirect_uri", os.Getenv("AUTH0_CALLBACK_URL"))
	params.Set("scope", "openid profile email offline_access")
	params.Set("audience", os.Getenv("AUTH0_AUDIENCE"))

	url := fmt.Sprintf("https://%s/authorize?%s", os.Getenv("AUTH0_DOMAIN"), params.Encode())
	fmt.Println(url)

	return c.Redirect(http.StatusTemporaryRedirect, url)
}

func callbackHandler(c echo.Context) error {
	code := c.QueryParam("code")

	payload := url.Values{}
	payload.Set("grant_type", "authorization_code")
	payload.Set("client_id", os.Getenv("AUTH0_CLIENT_ID"))
	payload.Set("client_secret", os.Getenv("AUTH0_CLIENT_SECRET"))
	payload.Set("code", code)
	payload.Set("redirect_uri", os.Getenv("AUTH0_CALLBACK_URL"))
	payload.Set("audience", os.Getenv("AUTH0_AUDIENCE"))
	data := payload.Encode()
	body := strings.NewReader(data)

	req, err := http.NewRequest("POST", fmt.Sprintf("https://%s/oauth/token", os.Getenv("AUTH0_DOMAIN")), body)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}
	defer res.Body.Close()
	bodyResp, _ := io.ReadAll(res.Body)

	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	err = json.Unmarshal(bodyResp, &tokenResponse)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}

	fmt.Println(tokenResponse.AccessToken)

	return c.Render(http.StatusOK, "callback.html", map[string]interface{}{
		"AccessToken":  tokenResponse.AccessToken,
		"RefreshToken": tokenResponse.RefreshToken,
	})
}
