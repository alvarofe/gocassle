package main

import (
	r "github.com/alvarofe/gocassle/server/routes"
	"github.com/ant0ine/go-json-rest/rest"
	"log"
	"net/http"
)

func main() {

	api := rest.NewApi()
	api.Use(rest.DefaultDevStack...)
	router, err := rest.MakeRouter(r.Routes...)
	if err != nil {
		log.Fatal(err)
	}
	api.SetApp(router)
	log.Fatal(http.ListenAndServe(":8080", api.MakeHandler()))
}
