package routes

import (
	m "github.com/alvarofe/gocassle/server/models"
	"github.com/ant0ine/go-json-rest/rest"
)

var users m.Users = m.Users{
	Store: map[string]*m.User{},
}

var Routes []*rest.Route = []*rest.Route{
	&rest.Route{"GET", "/pins", m.GetAllPins},
	&rest.Route{"POST", "/pins", m.PostPin},
}
