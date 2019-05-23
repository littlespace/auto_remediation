package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/mayuresh82/auto_remediation/models"
	"github.com/mayuresh82/auto_remediation/remediator"
	"github.com/stretchr/testify/assert"
)

type MockDB struct {
	query func() ([]interface{}, error)
	*models.DB
}

func (m *MockDB) Query(table string, params map[string]interface{}) ([]interface{}, error) {
	if m.query != nil {
		return m.query()
	}
	return nil, fmt.Errorf("Nothing found")
}

func TestServerGet(t *testing.T) {
	db := &MockDB{}
	r := &remediator.Remediator{
		Config: &remediator.ConfigHandler{Rules: []remediator.Rule{
			remediator.Rule{AlertName: "Test"},
		}},
		Db: db,
	}
	s := &Server{rem: r}
	router := mux.NewRouter()
	router.HandleFunc("/api/{category}", s.Get).Methods("GET")

	rr := httptest.NewRecorder()
	// test rules get
	req, err := http.NewRequest("GET", "/api/rules", nil)
	if err != nil {
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	assert.Equal(t, rr.Code, http.StatusOK)
	var rules []remediator.Rule
	if err := json.NewDecoder(rr.Result().Body).Decode(&rules); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, len(rules), 1)
	assert.Equal(t, rules[0].AlertName, "Test")

	// test rem get
	db.query = func() ([]interface{}, error) { return nil, fmt.Errorf("Dummy error") }
	req, _ = http.NewRequest("GET", "/api/remediations", nil)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, rr.Code, http.StatusInternalServerError)

	db.query = func() ([]interface{}, error) {
		ret := []interface{}{
			&models.Remediation{Id: 99, IncidentName: "Test"},
		}
		return ret, nil
	}
	req, _ = http.NewRequest("GET", "/api/remediations", nil)
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, rr.Code, http.StatusOK)
	var rem []*models.Remediation
	if err := json.NewDecoder(rr.Result().Body).Decode(&rem); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, len(rem), 1)
	assert.Equal(t, rem[0].Id, int64(99))
}
