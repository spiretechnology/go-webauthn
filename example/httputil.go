package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
)

func HttpGet[T any](handler func(ctx context.Context) (*T, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, err := handler(r.Context())
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusOK, result)
	})
}

func HttpPost[T, K any](handler func(ctx context.Context, req *T) (*K, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req T
		_ = json.NewDecoder(r.Body).Decode(&req)
		result, err := handler(r.Context(), &req)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, err)
			return
		}
		respondJSON(w, http.StatusOK, result)
	})
}

func respondJSON(w http.ResponseWriter, status int, data any) {
	if err, ok := data.(error); ok {
		data = map[string]string{"error": err.Error()}
	}
	dataJSON, _ := json.Marshal(data)
	w.Header().Add("Content-Type", "application/json")
	w.Header().Add("Content-Length", strconv.Itoa(len(dataJSON)))
	w.WriteHeader(status)
	w.Write(dataJSON)
}
