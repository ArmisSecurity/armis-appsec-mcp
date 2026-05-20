// Primary file: takes user input from HTTP request, passes to handler package
package main

import (
	"net/http"
	"github.com/org/myapp/internal/handler"
)

func main() {
	http.HandleFunc("/convert", func(w http.ResponseWriter, r *http.Request) {
		filename := r.FormValue("file")
		handler.ProcessFile(filename)
		w.Write([]byte("done"))
	})
	http.ListenAndServe(":8080", nil)
}
