package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello OpenShift!")
	fmt.Println("Servicing request for /")
}

func listenAndServe(port, certfile, keyfile string) {
	var err error
	if len(certfile) != 0 && len(keyfile) != 0 {
		fmt.Printf("serving HTTPS on %s\n", port)
		err = http.ListenAndServeTLS(":"+port, certfile, keyfile, nil)
	} else {
		fmt.Printf("serving HTTP on %s\n", port)
		err = http.ListenAndServe(":"+port, nil)
	}
	if err != nil {
		panic("ListenAndServe: " + err.Error())
	}
}

func main() {
	http.HandleFunc("/", rootHandler)

	subPaths := os.Getenv("HELLO_SUBPATHS")
	if len(subPaths) != 0 {
		paths := strings.Split(subPaths, ",")
		for i := range paths {
			p := paths[i]
			http.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, "Hello OpenShift! %s\n", p)
				fmt.Println("Servicing request for " + p)
			})
		}
	}

	port := os.Getenv("HELLO_PORT")
	if len(port) == 0 {
		port = "8080"
	}
	go listenAndServe(port, os.Getenv("HELLO_TLS_CERT"), os.Getenv("HELLO_TLS_KEY"))
	select {}
}
