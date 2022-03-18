package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const fwapidVersion = "1.0.0"

// CLIOptions - structure for command line options
type CLIOptions struct {
	domain      string
	httpsrv     string
	httpssrv    string
	httpsusele  bool
	httpspubkey string
	httpsprvkey string
	allowfile   string
	logfile     string
	version     bool
}

var cliops = CLIOptions{
	domain:      "",
	httpsrv:     "127.0.0.1:8840",
	httpssrv:    "",
	httpsusele:  false,
	httpspubkey: "",
	httpsprvkey: "",
	allowfile:   "",
	logfile:     "",
	version:     false,
}

type AllowRules struct {
	Mode  int        `json:"mode"`
	Rules []RuleData `json:"rules"`
}

type RuleData struct {
	Name    string   `json:"name"`
	Key     string   `json:"key"`
	Actions []string `json:"actions"`
}

var vAllowRules AllowRules = AllowRules{}

func isAllowed(vAction string, vKey string) bool {
	for i := 0; i < len(vAllowRules.Rules); i++ {
		if vAllowRules.Rules[i].Key == vKey {
			for j := 0; j < len(vAllowRules.Rules[i].Actions); j++ {
				if vAllowRules.Rules[i].Actions[j] == vAction {
					return true
				}
			}
			return false
		}
	}
	return false
}

// Run git command, will currently die on all errors
func runCmd(cmd *exec.Cmd) *bytes.Buffer {
	cmd.Dir = "/tmp/"
	var out bytes.Buffer
	cmd.Stdout = &out
	runError := cmd.Run()
	if runError != nil {
		log.Printf("error: (%s) command failed with:\n\"%s\n\"", runError, out.String())
		return bytes.NewBuffer([]byte{})
	}
	return &out
}

func fwapidHandler(w http.ResponseWriter, r *http.Request) {
	sURL := strings.TrimSpace(r.URL.Path)
	if len(sURL) == 0 || sURL == "/" {
		http.Error(w, "Invalid URL", http.StatusNotFound)
		return
	}
	tURL := strings.Split(sURL, "/")
	if len(tURL) < 2 {
		log.Printf("Too few tokens in URL: %s\n", sURL)
		http.Error(w, "Too few tokens", http.StatusBadRequest)
		return
	}

	allowBytes, err := os.ReadFile(cliops.allowfile)
	if err != nil {
		log.Printf("unavailable allow file: %s\n", sURL)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	err = json.Unmarshal(allowBytes, &vAllowRules)
	if err != nil {
		log.Printf("invalid content in allow file: %s\n", sURL)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	if !isAllowed(tURL[0], tURL[1]) {
		log.Printf("action not allowed from URL: %s\n", sURL)
		http.Error(w, "Not allowed", http.StatusForbidden)
		return
	}

	ipAddr := "127.0.0.1"
	switch tURL[0] {
	case "allow":
		ipAddr, _, err = net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Printf("action not allowed from URL: %s\n", sURL)
			http.Error(w, "Not allowed", http.StatusForbidden)
			return
		}
	case "allowip":
		if len(tURL) < 3 || len(tURL[2]) < 4 {
			log.Printf("too few tokens in URL: %s\n", sURL)
			http.Error(w, "Too few tokens", http.StatusBadRequest)
			return
		}
	default:
		log.Printf("action not allowed from URL: %s\n", sURL)
		http.Error(w, "Not allowed", http.StatusForbidden)
		return
	}

	netIP := net.ParseIP(ipAddr)
	if netIP == nil {
		log.Printf("action not allowed from URL: %s\n", sURL)
		http.Error(w, "Not allowed", http.StatusForbidden)
		return
	}

	log.Printf("allowed %s via URL: %s\n", ipAddr, sURL)
	// iptables -I INPUT -s abc.def.ghi.jkl -p tcp -m multiport --dports 80,443 -j ACCEPT
	runCmd(exec.Command("iptables", "-I", "-s", ipAddr, "-p", "tcp", "-m", "multiport",
		"--dports", "80,443", "-j", "ACCEPT"))

	fmt.Fprintf(w, "{ \"allowed\": \"%s\" }", ipAddr)
}

func startHTTPServices() chan error {

	errchan := make(chan error)

	// starting HTTP server
	if len(cliops.httpsrv) > 0 {
		go func() {
			log.Printf("staring HTTP service on: http://%s/ ...", cliops.httpsrv)
			if err := http.ListenAndServe(cliops.httpsrv, nil); err != nil {
				errchan <- err
			}

		}()
	}

	// starting HTTPS server
	if len(cliops.httpssrv) > 0 && len(cliops.httpspubkey) > 0 && len(cliops.httpsprvkey) > 0 {
		go func() {
			log.Printf("Staring HTTPS service on: http://%s/ ...", cliops.httpssrv)
			if len(cliops.domain) > 0 {
				dtoken := strings.Split(strings.TrimSpace(cliops.domain), ":")
				log.Printf("HTTPS with domain: https://%s:%s/ ...", cliops.domain, dtoken[1])
			}

			if err := http.ListenAndServeTLS(cliops.httpssrv, cliops.httpspubkey, cliops.httpsprvkey, nil); err != nil {
				errchan <- err
			}
		}()
	}

	return errchan
}

// initialize application components
func init() {
	// command line arguments
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s (v%s):\n", filepath.Base(os.Args[0]), fwapidVersion)
		flag.PrintDefaults()
		os.Exit(1)
	}

	flag.StringVar(&cliops.domain, "domain", cliops.domain, "http service domain")
	flag.StringVar(&cliops.httpsrv, "http-srv", cliops.httpsrv, "http server bind address")
	flag.StringVar(&cliops.httpssrv, "https-srv", cliops.httpssrv, "https server bind address")
	flag.StringVar(&cliops.httpspubkey, "https-pubkey", cliops.httpspubkey, "https server public key")
	flag.StringVar(&cliops.httpsprvkey, "https-prvkey", cliops.httpsprvkey, "https server private key")
	flag.StringVar(&cliops.allowfile, "allow-file", cliops.allowfile, "path to allow file")
	flag.StringVar(&cliops.logfile, "log", cliops.logfile, "path to log file or stdout")
	flag.BoolVar(&cliops.httpsusele, "use-letsencrypt", cliops.httpsusele,
		"use local letsencrypt certificates (requires domain)")
	flag.BoolVar(&cliops.version, "version", cliops.version, "print version")
}

func main() {
	// get flags
	flag.Parse()

	if cliops.httpsusele && len(cliops.domain) == 0 {
		log.Printf("use-letsencrypt requires domain parameter\n")
		os.Exit(1)
	}
	if cliops.httpsusele && len(cliops.httpssrv) > 0 && len(cliops.domain) > 0 {
		cliops.httpspubkey = "/etc/letsencrypt/live/" + cliops.domain + "/fullchain.pem"
		cliops.httpsprvkey = "/etc/letsencrypt/live/" + cliops.domain + "/privkey.pem"
	}

	// Open our Log
	if len(cliops.logfile) > 0 && cliops.logfile != "-" && cliops.logfile != "stdout" {
		lf, err := os.OpenFile(cliops.logfile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Panic(err)
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			runtime.Goexit()
		}
		defer lf.Close()

		log.SetOutput(lf)
	}

	http.HandleFunc("/", fwapidHandler)
	errchan := startHTTPServices()
	select {
	case err := <-errchan:
		log.Printf("unable to start http services due to (error: %v)", err)
	}
	os.Exit(1)
}
