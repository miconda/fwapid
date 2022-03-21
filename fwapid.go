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
	httpsrv:     "",
	httpssrv:    "",
	httpsusele:  false,
	httpspubkey: "",
	httpsprvkey: "",
	allowfile:   "",
	logfile:     "",
	version:     false,
}

type AllowRules struct {
	Mode    int        `json:"mode"`
	Command string     `json:"command"`
	Policy  string     `json:"policy"`
	Rules   []RuleData `json:"rules"`
}

type RuleData struct {
	Name    string   `json:"name"`
	Key     string   `json:"key"`
	DPorts  string   `json:"dports"`
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

func getAllowedIndex(vAction string, vKey string) int {
	for i := 0; i < len(vAllowRules.Rules); i++ {
		if vAllowRules.Rules[i].Key == vKey {
			for j := 0; j < len(vAllowRules.Rules[i].Actions); j++ {
				if vAllowRules.Rules[i].Actions[j] == vAction {
					return i
				}
			}
			return -1
		}
	}
	return -1
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
	srcIPAddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Printf("action not allowed from %s URL: %s\n", srcIPAddr, sURL)
		http.Error(w, "Not allowed", http.StatusForbidden)
		return
	}
	if len(sURL) == 0 || sURL == "/" {
		log.Printf("invalid request from %s URL: %s\n", srcIPAddr, sURL)
		http.Error(w, "Invalid URL", http.StatusNotFound)
		return
	}
	if !strings.HasPrefix(sURL, "/") {
		sURL = "/" + sURL
	}
	tURL := strings.Split(sURL, "/")
	if len(tURL) < 3 {
		log.Printf("Too few tokens from %s in URL: %s\n", srcIPAddr, sURL)
		http.Error(w, "Too few tokens", http.StatusBadRequest)
		return
	}

	allowBytes, err := os.ReadFile(cliops.allowfile)
	if err != nil {
		log.Printf("unavailable allow file - from %s URL: %s\n", srcIPAddr, sURL)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	err = json.Unmarshal(allowBytes, &vAllowRules)
	if err != nil {
		log.Printf("invalid content in allow file -  from %s URL: %s\n", srcIPAddr, sURL)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	if len(vAllowRules.Command) == 0 {
		vAllowRules.Command = "iptables"
	}
	if len(vAllowRules.Policy) == 0 {
		vAllowRules.Policy = "ACCEPT"
	}
	idxAllow := getAllowedIndex(tURL[1], tURL[2])
	if idxAllow < 0 {
		log.Printf("action not allowed from %s URL: %s\n", srcIPAddr, sURL)
		http.Error(w, "Not allowed", http.StatusForbidden)
		return
	}

	ipAddr := srcIPAddr
	switch tURL[1] {
	case "allow", "revoke", "show":
	case "allowip", "revokeip":
		if len(tURL) < 4 || len(strings.TrimSpace(tURL[3])) < 4 {
			log.Printf("too few tokens from %s URL: %s\n", srcIPAddr, sURL)
			http.Error(w, "Too few tokens", http.StatusBadRequest)
			return
		}
		ipAddr = strings.TrimSpace(tURL[3])
	default:
		log.Printf("action not allowed from %s URL: %s\n", srcIPAddr, sURL)
		http.Error(w, "Not allowed", http.StatusForbidden)
		return
	}

	netIP := net.ParseIP(ipAddr)
	if netIP == nil {
		log.Printf("action not allowed from %s URL: %s\n", srcIPAddr, sURL)
		http.Error(w, "Not allowed", http.StatusForbidden)
		return
	}

	if len(vAllowRules.Rules[idxAllow].DPorts) == 0 {
		vAllowRules.Rules[idxAllow].DPorts = "80,443"
	}
	// iptables -I|-D INPUT -s abc.def.ghi.jkl -p tcp -m multiport --dports 80,443 -j ACCEPT
	switch tURL[1] {
	case "allow", "allowip":
		log.Printf("allowed %s from %s via URL: %s\n", ipAddr, srcIPAddr, sURL)
		runCmd(exec.Command(vAllowRules.Command, "-I", "-s", ipAddr, "-p", "tcp", "-m", "multiport",
			"--dports", vAllowRules.Rules[idxAllow].DPorts, "-j", vAllowRules.Policy))
		fmt.Fprintf(w, "{ \"action\": \"allow\", \"address\": \"%s\" }", ipAddr)
	case "revoke", "revokeip":
		log.Printf("revoked %s from %s via URL: %s\n", ipAddr, srcIPAddr, sURL)
		runCmd(exec.Command(vAllowRules.Command, "-D", "-s", ipAddr, "-p", "tcp", "-m", "multiport",
			"--dports", vAllowRules.Rules[idxAllow].DPorts, "-j", vAllowRules.Policy))
		fmt.Fprintf(w, "{ \"action\": \"revoke\", \"address\": \"%s\" }", ipAddr)
	case "show":
		log.Printf("showed %s from %s via URL: %s\n", ipAddr, srcIPAddr, sURL)
		fmt.Fprintf(w, "{ \"action\": \"show\", \"address\": \"%s\" }", ipAddr)
	}
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
				dtoken := strings.Split(strings.TrimSpace(cliops.httpssrv), ":")
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

	if len(cliops.httpsrv) == 0 && len(cliops.httpssrv) == 0 {
		log.Printf("no http or https server address - exiting\n")
		os.Exit(1)
	}
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
