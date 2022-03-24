package main

import (
	"bytes"
	"encoding/json"
	"errors"
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
	"sync"
	"time"
)

const fwapidVersion = "1.0.0"

// CLIOptions - structure for command line options
type CLIOptions struct {
	domain        string
	httpsrv       string
	httpssrv      string
	httpsusele    bool
	httpspubkey   string
	httpsprvkey   string
	allowfile     string
	logfile       string
	cacheexpire   int64
	timerinterval int
	version       bool
}

var cliops = CLIOptions{
	domain:        "",
	httpsrv:       "",
	httpssrv:      "",
	httpsusele:    false,
	httpspubkey:   "",
	httpsprvkey:   "",
	allowfile:     "",
	logfile:       "",
	cacheexpire:   0,
	timerinterval: 120,
	version:       false,
}

type AllowRules struct {
	Mode    int        `json:"mode"`
	Command string     `json:"command"`
	OpAdd   string     `json:"opadd"`
	OpDel   string     `json:"opdel"`
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

type CacheItem struct {
	Key      string
	Command  string
	OpAdd    string
	OpDel    string
	Policy   string
	IPAddr   string
	DPorts   string
	ExpireAt int64
}

type CacheData struct {
	stop chan struct{}

	wg    sync.WaitGroup
	mu    sync.RWMutex
	items map[string]CacheItem
}

var localCacheData *CacheData = nil

func newCacheData(timerInterval time.Duration) *CacheData {
	cd := &CacheData{
		items: make(map[string]CacheItem),
		stop:  make(chan struct{}),
	}

	cd.wg.Add(1)
	go func(cleanupInterval time.Duration) {
		defer cd.wg.Done()
		cd.timerLoop(timerInterval)
	}(timerInterval)

	return cd
}

func (cd *CacheData) timerLoop(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-cd.stop:
			return
		case <-t.C:
			cd.mu.Lock()
			for cid, cit := range cd.items {
				if cit.ExpireAt <= time.Now().Unix() {
					log.Printf("revoking %s for key: %s\n", cit.IPAddr, cit.Key)
					runCmd(exec.Command(cit.Command, cit.OpDel, "INPUT", "-s", cit.IPAddr, "-p", "tcp", "-m", "multiport",
						"--dports", cit.DPorts, "-j", cit.Policy))
					delete(cd.items, cid)
				}
			}
			cd.mu.Unlock()
		}
	}
}

func (cd *CacheData) stopTimer() {
	close(cd.stop)
	cd.wg.Wait()
}

func (cd *CacheData) set(cid string, cit CacheItem) {
	cd.mu.Lock()
	defer cd.mu.Unlock()

	cd.items[cid] = cit
}

var (
	errItemNotInCache = errors.New("item not in cache")
)

func (cd *CacheData) get(cid string) (CacheItem, error) {
	cd.mu.RLock()
	defer cd.mu.RUnlock()

	cit, ok := cd.items[cid]
	if !ok {
		return CacheItem{}, errItemNotInCache
	}

	return cit, nil
}

func (cd *CacheData) rm(cid string) {
	cd.mu.Lock()
	defer cd.mu.Unlock()

	delete(cd.items, cid)
}

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

func getKeyIndex(vKey string) int {
	for i := 0; i < len(vAllowRules.Rules); i++ {
		if vAllowRules.Rules[i].Key == vKey {
			return i
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
	if len(vAllowRules.OpAdd) == 0 {
		vAllowRules.OpAdd = "-I"
	}
	if len(vAllowRules.OpDel) == 0 {
		vAllowRules.OpDel = "-D"
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
		log.Printf("allowing %s from %s via URL: %s\n", ipAddr, srcIPAddr, sURL)
		log.Printf("allow command: %s %s %s %s %s %s %s %s %s %s %s %s %s\n",
			vAllowRules.Command, vAllowRules.OpAdd, "INPUT", "-s", ipAddr, "-p", "tcp", "-m", "multiport",
			"--dports", vAllowRules.Rules[idxAllow].DPorts, "-j", vAllowRules.Policy)

		runCmd(exec.Command(vAllowRules.Command, vAllowRules.OpAdd, "INPUT", "-s", ipAddr, "-p", "tcp", "-m", "multiport",
			"--dports", vAllowRules.Rules[idxAllow].DPorts, "-j", vAllowRules.Policy))
		fmt.Fprintf(w, "{ \"action\": \"allow\", \"address\": \"%s\" }", ipAddr)
		if localCacheData != nil {
			var cItem CacheItem = CacheItem{
				Key:      tURL[2],
				Command:  vAllowRules.Command,
				OpAdd:    vAllowRules.OpAdd,
				OpDel:    vAllowRules.OpAdd,
				Policy:   vAllowRules.Policy,
				IPAddr:   ipAddr,
				DPorts:   vAllowRules.Rules[idxAllow].DPorts,
				ExpireAt: time.Now().Unix() + cliops.cacheexpire,
			}
			localCacheData.set(ipAddr, cItem)
		}
	case "revoke", "revokeip":
		log.Printf("revoking %s from %s via URL: %s\n", ipAddr, srcIPAddr, sURL)
		log.Printf("revoke command: %s %s %s %s %s %s %s %s %s %s %s %s %s\n",
			vAllowRules.Command, vAllowRules.OpDel, "INPUT", "-s", ipAddr, "-p", "tcp", "-m", "multiport",
			"--dports", vAllowRules.Rules[idxAllow].DPorts, "-j", vAllowRules.Policy)

		runCmd(exec.Command(vAllowRules.Command, vAllowRules.OpDel, "INPUT", "-s", ipAddr, "-p", "tcp", "-m", "multiport",
			"--dports", vAllowRules.Rules[idxAllow].DPorts, "-j", vAllowRules.Policy))
		fmt.Fprintf(w, "{ \"action\": \"revoke\", \"address\": \"%s\" }", ipAddr)
	case "show":
		log.Printf("showing %s from %s via URL: %s\n", ipAddr, srcIPAddr, sURL)
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
	flag.StringVar(&cliops.logfile, "log-file", cliops.logfile, "path to log file or stdout")
	flag.BoolVar(&cliops.httpsusele, "use-letsencrypt", cliops.httpsusele,
		"use local letsencrypt certificates (requires domain)")
	flag.Int64Var(&cliops.cacheexpire, "cache-expire", cliops.cacheexpire,
		"duration in seconds to expire items in the cache")
	flag.IntVar(&cliops.timerinterval, "timer-interval", cliops.timerinterval,
		"duration in seconds to run timer callback for cache expiration")
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

	if cliops.cacheexpire > 0 {
		localCacheData = newCacheData(time.Duration(cliops.timerinterval) * time.Second)
	}
	http.HandleFunc("/", fwapidHandler)
	errchan := startHTTPServices()
	select {
	case err := <-errchan:
		log.Printf("unable to start http services due to (error: %v)", err)
	}
	os.Exit(1)
}
