// main.go
//creator Bilal Inamdar
//bilalinamdar@gmail.com
//https://github.com/wmks-proxy

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"github.com/gorilla/mux"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
)

const version = "1.1"

/* ------------------------- env helpers ------------------------- */

func getEnvOrdered(names ...string) string {
	for _, k := range names {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func parseBoolEnv(val string, def bool) bool {
	if val == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return def
	}
}

func humanHelp(defaultListen string) string {
	return fmt.Sprintf(`webmks-proxy — vSphere WebMKS console proxy & VM browser (v%s)

SWITCHES
  --help            Show this help and exit
  --version         Show version and exit
  -listen ADDRESS   Bind address/port (default %q). Examples: ":8081", "0.0.0.0:8081", "0.0.0.0:443"

ENV / .ENV  (shell env overrides .env; prefer VCENTER_* names)
  VCENTER_URL         vCenter URL (e.g. https://vc.example.local)
  VCENTER_USER        vCenter username
  VCENTER_PASS        vCenter password
  VCENTER_LISTEN      Bind address/port if -listen not given (e.g. ":8081")
  VCENTER_SECURE_TLS  true|false — verify ESXi TLS certs (default: false)

Also accepted (lower priority): VMWARE_* → WEBMKS_* → legacy VCENTER / VMRC_USER / VMRC_PASS / PORT / SECURE_TLS

NETWORK & DNS  (IMPORTANT)
  • The proxy host MUST resolve:
      1) the vCenter FQDN, and
      2) every ESXi hostname returned in tickets.
    Use corporate DNS or add static hosts; otherwise consoles won’t connect.
    Linux /etc/hosts example:
      10.10.10.5   vc.example.local
      10.10.20.11  esx01.lab.local
      10.10.20.12  esx02.lab.local
  • Browsers only connect to this proxy; they do NOT talk to ESXi directly.

OPTIONAL EDGE (SSL & domain handled outside)
  • Use Nginx or Caddy for SSL, domain, rate limits, SSO, and timeouts.
    Ensure WebSocket Upgrade and long read timeouts for /ticket/*.

USAGE
  VCENTER_URL=https://vc.example.local VCENTER_USER=admin@vsphere.local VCENTER_PASS=*** \
  ./webmks-proxy -listen :8081

SERVICE
  Linux (systemd):
    [Unit] Description=WebMKS Proxy
    [Service]
    WorkingDirectory=/opt/webmks
    ExecStart=/opt/webmks/webmks-proxy -listen :8081
    EnvironmentFile=/opt/webmks/.env
    Restart=on-failure
    [Install] WantedBy=multi-user.target
    # systemctl enable --now webmks-proxy

  Windows:
    sc.exe create WebMKS binPath= "C:\webmks\webmks-proxy.exe -listen :8081" start= auto
    (set VCENTER_* vars in System Environment)

Creator
  Name : Bilal Inamdar
  Email: bilalinamdar@gmail.com
  Project: https://github.com/wmks-proxy
`, version, defaultListen)
}

/* ---------------------- CSP / headers ---------------------- */

func withSecurityHeaders(next http.Handler) http.Handler {
	const csp = "" +
		"default-src 'self'; " +
		"script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data: blob:; " +
		"connect-src 'self' http: https: ws: wss:; " +
		"font-src 'self' data:; " +
		"object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

/* ---------------------- ticket store (TTL) ---------------------- */

type ticketEntry struct {
	host    string
	expires time.Time
}
type ticketStore struct{ m sync.Map }

func (s *ticketStore) Put(id, host string, ttl time.Duration) {
	s.m.Store(id, ticketEntry{host: host, expires: time.Now().Add(ttl)})
}
func (s *ticketStore) Get(id string) (string, bool) {
	if v, ok := s.m.Load(id); ok {
		e := v.(ticketEntry)
		if time.Now().Before(e.expires) {
			return e.host, true
		}
		s.m.Delete(id)
	}
	return "", false
}
func (s *ticketStore) Janitor(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			s.m.Range(func(k, v any) bool {
				if v.(ticketEntry).expires.Before(now) {
					s.m.Delete(k)
				}
				return true
			})
		}
	}
}

/* ---------------- VM list (1 round-trip) ---------------- */

type VMItem struct {
	Name    string     `json:"name"`
	Created *time.Time `json:"created,omitempty"`
	Boot    *time.Time `json:"boot,omitempty"`
}
func bestTime(v VMItem) time.Time {
	if v.Created != nil {
		return *v.Created
	}
	if v.Boot != nil {
		return *v.Boot
	}
	return time.Time{}
}
func getPoweredOnVMItems(ctx context.Context, c *govmomi.Client) ([]VMItem, error) {
	m := view.NewManager(c.Client)
	v, err := m.CreateContainerView(ctx, c.ServiceContent.RootFolder, []string{"VirtualMachine"}, true)
	if err != nil { return nil, err }
	defer v.Destroy(ctx)

	var mos []mo.VirtualMachine
	if err := v.Retrieve(ctx, []string{"VirtualMachine"},
		[]string{"name", "runtime.powerState", "config.createDate", "runtime.bootTime"}, &mos); err != nil {
		return nil, err
	}

	out := make([]VMItem, 0, len(mos))
	for _, vm := range mos {
		if string(vm.Runtime.PowerState) == "poweredOn" {
			out = append(out, VMItem{ Name: vm.Name, Created: vm.Config.CreateDate, Boot: vm.Runtime.BootTime })
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ti, tj := bestTime(out[i]), bestTime(out[j])
		if !ti.Equal(tj) { return ti.After(tj) }
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

/* ------------------------------ main ------------------------------ */

func main() {
	// Load .env (does NOT override existing shell env)
	_ = godotenv.Load()

	// Defaults from env (priority: VCENTER_* → VMWARE_* → WEBMKS_* → legacy)
	envListen := getEnvOrdered("VCENTER_LISTEN", "VMWARE_LISTEN", "WEBMKS_LISTEN", "PORT", "LISTEN")
	if envListen == "" {
		envListen = ":8081"
	} else if _, err := strconv.Atoi(envListen); err == nil {
		envListen = ":" + envListen
	}

	// Flags
	flagHelp := flag.Bool("help", false, "show help")
	flagVersion := flag.Bool("version", false, "show version")
	flagListen := flag.String("listen", envListen, "listen address")
	flag.Usage = func() { fmt.Print(humanHelp(envListen)) }
	flag.Parse()

	if *flagHelp {
		fmt.Print(humanHelp(envListen))
		return
	}
	if *flagVersion {
		fmt.Println(version)
		return
	}

	// Resolve config from env (priority order)
	vcURLRaw := getEnvOrdered("VCENTER_URL", "VMWARE_VCENTER", "WEBMKS_VCENTER", "VCENTER")
	user := getEnvOrdered("VCENTER_USER", "VMWARE_USER", "WEBMKS_USER", "VMRC_USER")
	pass := getEnvOrdered("VCENTER_PASS", "VMWARE_PASS", "WEBMKS_PASS", "VMRC_PASS")
	secureTLS := parseBoolEnv(getEnvOrdered("VCENTER_SECURE_TLS", "VMWARE_SECURE_TLS", "WEBMKS_SECURE_TLS", "SECURE_TLS"), false)

	listenAddr := *flagListen
	if listenAddr == "" {
		listenAddr = envListen
	}

	// Validate
	if vcURLRaw == "" || user == "" || pass == "" {
		fmt.Print(humanHelp(envListen))
		log.Fatal("Missing required config: VCENTER_URL / VCENTER_USER / VCENTER_PASS")
	}

	// vCenter client
	vcURL, err := soap.ParseURL(vcURLRaw) // defaults to https if scheme omitted
	if err != nil { log.Fatal("Bad VCENTER_URL:", err) }
	vcURL.User = url.UserPassword(user, pass)

	indexTmpl := template.Must(template.ParseFiles("templates/index.html"))
	consoleTmpl := template.Must(template.ParseFiles("templates/console.html"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := govmomi.NewClient(ctx, vcURL, true)
	if err != nil { log.Fatal("govmomi.NewClient:", err) }

	checkLogin := func(ctx context.Context, c *govmomi.Client, ui *url.Userinfo) {
		ok, err := c.SessionManager.UserSession(ctx)
		if err != nil { log.Fatal("UserSession:", err) }
		if ok == nil {
			if err := c.SessionManager.Login(ctx, ui); err != nil {
				log.Fatal("SessionManager.Login:", err)
			}
		}
	}

	finder := find.NewFinder(client.Client, true)
	if dc, _ := finder.DefaultDatacenter(ctx); dc != nil {
		finder.SetDatacenter(dc)
	}

	var tickets ticketStore
	go tickets.Janitor(ctx, 2*time.Minute)

	r := mux.NewRouter()

	// index
	r.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		checkLogin(ctx, client, vcURL.User)
		items, err := getPoweredOnVMItems(req.Context(), client)
		if err != nil { http.Error(w, "VM list failed: "+err.Error(), 502); return }
		vmJSON, _ := json.Marshal(items)
		type idx struct {
			VMsJSON     template.JS
			VCenterHost string
		}
		_ = indexTmpl.Execute(w, idx{
			VMsJSON:     template.JS(string(vmJSON)),
			VCenterHost: vcURL.Host,
		})
	})

	// console
	r.HandleFunc("/console/{vm}", func(w http.ResponseWriter, req *http.Request) {
		checkLogin(ctx, client, vcURL.User)
		vm, err := finder.VirtualMachine(ctx, mux.Vars(req)["vm"])
		if err != nil { http.Error(w, "VM not found: "+err.Error(), 404); return }
		ticket, err := vm.AcquireTicket(ctx, "webmks")
		if err != nil { http.Error(w, "AcquireTicket failed: "+err.Error(), 502); return }

		host := net.JoinHostPort(ticket.Host, strconv.Itoa(int(ticket.Port)))
		tickets.Put(ticket.Ticket, host, 5*time.Minute)

		esxi := ticket.Host
		if hs, err := vm.HostSystem(ctx); err == nil && hs != nil {
			if hn, err := hs.ObjectName(ctx); err == nil && hn != "" {
				esxi = hn
			}
		}

		_ = consoleTmpl.Execute(w, struct {
			Name   string
			Ticket string
			VC     string
			ESXi   string
		}{
			Name:   user,
			Ticket: ticket.Ticket,
			VC:     vcURL.Host,
			ESXi:   esxi,
		})
	})

	// static
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static/"))))

	// ticket proxy
	wsProxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			id := strings.TrimPrefix(req.URL.Path, "/ticket/")
			if id == "" {
				log.Printf("proxy: empty ticket in path %q", req.URL.Path)
				return
			}
			if host, ok := tickets.Get(id); ok {
				req.URL.Scheme = "https"
				req.URL.Host = host
				req.Host = host
			} else {
				log.Printf("proxy: unknown/expired ticket %q", id)
			}
			if _, ok := req.Header["User-Agent"]; !ok {
				req.Header.Set("User-Agent", "")
			}
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !secureTLS},
		},
		FlushInterval: 100 * time.Millisecond,
	}
	r.Handle("/ticket/{ticket}", wsProxy)

	handler := withSecurityHeaders(r)

	log.Println("listening on", listenAddr)
	if err := http.ListenAndServe(listenAddr, handler); err != nil {
		log.Fatal(err)
	}
}

