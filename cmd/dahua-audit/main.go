// Command dahua-audit is a single-device hardening checker for Dahua-style
// cameras/NVRs that YOU OWN or are explicitly authorized to test.
//
// What it does (defensive only):
//   - verifies a single host:port is reachable,
//   - identifies the web (CGI) and SDK (TCP/37777) surfaces,
//   - checks whether well-known VENDOR-DEFAULT credentials are still active on
//     the web interface, so you can fix them.
//
// What it deliberately does NOT do:
//   - no P2P / cloud reachability, no serial-number enumeration,
//   - no CVE exploitation, no authentication bypass, no account creation,
//   - no mass targeting: exactly one host:port per run, gated behind an
//     explicit ownership/authorization attestation.
//
// It is the hardening-audit counterpart to the analysis in
// docs/dahua-p2p-security-analysis.md.
package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Widely published Dahua factory-default pairs. We test only these, only against
// a device the operator attests they own, purely to report "you are still on a
// default and should change it."
var defaultCreds = []struct{ User, Pass string }{
	{"admin", "admin"},
	{"admin", "admin123"},
	{"admin", "123456"},
	{"888888", "888888"},
	{"666666", "666666"},
}

func main() {
	var (
		target  string
		owns    bool
		scheme  string
		timeout time.Duration
	)
	flag.StringVar(&target, "target", "", "a single host:port you own or are authorized to test (e.g. 192.168.1.108:80)")
	flag.BoolVar(&owns, "i-own-this-device", false, "REQUIRED: attest you own or have written authorization to test this device")
	flag.StringVar(&scheme, "scheme", "http", "scheme for the web interface check: http or https")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "per-connection timeout")
	flag.Parse()

	if err := run(target, owns, scheme, timeout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(target string, owns bool, scheme string, timeout time.Duration) error {
	if target == "" {
		return errors.New("--target is required (a single host:port, e.g. 192.168.1.108:80)")
	}
	if err := validateSingleTarget(target); err != nil {
		return err
	}
	if !owns {
		return errors.New("refusing to run without --i-own-this-device: this tool is only for devices you own or are authorized to test")
	}

	host, port, _ := net.SplitHostPort(target)
	fmt.Printf("dahua-audit — hardening check for %s\n", target)
	fmt.Printf("(single device only; no P2P, no enumeration, no exploitation)\n\n")

	// 1. Reachability.
	if err := checkReachable(target, timeout); err != nil {
		fmt.Printf("[reachability] UNREACHABLE: %v\n", err)
		return nil
	}
	fmt.Printf("[reachability] OK — TCP %s open\n", target)

	// 2. Surface identification (informational only).
	switch port {
	case "37777":
		fmt.Printf("[surface] TCP/37777 is the Dahua SDK port. This audit does not\n")
		fmt.Printf("          speak the binary SDK protocol; re-run against the web\n")
		fmt.Printf("          port (80/443) for the default-credential check.\n")
	case "80", "443", "8080":
		runWebChecks(scheme, host, port, timeout)
	default:
		fmt.Printf("[surface] Port %s is not a standard Dahua web/SDK port; trying a\n", port)
		fmt.Printf("          web (CGI) check anyway.\n")
		runWebChecks(scheme, host, port, timeout)
	}

	fmt.Printf("\nSee docs/dahua-p2p-security-analysis.md §6 for full hardening steps\n")
	fmt.Printf("(disable P2P if unused, patch firmware, segment the network).\n")
	return nil
}

// validateSingleTarget rejects anything that is not one host:port: no CIDR
// ranges, comma lists, wildcards, whitespace, or bare serial numbers. This keeps
// the tool structurally incapable of mass/sweep use.
func validateSingleTarget(t string) error {
	if strings.ContainsAny(t, ", \t*/\\") {
		return errors.New("target must be a single host:port — ranges, lists, wildcards, and files are not supported")
	}
	host, port, err := net.SplitHostPort(t)
	if err != nil {
		return fmt.Errorf("target must be host:port (got %q): %w", t, err)
	}
	if host == "" || port == "" {
		return errors.New("target must include both a host and a port, e.g. 192.168.1.108:80")
	}
	// A bare 10/15-digit string is a Dahua serial, not a host — refuse it so the
	// tool can't be pointed at the P2P/serial path.
	if isAllDigits(host) && (len(host) == 10 || len(host) == 15) {
		return errors.New("that looks like a device serial, not a host — this tool only tests a direct IP/hostname you own")
	}
	return nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func checkReachable(addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	return conn.Close()
}

func runWebChecks(scheme, host, port string, timeout time.Duration) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// Cameras ship self-signed certs; skip verification for the local
			// reachability/hardening check only.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		// Don't follow redirects; we want to see the auth challenge.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	base := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, port))
	url := base + "/cgi-bin/magicBox.cgi?action=getDeviceType"

	fmt.Printf("[web] probing %s\n", url)

	found := false
	for _, c := range defaultCreds {
		ok, err := tryDigest(client, url, c.User, c.Pass)
		if err != nil {
			fmt.Printf("[web] could not complete check with %q: %v\n", c.User, err)
			break
		}
		if ok {
			fmt.Printf("[web] \u26a0 DEFAULT CREDENTIALS ACTIVE: %s:%s — change this now\n", c.User, c.Pass)
			found = true
		}
	}
	if !found {
		fmt.Printf("[web] OK — no tested factory-default credential pair was accepted\n")
	}
}

// tryDigest performs a single HTTP Digest authentication round against url with
// the given credentials and reports whether access was granted (HTTP 200).
func tryDigest(client *http.Client, url, user, pass string) (bool, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		// No auth required at all — also a hardening finding, but report via the
		// caller's default-cred path by treating "open" as access granted.
		return true, nil
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return false, nil
	}

	ch := parseDigestChallenge(resp.Header.Get("WWW-Authenticate"))
	if ch["nonce"] == "" || ch["realm"] == "" {
		return false, nil // not Digest (or no challenge) — nothing to try
	}

	authHeader := buildDigestAuth(ch, user, pass, http.MethodGet, reqURI(url))
	req2, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req2.Header.Set("Authorization", authHeader)
	resp2, err := client.Do(req2)
	if err != nil {
		return false, err
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	return resp2.StatusCode == http.StatusOK, nil
}

func parseDigestChallenge(h string) map[string]string {
	out := map[string]string{}
	h = strings.TrimSpace(h)
	if i := strings.IndexByte(h, ' '); i >= 0 && strings.EqualFold(h[:i], "Digest") {
		h = h[i+1:]
	}
	for _, part := range splitDigestParams(h) {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.Trim(strings.TrimSpace(kv[1]), `"`)
		out[key] = val
	}
	return out
}

// splitDigestParams splits on commas that are not inside quotes.
func splitDigestParams(s string) []string {
	var parts []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case r == ',' && !inQuote:
			parts = append(parts, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		parts = append(parts, strings.TrimSpace(cur.String()))
	}
	return parts
}

func buildDigestAuth(ch map[string]string, user, pass, method, uri string) string {
	realm := ch["realm"]
	nonce := ch["nonce"]
	qop := ch["qop"]
	opaque := ch["opaque"]

	ha1 := md5hex(fmt.Sprintf("%s:%s:%s", user, realm, pass))
	ha2 := md5hex(fmt.Sprintf("%s:%s", method, uri))

	var response string
	var extra string
	if strings.Contains(qop, "auth") {
		qop = "auth"
		cnonce := randomHex(8)
		nc := "00000001"
		response = md5hex(strings.Join([]string{ha1, nonce, nc, cnonce, qop, ha2}, ":"))
		extra = fmt.Sprintf(`, qop=%s, nc=%s, cnonce="%s"`, qop, nc, cnonce)
	} else {
		response = md5hex(fmt.Sprintf("%s:%s:%s", ha1, nonce, ha2))
	}

	auth := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		user, realm, nonce, uri, response)
	auth += extra
	if opaque != "" {
		auth += fmt.Sprintf(`, opaque="%s"`, opaque)
	}
	return auth
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b)
}

// reqURI returns the path+query portion of a URL for the Digest uri field.
func reqURI(full string) string {
	i := strings.Index(full, "://")
	if i < 0 {
		return full
	}
	rest := full[i+3:]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return rest[j:]
	}
	return "/"
}
