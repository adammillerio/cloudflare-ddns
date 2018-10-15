// Package main of cloudyn provides a server for updating CloudFlare
// DNS entries using the dyn dynamic DNS API.
// API reference: https://help.dyn.com/remote-access-api/perform-update/
// Return code reference: https://help.dyn.com/remote-access-api/return-codes/
package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"

	cloudflare "github.com/cloudflare/cloudflare-go"
	envconfig "github.com/kelseyhightower/envconfig"
	log "github.com/sirupsen/logrus"
)

// Type config represents the configuration for the application, with the names
// of the variables representing their corresponding environment variables.
type config struct {
	Addr              string `default:":8080"`
	LogLevel          string `default:"info" split_words:"true"`
	DisableAccessLogs bool   `default:"false" split_words:"true"`
}

// Regex for hostname validation, compiled at runtime
var hostnameRegex = regexp.MustCompile(`^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})
	|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a
	-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$`)

// Application configuration
var cfg config

func init() {
	// Parse environment variables
	err := envconfig.Process("cloudyn", &cfg)
	if err != nil {
		log.Fatalf("Error parsing environment variables: %s", err)
	}

	// If PORT variable is supplied by Heroku, override the CDDNS_ADDR var.
	if envPort, exists := os.LookupEnv("PORT"); exists {
		cfg.Addr = fmt.Sprintf(":%s", envPort)
	}

	// Logging options
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(os.Stdout)

	// Set log level via environment variable, defaulting to info
	switch cfg.LogLevel {
	case "info":
		log.SetLevel(log.InfoLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	default:
		log.SetLevel(log.InfoLevel)
		log.Info("Unknown log level provided, defaulting to INFO")
	}
}

func main() {
	// Handle the update route
	http.HandleFunc("/update", updateHandler)
	http.HandleFunc("/nic/update", updateHandler)

	// Handle the checkip route
	http.HandleFunc("/checkip", checkIPHandler)

	// Handle the index route
	http.HandleFunc("/", indexHandler)

	log.Infof("Starting ClouDyn on %s", cfg.Addr)
	if cfg.DisableAccessLogs {
		// Start server without access logs
		log.Fatal(http.ListenAndServe(cfg.Addr, nil))
	} else {
		// Start server with access logs
		log.Fatal(http.ListenAndServe(cfg.Addr, logRequest(http.DefaultServeMux)))
	}
}

// indexHandler Serves a static web page with information about ClouDyn
func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `
	<html>
		<head>
			<title>ClouDyn</title>
		</head>
		<body>
			<h1>ClouDyn</h1>
			<h2>Available Routes</h2>
			<p><a href="update">/update</a> - Perform a DNS update</p>
			<p><a href="nic/update">/nic/update</a> - Perform a DNS update (dyndns2)</p>
			<p><a href="checkip">/checkip</a> - Get the current host's public IP</p>
			<h2>Documentation</h2>
			<p><a href="https://github.com/adammillerio/cloudyn">GitHub</a></p>
			<h2>Info</h2>
			<p>Created by <a href="https://adammiller.io">Adam Miller</a></p>
		</body>
	</html>
	`)
}

// checkIPHandler Determines the requesting host's public IP address from
// available data and returns it.
func checkIPHandler(w http.ResponseWriter, r *http.Request) {
	ip, err := requestIP(r)

	// If the IP was found, print it. Otherwise, print an error.
	if err == nil {
		fmt.Fprintf(w, "<html><head><title>Current IP Check</title></head><body>Current IP Address: %s</body></html>", ip)
	} else {
		w.WriteHeader(http.StatusBadRequest)
		log.Debug(err)
		fmt.Fprintf(w, "<html><head><title>Current IP Check</title></head><body>Unable to determine IP</body></html>")
	}
}

// updateHandler handles the update HTTP request by taking the provided
// parameters and attempting to perform a dynamic DNS update.
// It returns nothing, but outputs a standard dyn return code of the status.
func updateHandler(w http.ResponseWriter, r *http.Request) {
	cLog := log.WithFields(log.Fields{
		"remote": r.RemoteAddr,
		"method": r.Method,
		"url":    r.URL.String(),
	})

	// Parse and validate the hostname.
	// Though not documented, notfqdn is used when the hostname is invalid in
	// addition to not existing in the user's account.
	hostname, valid := parseHostname(r.URL.Query().Get("hostname"))
	if !valid {
		cLog.Debug("Missing or invalid hostname")
		fmt.Fprint(w, "notfqdn")
		return
	}

	// First attempt to retrieve authentication information via basic auth.
	// In the case of CF, this is an email and an API key, not a username and
	// password.
	email, key, valid := r.BasicAuth()
	if !valid {
		// If not valid, attempt to parse the email and key from fallback URL
		// parameters.
		// badauth and HTTP 401 is provided if these values cannot be retrieved.
		emailURL := r.URL.Query().Get("email")
		if len(emailURL) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			cLog.Debug("Missing email or API key")
			fmt.Fprint(w, "badauth")
			return
		} else {
			email = emailURL
		}

		keyURL := r.URL.Query().Get("key")
		if len(keyURL) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			cLog.Debug("Missing username or API key")
			fmt.Fprint(w, "badauth")
			return
		} else {
			key = keyURL
		}
	}

	// Parse and validate the new IP address to attempt to set.
	// Though not documented, badip is provided when an IP fails validation.
	myip, valid := parseIP(r.URL.Query().Get("myip"))
	if !valid {
		// If myip is not provided, attempt to determine it from request data.
		var err error

		myip, err = requestIP(r)
		if err != nil {
			cLog.Debug("Missing or invalid myip")
			fmt.Fprint(w, "badip")
			return
		}
	}

	// Attempt the DNS update and print the code returned.
	code := update(email, key, hostname, myip)
	fmt.Fprint(w, code)
}

// update attempts to perform a CloudFlare DNS update using provided values.
// It returns a standard dyn return code based on the status from CloudFlare.
func update(email string, key string, hostname string, myip string) string {
	cLog := log.WithFields(log.Fields{
		"email":    email,
		"hostname": hostname,
		"myip":     myip,
	})

	// Create a new CloudFlare API client using the provided credentials.
	// In the event of failure, provide dnserr.
	// NOTE: This is a best guess attempt at what dyn code matches this state.
	cf, err := cloudflare.New(key, email)
	if err != nil {
		cLog.Debug(err)
		return "dnserr"
	}

	// Retrieve the record and zone values based on the provided hostname.
	// If not failed, return the notfqdn code.
	record, zone, err := recordByHostname(cf, hostname)
	if err != nil {
		cLog.Debug(err)
		return "notfqdn"
	}

	// If the new IP is the same as the one in CloudFlare, return the nochg code.
	if record.Content == myip {
		return fmt.Sprintf("nochg %s", myip)
	}

	// Update the record content with the new IP.
	record.Content = myip

	// Attempt to update the DNS record in CloudFlare.
	// In the event of failure, provide dnserr.
	// NOTE: This is a best guess attempt at what dyn code matches this state.
	err = cf.UpdateDNSRecord(zone.ID, record.ID, record)
	if err != nil {
		cLog.Debug(err)
		return "dnserr"
	}

	// Return the good code if the update is successful.
	return fmt.Sprintf("good %s", myip)
}

// recordByHostname Searches all DNS records in a CloudFlare account to find
// the record matching the provided hostname.
// It returns the CloudFlare DNS record and Zone structs or any errors
// encountered during the search.
func recordByHostname(cf *cloudflare.API, hostname string) (cloudflare.DNSRecord, cloudflare.Zone, error) {
	// Create the Zone struct.
	var hostZone cloudflare.Zone

	// Initialize the DNSRecord struct with the provided hostname.
	hostRecord := cloudflare.DNSRecord{
		Name: hostname,
	}

	// Retrieve all zones in the account.
	zones, err := cf.ListZones()
	if err != nil {
		return hostRecord, hostZone, err
	}

	// Go through each zone in the account.
	for _, zone := range zones {
		// Retrieve all the DNS records for the zone.
		records, err := cf.DNSRecords(zone.ID, hostRecord)
		if err != nil {
			return hostRecord, hostZone, err
		}

		// Search all records in the zone.
		for _, record := range records {
			// If an A or AAAA record matches the provided hostname, return it.
			if (record.Type == "A" || record.Type == "AAAA") && record.Name == hostRecord.Name {
				hostZone = zone
				hostRecord = record
				return hostRecord, hostZone, nil
			}
		}
	}

	// Otherwise, provide an error indicating the hostname cannot be found.
	return hostRecord, hostZone, errors.New("Zone ID with matching hostname not found")
}

// requestIP Determines the requesting host's public IP address from
// available data and returns it.
// It returns the IP as a string, and any errors encountered.
func requestIP(r *http.Request) (string, error) {
	var ip string

	// First get IP from the request's address
	if requestIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = requestIP
	}

	// If X-Forwarded-For is present, then override.
	// Typically, this is sent by reverse proxies.
	if xForwardedFor, valid := parseIP(r.Header.Get("X-Forwarded-For")); valid {
		ip = xForwardedFor
	}

	// If Client-IP is present, then override.
	// This additional header is in the Dyn CheckIP specifications.
	if clientIP, valid := parseIP(r.Header.Get("Client-IP")); valid {
		ip = clientIP
	}

	// If CF-Connecting-IP is present then override.
	// If sending traffic through CloudFlare, this header will contain the
	// requesting IP. X-Forwarded-For is also sent, but can be provided in a way
	// that will fail IP parsing.
	if cfConnectingIP, valid := parseIP(r.Header.Get("CF-Connecting-IP")); valid {
		ip = cfConnectingIP
	}

	if len(ip) != 0 {
		return ip, nil
	} else {
		return ip, errors.New("Unable to determine IP")
	}
}

// parseIP Parses and validates a provided string as an IP address.
// It returns the string as well as a boolean indicating validity.
func parseIP(ip string) (string, bool) {
	// Use the net parse tool to parse the IP address and return validity.
	if parsedIP := net.ParseIP(ip); parsedIP == nil {
		return ip, false
	} else {
		return ip, true
	}
}

// parseHostname Parses and validates a provided string as a DNS hostname.
// It returns the string as well as a boolean indicating validity.
func parseHostname(hostname string) (string, bool) {
	// Return the hostname and the result of the DNS hostname regex.
	return hostname, hostnameRegex.MatchString(hostname)
}

// logRequest implements a basic default HTTP handler for the purpose of
// providing access logs.
// It returns a handler function that logs the request prior to serving it.
func logRequest(handler http.Handler) http.Handler {
	// Return the handler.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log the request and serve it.
		log.WithFields(log.Fields{
			"remote":       r.RemoteAddr,
			"ip-client":    r.Header.Get("Client-IP"),
			"ip-forwarded": r.Header.Get("X-Forwarded-For"),
			"ip-cf":        r.Header.Get("CF-Connecting-IP"),
			"method":       r.Method,
			"url":          r.URL.String(),
		}).Info()
		handler.ServeHTTP(w, r)
	})
}
