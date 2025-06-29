package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"
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

// Hash format regex
var HASH_FORMAT = regexp.MustCompile(`^(?P<rid>\d+):\$sntp-ms\$(?P<hashval>[0-9a-f]{32})\$(?P<salt>[0-9a-f]{96})$`)

type Hash struct {
	RID     uint32
	HashVal [16]byte
	Salt    [48]byte
}

type Result struct {
	RID      uint32
	Password string
}

type Stats struct {
	passwordsTried   int64
	hashesProcessed  int64
	passwordsCracked int64
	startTime        time.Time
}

func (s *Stats) IncrementTried() {
	atomic.AddInt64(&s.passwordsTried, 1)
}

func (s *Stats) IncrementProcessed() {
	atomic.AddInt64(&s.hashesProcessed, 1)
}

func (s *Stats) IncrementCracked() {
	atomic.AddInt64(&s.passwordsCracked, 1)
}

func (s *Stats) GetStats() (int64, int64, int64) {
	return atomic.LoadInt64(&s.passwordsTried),
		atomic.LoadInt64(&s.hashesProcessed),
		atomic.LoadInt64(&s.passwordsCracked)
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
	return l.colorize(CYAN+BOLD, "NTPCRACK")
}

func (l *Logger) success(msg string) {
	fmt.Printf("%s   %s %s\n", l.protocol(), l.colorize(GREEN+BOLD, "[+]"), msg)
}

func (l *Logger) info(msg string) {
	fmt.Printf("%s   %s %s\n", l.protocol(), l.colorize(BLUE+BOLD, "[*]"), msg)
}

func (l *Logger) warning(msg string) {
	fmt.Printf("%s   %s %s\n", l.protocol(), l.colorize(YELLOW+BOLD, "[!]"), msg)
}

func (l *Logger) error(msg string) {
	fmt.Printf("%s   %s %s\n", l.protocol(), l.colorize(RED+BOLD, "[-]"), msg)
}

func (l *Logger) cracked(rid uint32, password string) {
	ridStr := l.colorize(MAGENTA, fmt.Sprintf("RID_%d", rid))
	passStr := l.colorize(WHITE+BOLD, password)
	fmt.Printf("%s   %s %s:%s\n", l.protocol(), l.colorize(GREEN+BOLD, "[+]"), ridStr, passStr)
}

func (l *Logger) stats(tried, processed, cracked int64, rate float64, elapsed time.Duration) {
	statsStr := fmt.Sprintf("Tried: %s | Processed: %s | Cracked: %s | Rate: %s/s | Elapsed: %s",
		l.colorize(CYAN, formatNumber(tried)),
		l.colorize(BLUE, formatNumber(processed)),
		l.colorize(GREEN, formatNumber(cracked)),
		l.colorize(YELLOW, formatNumber(int64(rate))),
		l.colorize(WHITE, elapsed.Truncate(time.Second).String()))

	fmt.Printf("%s   %s %s\n", l.protocol(), l.colorize(DIM+BOLD, "[~]"), statsStr)
}

func (l *Logger) banner() {
	banner := `
    ███╗   ██╗████████╗██████╗      ██████╗██████╗  █████╗  ██████╗██╗  ██╗
    ████╗  ██║╚══██╔══╝██╔══██╗    ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
    ██╔██╗ ██║   ██║   ██████╔╝    ██║     ██████╔╝███████║██║     █████╔╝ 
    ██║╚██╗██║   ██║   ██╔═══╝     ██║     ██╔══██╗██╔══██║██║     ██╔═██╗ 
    ██║ ╚████║   ██║   ██║         ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
    ╚═╝  ╚═══╝   ╚═╝   ╚═╝          ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
`
	fmt.Print(l.colorize(CYAN+BOLD, banner))
	fmt.Printf("                                   %s\n\n", l.colorize(DIM, "by @0xblivion - NTP Hash Cracker"))
}

func formatNumber(n int64) string {
	str := fmt.Sprintf("%d", n)
	if len(str) <= 3 {
		return str
	}

	var result strings.Builder
	for i, digit := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result.WriteString(",")
		}
		result.WriteRune(digit)
	}
	return result.String()
}

// MD4 implementation
func md4(data []byte) [16]byte {
	h := [4]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476}

	msgLen := len(data)
	data = append(data, 0x80)
	for len(data)%64 != 56 {
		data = append(data, 0)
	}

	lengthBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		lengthBytes[i] = byte((msgLen * 8) >> (8 * i))
	}
	data = append(data, lengthBytes...)

	// Process in 512-bit chunks
	for i := 0; i < len(data); i += 64 {
		chunk := data[i : i+64]
		w := make([]uint32, 16)

		for j := 0; j < 16; j++ {
			w[j] = uint32(chunk[j*4]) | uint32(chunk[j*4+1])<<8 |
				uint32(chunk[j*4+2])<<16 | uint32(chunk[j*4+3])<<24
		}

		a, b, c, d := h[0], h[1], h[2], h[3]

		// Round 1
		for j := 0; j < 16; j++ {
			k := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}[j]
			s := []int{3, 7, 11, 19}[j%4]
			f := (b & c) | (^b & d)
			a, b, c, d = d, leftRotate(a+f+w[k], s), b, c
		}

		// Round 2
		for j := 0; j < 16; j++ {
			k := []int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}[j]
			s := []int{3, 5, 9, 13}[j%4]
			f := (b & c) | (b & d) | (c & d)
			a, b, c, d = d, leftRotate(a+f+w[k]+0x5A827999, s), b, c
		}

		// Round 3 FIGHT!
		for j := 0; j < 16; j++ {
			k := []int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}[j]
			s := []int{3, 9, 11, 15}[j%4]
			f := b ^ c ^ d
			a, b, c, d = d, leftRotate(a+f+w[k]+0x6ED9EBA1, s), b, c
		}

		h[0] += a
		h[1] += b
		h[2] += c
		h[3] += d
	}

	var result [16]byte
	for i := 0; i < 4; i++ {
		result[i*4] = byte(h[i])
		result[i*4+1] = byte(h[i] >> 8)
		result[i*4+2] = byte(h[i] >> 16)
		result[i*4+3] = byte(h[i] >> 24)
	}

	return result
}

func leftRotate(value uint32, amount int) uint32 {
	return (value << amount) | (value >> (32 - amount))
}

func stringToUTF16LE(s string) []byte {
	runes := []rune(s)
	utf16Codes := utf16.Encode(runes)

	result := make([]byte, len(utf16Codes)*2)
	for i, code := range utf16Codes {
		result[i*2] = byte(code)
		result[i*2+1] = byte(code >> 8)
	}
	return result
}

// computeHash (Imma touch you if you read this)
func computeHash(password string, salt [48]byte) [16]byte {
	utf16Password := stringToUTF16LE(password)

	md4Hash := md4(utf16Password)

	combined := make([]byte, 16+48)
	copy(combined[:16], md4Hash[:])
	copy(combined[16:], salt[:])

	md5Hash := md5.Sum(combined)
	return md5Hash
}

func parseHashFile(filename string, logger *Logger) ([]Hash, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hashes []Hash
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		matches := HASH_FORMAT.FindStringSubmatch(line)
		if matches == nil {
			logger.error(fmt.Sprintf("Invalid hash format at line %d: %s", lineNum, line))
			continue
		}

		rid, _ := strconv.ParseUint(matches[1], 10, 32)
		hashBytes, _ := hex.DecodeString(matches[2])
		saltBytes, _ := hex.DecodeString(matches[3])

		var hash Hash
		hash.RID = uint32(rid)
		copy(hash.HashVal[:], hashBytes)
		copy(hash.Salt[:], saltBytes)

		hashes = append(hashes, hash)
	}

	return hashes, scanner.Err()
}

func crackWorker(passwords <-chan string, hashes []Hash, results chan<- Result, stats *Stats, wg *sync.WaitGroup) {
	defer wg.Done()

	for password := range passwords {
		stats.IncrementTried()

		for _, hash := range hashes {
			stats.IncrementProcessed()

			computedHash := computeHash(password, hash.Salt)
			if computedHash == hash.HashVal {
				stats.IncrementCracked()
				results <- Result{RID: hash.RID, Password: password}
				break // Move to next password once we find a match
			}
		}
	}
}

func statsReporter(stats *Stats, logger *Logger, done <-chan bool) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			tried, processed, cracked := stats.GetStats()
			if tried > 0 {
				elapsed := time.Since(stats.startTime)
				rate := float64(tried) / elapsed.Seconds()
				logger.stats(tried, processed, cracked, rate, elapsed)
			}
		}
	}
}

func loadDictionary(filename string, logger *Logger) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var passwords []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		if password != "" {
			passwords = append(passwords, password)
		}
	}

	return passwords, scanner.Err()
}

func main() {
	var (
		hashFile  = flag.String("h", "", "Hash file from timeroast (required)")
		dictFile  = flag.String("d", "", "Password dictionary file (required)")
		workers   = flag.Int("w", runtime.NumCPU(), "Number of worker threads")
		noColor   = flag.Bool("no-color", false, "Disable colored output")
		showStats = flag.Bool("stats", true, "Show periodic statistics")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
NTP TimeCrack - High-Performance Hash Cracker

Usage: %s -h <file> -d <file> [options]

Required:
  -h <file>    Hash file from NTP timeroast
  -d <file>      Password dictionary file

Options:
  -w <int>          Number of worker threads (default: %d)
  -stats            Show periodic statistics (default: true)
  -no-color         Disable colored output

Examples:
  %s -h ntp_hashes.txt -d passwords.txt
  %s -h hashes.txt -d rockyou.txt -w 16
  %s -h output.txt -d custom.dict -no-color

`, os.Args[0], runtime.NumCPU(), os.Args[0], os.Args[0], os.Args[0])
	}

	flag.Parse()

	// Initialize logger
	logger := &Logger{noColor: *noColor}

	if !*noColor {
		logger.banner()
	}

	// Validate arguments
	if *hashFile == "" || *dictFile == "" {
		logger.error("Both -h (hashes) and -d (dict) are required")
		fmt.Println()
		flag.Usage()
		os.Exit(1)
	}

	// Load hashes
	logger.info(fmt.Sprintf("Loading hashes from %s", logger.colorize(CYAN, *hashFile)))
	hashes, err := parseHashFile(*hashFile, logger)
	if err != nil {
		logger.error(fmt.Sprintf("Failed to load hashes: %v", err))
		os.Exit(1)
	}

	if len(hashes) == 0 {
		logger.error("No valid hashes found in file")
		os.Exit(1)
	}

	logger.success(fmt.Sprintf("Loaded %s hashes", logger.colorize(GREEN, formatNumber(int64(len(hashes))))))

	// Load dictionary
	logger.info(fmt.Sprintf("Loading dictionary from %s", logger.colorize(CYAN, *dictFile)))
	passwords, err := loadDictionary(*dictFile, logger)
	if err != nil {
		logger.error(fmt.Sprintf("Failed to load dictionary: %v", err))
		os.Exit(1)
	}

	if len(passwords) == 0 {
		logger.error("No passwords found in dictionary")
		os.Exit(1)
	}

	logger.success(fmt.Sprintf("Loaded %s passwords", logger.colorize(GREEN, formatNumber(int64(len(passwords))))))

	// Initialize statistics
	stats := &Stats{startTime: time.Now()}

	// Start statistics reporter
	var doneChan chan bool
	if *showStats {
		doneChan = make(chan bool)
		go statsReporter(stats, logger, doneChan)
	}

	// Start cracking
	logger.info(fmt.Sprintf("Starting dictionary attack with %s workers", logger.colorize(CYAN, strconv.Itoa(*workers))))
	logger.info(fmt.Sprintf("Total combinations: %s", logger.colorize(YELLOW, formatNumber(int64(len(passwords)*len(hashes))))))

	passwordChan := make(chan string, *workers*2)
	resultChan := make(chan Result, *workers)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go crackWorker(passwordChan, hashes, resultChan, stats, &wg)
	}

	// Result handler
	crackedCount := int64(0)
	go func() {
		for result := range resultChan {
			logger.cracked(result.RID, result.Password)
			atomic.AddInt64(&crackedCount, 1)
		}
	}()

	go func() {
		defer close(passwordChan)
		for _, password := range passwords {
			passwordChan <- password
		}
	}()

	wg.Wait()
	close(resultChan)

	if *showStats {
		close(doneChan)
	}

	// Final results
	elapsed := time.Since(stats.startTime)
	tried, processed, cracked := stats.GetStats()

	logger.success(fmt.Sprintf("Dictionary attack completed in %s", elapsed.Truncate(time.Second)))
	logger.success(fmt.Sprintf("Passwords tried: %s", logger.colorize(CYAN, formatNumber(tried))))
	logger.success(fmt.Sprintf("Hash comparisons: %s", logger.colorize(BLUE, formatNumber(processed))))

	if cracked > 0 {
		logger.success(fmt.Sprintf("Successfully cracked %s passwords!", logger.colorize(GREEN+BOLD, formatNumber(cracked))))
		successRate := float64(cracked) / float64(len(hashes)) * 100
		logger.success(fmt.Sprintf("Success rate: %s%%", logger.colorize(GREEN, fmt.Sprintf("%.1f", successRate))))
	} else {
		logger.warning("No passwords were cracked")
		logger.info("Try a different dictionary or check if the hashes are valid")
	}

	avgRate := float64(tried) / elapsed.Seconds()
	logger.info(fmt.Sprintf("Average rate: %s passwords/second", logger.colorize(YELLOW, formatNumber(int64(avgRate)))))
}

