package config

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/massnetorg/mass-core/logging"
	"github.com/massnetorg/mass-core/wire"
)

// appDataDir returns an operating system specific directory to be used for
// storing application data for an application.  See AppDataDir for more
// details.  This unexported version takes an operating system argument
// primarily to enable the testing package to properly test the function by
// forcing an operating system that is not the currently one.
func appDataDir(goos, appName string, roaming bool) string {
	if appName == "" || appName == "." {
		return "."
	}

	// The caller really shouldn't prepend the appName with a period, but
	// if they do, handle it gracefully by stripping it.
	appName = strings.TrimPrefix(appName, ".")
	appNameUpper := string(unicode.ToUpper(rune(appName[0]))) + appName[1:]
	appNameLower := string(unicode.ToLower(rune(appName[0]))) + appName[1:]

	// Get the OS specific home directory via the Go standard lib.
	var homeDir string
	usr, err := user.Current()
	if err == nil {
		homeDir = usr.HomeDir
	}

	// Fall back to standard HOME environment variable that works
	// for most POSIX OSes if the directory from the Go standard
	// lib failed.
	if err != nil || homeDir == "" {
		homeDir = os.Getenv("HOME")
	}

	switch goos {
	// Attempt to use the LOCALAPPDATA or APPDATA environment variable on
	// Windows.
	case "windows":
		// Windows XP and before didn't have a LOCALAPPDATA, so fallback
		// to regular APPDATA when LOCALAPPDATA is not set.
		appData := os.Getenv("LOCALAPPDATA")
		if roaming || appData == "" {
			appData = os.Getenv("APPDATA")
		}

		if appData != "" {
			return filepath.Join(appData, appNameUpper)
		}

	case "darwin":
		if homeDir != "" {
			return filepath.Join(homeDir, "Library",
				"Application Support", appNameUpper)
		}

	case "plan9":
		if homeDir != "" {
			return filepath.Join(homeDir, appNameLower)
		}

	default:
		if homeDir != "" {
			return filepath.Join(homeDir, "."+appNameLower)
		}
	}

	// Fall back to the current directory if all else fails.
	return "."
}

// AppDataDir returns an operating system specific directory to be used for
// storing application data for an application.
//
// The appName parameter is the name of the application the data directory is
// being requested for.  This function will prepend a period to the appName for
// POSIX style operating systems since that is standard practice.  An empty
// appName or one with a single dot is treated as requesting the current
// directory so only "." will be returned.  Further, the first character
// of appName will be made lowercase for POSIX style operating systems and
// uppercase for Mac and Windows since that is standard practice.
//
// The roaming parameter only applies to Windows where it specifies the roaming
// application data profile (%APPDATA%) should be used instead of the local one
// (%LOCALAPPDATA%) that is used by default.
//
// Example results:
//  dir := AppDataDir("myapp", false)
//   POSIX (Linux/BSD): ~/.myapp
//   Mac OS: $HOME/Library/Application Support/Myapp
//   Windows: %LOCALAPPDATA%\Myapp
//   Plan 9: $home/myapp
func AppDataDir(appName string, roaming bool) string {
	return appDataDir(runtime.GOOS, appName, roaming)
}

// removeDuplicateAddresses returns a new slice with all duplicate entries in
// addrs removed.
func removeDuplicateAddresses(addrs []string) []string {
	result := make([]string, 0, len(addrs))
	seen := map[string]struct{}{}
	for _, val := range addrs {
		if _, ok := seen[val]; !ok {
			result = append(result, val)
			seen[val] = struct{}{}
		}
	}
	return result
}

// NormalizeAddress returns addr with the passed default port appended if
// there is not already a port specified.
func NormalizeAddress(addr, defaultPort string) string {
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.JoinHostPort(addr, defaultPort)
	}
	return addr
}

// normalizeAddresses returns a new slice with all the passed peer addresses
// normalized with the given default port, and all duplicates removed.
func NormalizeAddresses(addrs []string, defaultPort string) []string {
	for i, addr := range addrs {
		addrs[i] = NormalizeAddress(addr, defaultPort)
	}

	return removeDuplicateAddresses(addrs)
}

// NormalizeSeed accepts four types of params:
//   (1) [IPV4/IPV6]
//   (2) [IPV4/IPV6]:[PORT]
//   (3) [DOMAIN]
//   (4) [DOMAIN]:[PORT]
// It returns error if receive other types of params.
//
// Run step:
//   (1) check if Seed has port, then split Host and Port;
//   (2) check validity of Port, then assign default value to empty Port;
//   (3) randomly select an IP if Host is a domain;
//   (4) join host and port.
func NormalizeSeed(seed, defaultPort string) (string, error) {
	// Step 1: Split Host and Port
	if !strings.Contains(seed, ":") {
		seed += ":"
	} else if i := strings.LastIndex(seed, "]"); i != -1 {
		seed = strings.Join([]string{seed[:i+1], ":", seed[i+1:]}, "")
	}
	host, port, err := net.SplitHostPort(seed)
	if err != nil {
		return "", err
	}

	// Step 2: Ensure Port is valid
	if port == "" {
		port = defaultPort
	}
	portN, err := strconv.Atoi(port)
	if err != nil {
		return "", err
	}
	if portN < 0 || portN > 65535 {
		return "", errors.New(fmt.Sprintf("invalid port %d", portN))
	}

	// Step 3: Figure out IP/Domain
	if ip := net.ParseIP(host); ip == nil {
		res, err := net.LookupIP(host)
		if err != nil {
			return "", err
		}
		randSource := rand.NewSource(time.Now().UnixNano())
		idx := int(randSource.Int63()) % len(res)
		host = res[idx].String()
	}

	// Step 4: Make result
	return net.JoinHostPort(host, port), nil
}

// Normalize Seeds joined with ','.
func NormalizeSeeds(inputs, defaultPort string) string {
	// remove blank
	inputs = strings.Replace(inputs, " ", "", -1)
	if inputs == "" {
		return ""
	}
	// normalize each seed
	seeds := make([]string, 0)
	for _, seed := range strings.Split(inputs, ",") {
		hostport, err := NormalizeSeed(seed, defaultPort)
		if err != nil {
			logging.CPrint(logging.WARN, "invalid seed", logging.LogFormat{"seed": seed, "err": err})
			continue
		}
		seeds = append(seeds, hostport)
	}
	// remove duplicate seed
	seeds = removeDuplicateAddresses(seeds)
	// make result
	return strings.Join(seeds, ",")
}

// checkpointSorter implements sort.Interface to allow a slice of checkpoints to
// be sorted.
type checkpointSorter []Checkpoint

// Len returns the number of checkpoints in the slice.  It is part of the
// sort.Interface implementation.
func (s checkpointSorter) Len() int {
	return len(s)
}

// Swap swaps the checkpoints at the passed indices.  It is part of the
// sort.Interface implementation.
func (s checkpointSorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less returns whether the checkpoint with index i should sort before the
// checkpoint with index j.  It is part of the sort.Interface implementation.
func (s checkpointSorter) Less(i, j int) bool {
	return s[i].Height < s[j].Height
}

// MergeCheckpoints returns two slices of checkpoints merged into one slice
// such that the checkpoints are sorted by height.  In the case the additional
// checkpoints contain a checkpoint with the same height as a checkpoint in the
// default checkpoints, the additional checkpoint will take precedence and
// overwrite the default one.
func MergeCheckpoints(defaultCheckpoints, additional []Checkpoint) []Checkpoint {
	// Create a map of the additional checkpoints to remove duplicates while
	// leaving the most recently-specified checkpoint.
	extra := make(map[uint64]Checkpoint)
	for _, checkpoint := range additional {
		extra[checkpoint.Height] = checkpoint
	}

	// Add all default checkpoints that do not have an override in the
	// additional checkpoints.
	numDefault := len(defaultCheckpoints)
	checkpoints := make([]Checkpoint, 0, numDefault+len(extra))
	for _, checkpoint := range defaultCheckpoints {
		if _, exists := extra[checkpoint.Height]; !exists {
			checkpoints = append(checkpoints, checkpoint)
		}
	}

	// Append the additional checkpoints and return the sorted results.
	for _, checkpoint := range extra {
		checkpoints = append(checkpoints, checkpoint)
	}
	sort.Sort(checkpointSorter(checkpoints))
	return checkpoints
}

// newCheckpointFromStr parses checkpoints in the '<height>:<hash>' format.
func newCheckpointFromStr(checkpoint string) (Checkpoint, error) {
	parts := strings.Split(checkpoint, ":")
	if len(parts) != 2 {
		return Checkpoint{}, fmt.Errorf("unable to parse "+
			"checkpoint %q -- use the syntax <height>:<hash>",
			checkpoint)
	}

	height, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("unable to parse "+
			"checkpoint %q due to malformed height", checkpoint)
	}

	if len(parts[1]) == 0 {
		return Checkpoint{}, fmt.Errorf("unable to parse "+
			"checkpoint %q due to missing hash", checkpoint)
	}
	hash, err := wire.NewHashFromStr(parts[1])
	if err != nil {
		return Checkpoint{}, fmt.Errorf("unable to parse "+
			"checkpoint %q due to malformed hash", checkpoint)
	}

	return Checkpoint{
		Height: height,
		Hash:   hash,
	}, nil
}

// parseCheckpoints checks the checkpoint strings for valid syntax
// ('<height>:<hash>') and parses them to Checkpoint instances.
func ParseCheckpoints(checkpointStrings []string) ([]Checkpoint, error) {
	if len(checkpointStrings) == 0 {
		return nil, nil
	}
	checkpoints := make([]Checkpoint, len(checkpointStrings))
	for i, cpString := range checkpointStrings {
		checkpoint, err := newCheckpointFromStr(cpString)
		if err != nil {
			return nil, err
		}
		checkpoints[i] = checkpoint
	}
	return checkpoints, nil
}
