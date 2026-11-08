package keys

import (
	"fmt"
	"os/exec"
	"regexp"
)

func haveSealed() bool { return true }

// machineFingerprint reads the serial number and hardware UUID from IOKit and
// the data volume's UUID from diskutil. system_profiler's hardware report
// prints the first two but not the third. None of them change across macOS updates. A logic board replacement
// changes the first two, and erasing the disk changes the third.
func machineFingerprint() ([]byte, error) {
	hw, err := exec.Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice", "-a").Output()
	if err != nil {
		return nil, fmt.Errorf("reading the hardware identity with ioreg: %w", err)
	}
	vol, err := exec.Command("/usr/sbin/diskutil", "info", "-plist", "/System/Volumes/Data").Output()
	if err != nil {
		return nil, fmt.Errorf("reading the data volume with diskutil: %w", err)
	}
	pairs := []string{}
	for _, f := range []struct {
		plist []byte
		key   string
	}{{hw, "IOPlatformSerialNumber"}, {hw, "IOPlatformUUID"}, {vol, "VolumeUUID"}} {
		v := plistString(f.plist, f.key)
		if v == "" {
			return nil, fmt.Errorf("couldn't read %s for this machine's fingerprint", f.key)
		}
		pairs = append(pairs, f.key, v)
	}
	return encodeFingerprint(pairs...), nil
}

// plistString returns the string value of key in an XML plist, or "".
func plistString(plist []byte, key string) string {
	m := regexp.MustCompile(`<key>` + regexp.QuoteMeta(key) + `</key>\s*<string>([^<]*)</string>`).FindSubmatch(plist)
	if m == nil {
		return ""
	}
	return string(m[1])
}
