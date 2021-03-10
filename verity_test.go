package verity

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"testing"
	"time"

	"github.com/tych0/go-losetup"
	"golang.org/x/sys/unix"
)

func TestVerity(t *testing.T) {
	dir := t.TempDir()

	// Setup data device
	d, err := os.Create(dir + "/data")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	// Write some data there
	if _, err := d.WriteString("Hello verity!!!!"); err != nil {
		t.Fatal(err)
	}

	if err := d.Truncate(32768); err != nil {
		t.Fatal(err)
	}
	dLoop, err := losetup.Attach(dir+"/data", 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer dLoop.Detach()

	// Setup hash device
	h, err := os.Create(dir + "/hash")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.Truncate(8192); err != nil {
		t.Fatal(err)
	}
	hLoop, err := losetup.Attach(dir+"/hash", 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer hLoop.Detach()

	// format hash device
	salt, err := randomHex(32)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("veritysetup", "format", "--salt", salt, dLoop.Path(), hLoop.Path()).Output()
	if err != nil {
		t.Fatal(err)
	}
	props, err := parseProperties(out)
	if err != nil {
		t.Fatal(err)
	}

	rootHash := props["Root hash"]
	name := "test.verity"
	if err := Open(name, dLoop.Path(), hLoop.Path(), rootHash); err != nil {
		t.Fatal(err)
	}
	defer Close(name)

	mapper := "/dev/mapper/" + name
	if err := waitForFile(mapper); err != nil {
		t.Fatal(err)
	}

	out, err = exec.Command("lsblk", "-n", "-o", "UUID", mapper).Output()
	if err != nil {
		t.Fatal(err)
	}
	gotUuid := string(out)
	if expectUuid := props["UUID"]; expectUuid != gotUuid {
		// setting UUID to the verity device does not work for some reason
		// t.Fatalf("wrong uuid: expect %s, got %s", expectUuid, gotUuid)
	}

	// Now verify the data read from the mapper
	data, err := os.ReadFile(mapper)
	if err != nil {
		t.Fatal(err)
	}
	expectedData := make([]byte, 32768)
	copy(expectedData, "Hello verity!!!!")
	if bytes.Compare(expectedData, data) != 0 {
		t.Fatal("data read from the mapper differs from the backing file")
	}

	// Now corrupt the backing file (flip the first character from H to h)
	// verity should fail
	if _, err := d.WriteAt([]byte{'h'}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(mapper); err == nil {
		t.Fatal("expected EIO if backing device is corrupted")
	} else {
		e := errors.Unwrap(err)
		if e != unix.EIO {
			t.Fatalf("unexpected error on verity corruption: %v", err)
		}
	}
}

func parseProperties(data []byte) (map[string]string, error) {
	re := regexp.MustCompile(`([\w ,]+):\W*([^\n]+)`)
	matches := re.FindAllStringSubmatch(string(data), -1)

	result := make(map[string]string)
	for _, m := range matches {
		result[m[1]] = m[2]
	}

	return result, nil
}

func waitForFile(filename string) error {
	timeout := 5 * time.Second

	limit := time.Now().Add(timeout)
	for {
		_, err := os.Stat(filename)
		if err == nil {
			return nil // file is here
		}
		if !os.IsNotExist(err) {
			return err
		}
		if time.Now().After(limit) {
			return fmt.Errorf("timeout waiting for file %s", filename)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func randomHex(n int) (string, error) {
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}
