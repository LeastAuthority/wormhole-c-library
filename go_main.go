package main

import "C"

import (
	"context"
	"os"
	"fmt"
	"strings"
	"bufio"
	"path/filepath"
	"log"
	"io"
	"io/ioutil"

	"github.com/psanford/wormhole-william/wormhole"
	"github.com/klauspost/compress/zip"
)

var (
	relayURL        string
	verify          bool
	codeLen         int
	codeFlag        string
)

func errf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg, args...)
	if !strings.HasSuffix("\n", msg) {
		fmt.Fprint(os.Stderr, "\n")
	}
}

func bail(msg string, args ...interface{}) {
	errf(msg, args...)
	os.Exit(1)
}

func formatBytes(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "kMGTPE"[exp])
}

func newClient() wormhole.Client {
	c := wormhole.Client{
		RendezvousURL:             relayURL,
		PassPhraseComponentLength: codeLen,
	}

	if verify {
		c.VerifierOk = func(code string) bool {
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Verifier %s. ok? (yes/no): ", code)

			yn, _ := reader.ReadString('\n')
			yn = strings.TrimSpace(yn)

			return yn == "yes"
		}
	}

	return c
}

func printInstructions(code string) {
	mwCmd := "wormhole receive"
	wwCmd := "wormhole-william recv"

	if verify {
		mwCmd = mwCmd + " --verify"
		wwCmd = wwCmd + " --verify"
	}

	fmt.Printf("On the other computer, please run: %s (or %s)\n", mwCmd, wwCmd)
	fmt.Printf("Wormhole code is: %s\n", code)
}

//export sendFile
func sendFile(filename string) {
	fmt.Printf("filename is %s\n", filename)
	f, err := os.Open(filename)
	if err != nil {
		bail("Failed to open %s: %s", filename, err)
	}

	c := newClient()

	ctx := context.Background()

	args := []wormhole.SendOption{
		wormhole.WithCode(codeFlag),
	}

	code, status, err := c.SendFile(ctx, filepath.Base(filename), f, args...)
	if err != nil {
		bail("Error sending message: %s", err)
	}

	printInstructions(code)

	s := <-status

	if s.OK {
		fmt.Println("file sent")
	} else {
		bail("Send error: %s", s.Error)
	}
}

//export recvAction
func recvAction() {
	var (
		c    = newClient()
		ctx  = context.Background()
	)
	var code string;

	if code == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter receive wormhole code: ")

		line, err := reader.ReadString('\n')
		if err != nil {
			errf("Error reading from stdin: %s\n", err)
		}
		code = strings.TrimSpace(line)
	}

	if verify {
		c.VerifierOk = func(code string) bool {
			fmt.Printf("Verifier %s.\n", code)
			return true
		}
	}

	msg, err := c.Receive(ctx, code)
	if err != nil {
		log.Fatal(err)
	}

	switch msg.Type {
	case wormhole.TransferText:
		body, err := ioutil.ReadAll(msg)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(string(body))
	case wormhole.TransferFile:
		var acceptFile bool
		if _, err := os.Stat(msg.Name); err == nil {
			msg.Reject()
			errf("Error refusing to overwrite existing '%s'", msg.Name)
		} else if !os.IsNotExist(err) {
			msg.Reject()
			errf("Error stat'ing existing '%s'\n", msg.Name)
		} else {
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Receiving file (%s) into: %s\n", formatBytes(msg.TransferBytes64), msg.Name)
			fmt.Print("ok? (y/N):")

			line, err := reader.ReadString('\n')
			if err != nil {
				errf("Error reading from stdin: %s\n", err)
			}
			line = strings.TrimSpace(line)
			if line == "y" {
				acceptFile = true
			}

			if !acceptFile {
				msg.Reject()
				bail("transfer rejected")
			} else {
				wd, err := os.Getwd()
				if err != nil {
					bail("Failed to get working directory: %s", err)
				}
				f, err := ioutil.TempFile(wd, fmt.Sprintf("%s.tmp", msg.Name))
				if err != nil {
					bail("Failed to create tempfile: %s", err)
				}

				_, err = io.Copy(f, msg)
				if err != nil {
					os.Remove(f.Name())
					bail("Receive file error: %s", err)
				}

				tmpName := f.Name()
				f.Close()

				err = os.Rename(tmpName, msg.Name)
				if err != nil {
					bail("Rename %s to %s failed: %s", tmpName, msg.Name, err)
				}
			}
		}
	case wormhole.TransferDirectory:
		var acceptDir bool

		wd, err := os.Getwd()
		if err != nil {
			bail("Failed to get working directory: %s", err)
		}

		dirName := msg.Name
		dirName, err = filepath.Abs(dirName)
		if err != nil {
			bail("Failed to get abs directory: %s", err)
		}

		if filepath.Dir(dirName) != wd {
			bail("Bad Directory name %s", msg.Name)
		}

		if _, err := os.Stat(dirName); err == nil {
			errf("Error refusing to overwrite existing '%s'", msg.Name)
		} else if !os.IsNotExist(err) {
			errf("Error stat'ing existing '%s'\n", msg.Name)
		} else {
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Receiving directory (%s) into: %s\n", formatBytes(msg.TransferBytes64), msg.Name)
			fmt.Printf("%d files, %s (uncompressed)\n", msg.FileCount, formatBytes(msg.UncompressedBytes64))
			fmt.Print("ok? (y/N):")

			line, err := reader.ReadString('\n')
			if err != nil {
				errf("Error reading from stdin: %s\n", err)
			}
			line = strings.TrimSpace(line)
			if line == "y" {
				acceptDir = true
			}

			if !acceptDir {
				msg.Reject()
				bail("transfer rejected")
			} else {
				err = os.Mkdir(msg.Name, 0777)
				if err != nil {
					bail("Mkdir error for %s: %s\n", msg.Name, err)
				}

				tmpFile, err := ioutil.TempFile(wd, fmt.Sprintf("%s.zip.tmp", msg.Name))
				if err != nil {
					bail("Failed to create tempfile: %s", err)
				}

				defer tmpFile.Close()
				defer os.Remove(tmpFile.Name())

				n, err := io.Copy(tmpFile, msg)
				if err != nil {
					os.Remove(tmpFile.Name())
					bail("Receive file error: %s", err)
				}

				tmpFile.Seek(0, io.SeekStart)
				zr, err := zip.NewReader(tmpFile, int64(n))
				if err != nil {
					bail("Read zip error: %s", err)
				}

				for _, zf := range zr.File {
					p, err := filepath.Abs(filepath.Join(dirName, zf.Name))
					if err != nil {
						bail("Failes to calculate file path ABS: %s", err)
					}

					if !strings.HasPrefix(p, dirName) {
						bail("Dangerous filename detected: %s", zf.Name)
					}

					rc, err := zf.Open()
					if err != nil {
						bail("Failed to open file in zip: %s %s", zf.Name, err)
					}

					dir := filepath.Dir(p)
					err = os.MkdirAll(dir, 0777)
					if err != nil {
						bail("Failed to mkdirall %s: %s", dir, err)
					}

					f, err := os.Create(p)
					if err != nil {
						bail("Failed to open %s: %s", p, err)
					}

					_, err = io.Copy(f, rc)
					if err != nil {
						bail("Failed to write to %s: %s", p, err)
					}

					err = f.Close()
					if err != nil {
						bail("Error closing %s: %s", p, err)
					}

					rc.Close()
				}
			}
		}
	}
}


func main() {
	// We need the main function to make possible
	// CGO compiler to compile the package as C shared library
}
