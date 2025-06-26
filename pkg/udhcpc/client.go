package udhcpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"

	"github.com/devplayer0/docker-net-dhcp/pkg/util"
)

const (
	DefaultHandler = "/usr/lib/net-dhcp/udhcpc-handler"
	VendorID       = "docker-net-dhcp"
)

type DHCPClientOptions struct {
	Hostname  string
	V6        bool
	Once      bool
	Namespace string

	HandlerScript string
}

// DHCPClient represents a udhcpc(6) client
type DHCPClient struct {
	Opts *DHCPClientOptions

	cmd       *exec.Cmd
	eventPipe io.ReadCloser
}

// NewDHCPClientInform creates a new udhcpc client for INFORM requests (configuration only, no IP assignment)
func NewDHCPClientInform(iface string, opts *DHCPClientOptions) (*DHCPClient, error) {
	if opts.HandlerScript == "" {
		opts.HandlerScript = DefaultHandler
	}

	path := "udhcpc"
	if opts.V6 {
		// DHCPv6 doesn't support INFORM in the same way as DHCPv4
		// For IPv6, we'll use information-request which is similar
		path = "udhcpc6"
	}
	
	c := &DHCPClient{
		Opts: opts,
		// Foreground, set interface and handler "script"
		cmd: exec.Command(path, "-f", "-i", iface, "-s", opts.HandlerScript),
	}

	stderrPipe, err := c.cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to set up udhcpc stderr pipe: %w", err)
	}
	// Pipe udhcpc stderr (logs) to logrus at debug level
	go io.Copy(log.StandardLogger().WriterLevel(log.DebugLevel), stderrPipe)

	if c.eventPipe, err = c.cmd.StdoutPipe(); err != nil {
		return nil, fmt.Errorf("failed to set up udhcpc stdout pipe: %w", err)
	}

	if opts.Once {
		// Exit after obtaining configuration
		c.cmd.Args = append(c.cmd.Args, "-q")
	} else {
		// Release IP address on exit
		c.cmd.Args = append(c.cmd.Args, "-R")
	}

	// Add INFORM mode for IPv4 (request configuration without IP assignment)
	if !opts.V6 {
		c.cmd.Args = append(c.cmd.Args, "-n")  // Don't configure interface
		c.cmd.Args = append(c.cmd.Args, "-I")  // Use DHCP INFORM
	}

	if opts.Hostname != "" {
		hostnameOpt := "hostname:" + opts.Hostname
		if opts.V6 {
			// TODO: We encode the fqdn for DHCPv6 because udhcpc6 seems to be broken
			var data bytes.Buffer

			// flags: S bit set (see RFC4704)
			binary.Write(&data, binary.BigEndian, uint8(0b0001))
			binary.Write(&data, binary.BigEndian, uint8(len(opts.Hostname)))
			data.WriteString(opts.Hostname)

			hostnameOpt = "0x27:" + hex.EncodeToString(data.Bytes())
		}

		c.cmd.Args = append(c.cmd.Args, "-x", hostnameOpt)
	}

	// Vendor ID string option is not available for udhcpc6
	if !opts.V6 {
		c.cmd.Args = append(c.cmd.Args, "-V", VendorID)
	}

	log.WithField("cmd", c.cmd).Trace("new udhcpc INFORM client")

	return c, nil
}

// NewDHCPClient creates a new udhcpc(6) client
func NewDHCPClient(iface string, opts *DHCPClientOptions) (*DHCPClient, error) {
	if opts.HandlerScript == "" {
		opts.HandlerScript = DefaultHandler
	}

	path := "udhcpc"
	if opts.V6 {
		path = "udhcpc6"
	}
	c := &DHCPClient{
		Opts: opts,
		// Foreground, set interface and handler "script"
		cmd: exec.Command(path, "-f", "-i", iface, "-s", opts.HandlerScript),
	}

	stderrPipe, err := c.cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to set up udhcpc stderr pipe: %w", err)
	}
	// Pipe udhcpc stderr (logs) to logrus at debug level
	go io.Copy(log.StandardLogger().WriterLevel(log.DebugLevel), stderrPipe)

	if c.eventPipe, err = c.cmd.StdoutPipe(); err != nil {
		return nil, fmt.Errorf("failed to set up udhcpc stdout pipe: %w", err)
	}

	if opts.Once {
		// Exit after obtaining lease
		c.cmd.Args = append(c.cmd.Args, "-q")
	} else {
		// Release IP address on exit
		c.cmd.Args = append(c.cmd.Args, "-R")
	}

	if opts.Hostname != "" {
		hostnameOpt := "hostname:" + opts.Hostname
		if opts.V6 {
			// TODO: We encode the fqdn for DHCPv6 because udhcpc6 seems to be broken
			var data bytes.Buffer

			// flags: S bit set (see RFC4704)
			binary.Write(&data, binary.BigEndian, uint8(0b0001))
			binary.Write(&data, binary.BigEndian, uint8(len(opts.Hostname)))
			data.WriteString(opts.Hostname)

			hostnameOpt = "0x27:" + hex.EncodeToString(data.Bytes())
		}

		c.cmd.Args = append(c.cmd.Args, "-x", hostnameOpt)
	}

	// Vendor ID string option is not available for udhcpc6
	if !opts.V6 {
		c.cmd.Args = append(c.cmd.Args, "-V", VendorID)
	}

	log.WithField("cmd", c.cmd).Trace("new udhcpc client")

	return c, nil
}

// Start starts udhcpc(6)
func (c *DHCPClient) Start() (chan Event, error) {
	if c.Opts.Namespace != "" {
		// Lock the OS Thread so we don't accidentally switch namespaces
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		origNS, err := netns.Get()
		if err != nil {
			return nil, fmt.Errorf("failed to open current network namespace: %w", err)
		}
		defer origNS.Close()

		ns, err := netns.GetFromPath(c.Opts.Namespace)
		if err != nil {
			return nil, fmt.Errorf("failed to open network namespace `%v`: %w", c.Opts.Namespace, err)
		}
		defer ns.Close()

		if err := netns.Set(ns); err != nil {
			return nil, fmt.Errorf("failed to enter network namespace: %w", err)
		}

		// Make sure we go back to the old namespace when we return
		defer netns.Set(origNS)
	}

	if err := c.cmd.Start(); err != nil {
		return nil, err
	}

	events := make(chan Event)
	go func() {
		scanner := bufio.NewScanner(c.eventPipe)
		for scanner.Scan() {
			log.WithField("line", string(scanner.Bytes())).Trace("udhcpc handler line")

			// Each line is a JSON-encoded event
			var event Event
			if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
				log.WithError(err).Warn("Failed to decode udhcpc event")
				continue
			}

			events <- event
		}
	}()

	return events, nil
}

// Finish sends SIGTERM to udhcpc(6) and waits for it to exit. SIGTERM will not
// be sent if `Opts.Once` is set.
func (c *DHCPClient) Finish(ctx context.Context) error {
	// If only running to get an IP once, udhcpc will terminate on its own
	if !c.Opts.Once {
		if err := c.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			return fmt.Errorf("failed to send SIGTERM to udhcpc: %w", err)
		}
	}

	errChan := make(chan error)
	go func() {
		errChan <- c.cmd.Wait()
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		c.cmd.Process.Kill()
		return ctx.Err()
	}
}

// GetNetworkConfig is a convenience function that runs udhcpc INFORM to get
// network configuration (gateway, DNS, etc.) without requesting an IP address.
func GetNetworkConfig(ctx context.Context, iface string, opts *DHCPClientOptions) (Info, error) {
	dummy := Info{}

	opts.Once = true
	client, err := NewDHCPClientInform(iface, opts)
	if err != nil {
		return dummy, fmt.Errorf("failed to create DHCP INFORM client: %w", err)
	}

	events, err := client.Start()
	if err != nil {
		return dummy, fmt.Errorf("failed to start DHCP INFORM client: %w", err)
	}

	var info *Info
	done := make(chan struct{})
	go func() {
		for {
			select {
			case event := <-events:
				switch event.Type {
				case "bound", "renew":
					info = &event.Data
				}
			case <-done:
				return
			}
		}
	}()
	defer close(done)

	if err := client.Finish(ctx); err != nil {
		return dummy, err
	}

	if info == nil {
		return dummy, util.ErrNoLease
	}

	return *info, nil
}

// GetIP is a convenience function that runs udhcpc(6) once and returns the IP
// info obtained.
func GetIP(ctx context.Context, iface string, opts *DHCPClientOptions) (Info, error) {
	dummy := Info{}

	opts.Once = true
	client, err := NewDHCPClient(iface, opts)
	if err != nil {
		return dummy, fmt.Errorf("failed to create DHCP client: %w", err)
	}

	events, err := client.Start()
	if err != nil {
		return dummy, fmt.Errorf("failed to start DHCP client: %w", err)
	}

	var info *Info
	done := make(chan struct{})
	go func() {
		for {
			select {
			case event := <-events:
				switch event.Type {
				case "bound", "renew":
					info = &event.Data
				}
			case <-done:
				return
			}
		}
	}()
	defer close(done)

	if err := client.Finish(ctx); err != nil {
		return dummy, err
	}

	if info == nil {
		return dummy, util.ErrNoLease
	}

	return *info, nil
}
