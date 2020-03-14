package pgtpm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"
)

// MSSimulator implements io.ReadWriteCloser and can be passed to the go-tpm
// package to interface with the Microsoft TPM 2.0 Simulator.
type MSSimulator struct {
	tpmSock      net.Conn
	platformSock net.Conn
	state        connState
	host         string
}

// connState is the connection state. Transmit and receive operations must
// strictly alternate, and the connection state enforces that.
type connState int

// Connection state constants.
const (
	stateTransmit = iota
	stateReceive
)

// Simulator command constants.
const (
	msSimPowerOn        uint32 = 0x01
	msSimNVOn           uint32 = 0x0b
	msSimTPMSendCommand uint32 = 0x08
)

// Write writes to the Microsoft simulator.
func (c *MSSimulator) Write(p []byte) (int, error) {
	// Check state.
	if c.state != stateTransmit {
		return 0, fmt.Errorf("attempted to transmit in receive state")
	}
	c.state = stateReceive

	// Prepare the command.
	if err := c.prepareCommand(len(p)); err != nil {
		return 0, err
	}

	// Write the command.
	return c.tpmSock.Write(p)
}

// Read reads from the Microsoft simulator.
func (c *MSSimulator) Read(p []byte) (int, error) {
	// Check state.
	if c.state != stateReceive {
		return 0, fmt.Errorf("attempted to receive in transmit state")
	}
	c.state = stateTransmit

	// Read the length of the response.
	rlen, err := c.readResponseLength()
	if err != nil {
		return 0, err
	}

	// Read the response bytes.
	n, err := c.tpmSock.Read(p[:rlen])
	if err != nil {
		return 0, err
	} else if n != rlen {
		return 0, fmt.Errorf("read %d response length bytes when %d were expected", n, rlen)
	}

	// Read the four appended zero bytes.
	err = c.readAppendedZeroBytes()
	if err != nil {
		return 0, err
	}

	return n, nil
}

// Close closes the connection with the Microsoft simulator.
func (c *MSSimulator) Close() error {
	var errPlatform error
	var errTPM error

	if c.platformSock != nil {
		errPlatform = c.platformSock.Close()
	}

	if c.tpmSock != nil {
		errTPM = c.tpmSock.Close()
	}

	c.tpmSock = nil
	c.platformSock = nil

	if errPlatform != nil {
		return errPlatform
	}

	return errTPM
}

// platformFunction sends the specified platform function to the simulator
// and reads the response. An error is returned if the response is not zero.
func (c *MSSimulator) platformFunction(cmd uint32) error {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, cmd)

	n, err := c.platformSock.Write(buf)
	if err != nil {
		return err
	}

	n, err = c.platformSock.Read(buf)
	if err != nil {
		return err
	} else if n < 4 {
		return fmt.Errorf("read %d platform function response bytes, expected 4", n)
	}

	var rc = binary.BigEndian.Uint32(buf)
	if rc != 0 {
		return fmt.Errorf("failed with platform error code: %d", rc)
	}

	return nil
}

// prepareCommand sends an MS_SIM_TPM_SEND_COMMAND command to the simulator
// for a command with the specified length.
func (c *MSSimulator) prepareCommand(n int) error {
	buf := make([]byte, 9)
	binary.BigEndian.PutUint32(buf[0:4], msSimTPMSendCommand)
	buf[4] = 0 // Locality
	binary.BigEndian.PutUint32(buf[5:9], uint32(n))

	_, err := c.tpmSock.Write(buf)
	return err
}

// readResponseLength reads a four-byte length field prepended to a
// command response.
func (c *MSSimulator) readResponseLength() (int, error) {
	buf := make([]byte, 4)
	if n, err := c.tpmSock.Read(buf); err != nil {
		return 0, err
	} else if n != 4 {
		return 0, fmt.Errorf("read %d response length bytes when 4 were expected", n)
	}

	return int(binary.BigEndian.Uint32(buf)), nil
}

// readAppendedZeroBytes reads the four zero bytes appended to a command
// response, and returns an error if less than 4 bytes were read, or if
// any of the four bytes were non-zero.
func (c *MSSimulator) readAppendedZeroBytes() error {
	buf := make([]byte, 4)
	if n, err := c.tpmSock.Read(buf); err != nil {
		return err
	} else if n != 4 {
		return fmt.Errorf("read %d appended bytes when 4 were expected", n)
	}

	if v := binary.BigEndian.Uint32(buf); v != 0 {
		return fmt.Errorf("read value 0x%08x, expected 0x00000000", v)
	}

	return nil
}

// NewMSSimulator initializes a connection to the Microsoft TPM 2.0
// Simulator.
func NewMSSimulator(conf string) (*MSSimulator, error) {
	// Extract hostname and port number from conf string.
	elements := strings.Split(conf, ":")
	if len(elements) != 2 {
		return nil, fmt.Errorf("conf string must be of the format host:port")
	}

	hostname := elements[0]

	tpmPort, err := strconv.Atoi(elements[1])
	if err != nil {
		return nil, fmt.Errorf("invalid port number: %v", err)
	}

	// The platform server port is always 1 higher than the TPM command
	// server port.
	platformPort := tpmPort + 1

	// Connect to platform and TPM command servers.
	var s = &MSSimulator{
		state: stateTransmit,
	}

	s.platformSock, err = net.Dial("tcp", fmt.Sprintf("%s:%d", hostname, platformPort))
	if err != nil {
		return nil, err
	}

	if err := s.platformFunction(msSimPowerOn); err != nil {
		s.Close()
		return nil, err
	}

	if err := s.platformFunction(msSimNVOn); err != nil {
		s.Close()
		return nil, err
	}

	s.tpmSock, err = net.Dial("tcp", fmt.Sprintf("%s:%d", hostname, tpmPort))
	if err != nil {
		s.Close()
		return nil, err
	}

	// Start up TPM. If the command has previously been received, the error
	// code will be TPM_RC_INITIALIZE, and we don't treat it as an error.
	if err := tpm2.Startup(s, tpm2.StartupClear); err != nil {
		var te tpm2.Error
		if !errors.As(err, &te) || te.Code != tpm2.RCInitialize {
			s.Close()
			return nil, err
		}
	}

	return s, nil
}
