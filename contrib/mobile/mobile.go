package mobile

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"regexp"

	"github.com/ruvcoindev/ruvchain-go/src/config"
	"github.com/ruvcoindev/ruvchain-go/src/restapi"
	"github.com/ruvcoindev/ruvckr/src/ckriprwc"
	c "github.com/ruvcoindev/ruvckr/src/config"
	"github.com/gologme/log"
	"github.com/mitchellh/mapstructure"

	"github.com/ruvcoindev/ruvchain-go/src/core"
	"github.com/ruvcoindev/ruvchain-go/src/defaults"
	"github.com/ruvcoindev/ruvchain-go/src/multicast"
	"github.com/ruvcoindev/ruvchain-go/src/version"

	_ "golang.org/x/mobile/bind"
)

// Ruvchain mobile package is meant to "plug the gap" for mobile support, as
// Gomobile will not create headers for Swift/Obj-C etc if they have complex
// (non-native) types. Therefore for iOS we will expose some nice simple
// functions. Note that in the case of iOS we handle reading/writing to/from TUN
// in Swift therefore we use the "dummy" TUN interface instead.
type Ruvchain struct {
	core        *core.Core
	iprwc       *ckriprwc.ReadWriteCloser
	config      *config.NodeConfig
	multicast   *multicast.Multicast
	rest_server *restapi.RestServer
	log         MobileLogger
}

// StartAutoconfigure starts a node with a randomly generated config
func (m *Ruvchain) StartAutoconfigure() error {
	return m.StartJSON([]byte("{}"))
}

// StartJSON starts a node with the given JSON config. You can get JSON config
// (rather than HJSON) by using the GenerateConfigJSON() function
func (m *Ruvchain) StartJSON(configjson []byte) error {
	logger := log.New(m.log, "", 0)
	logger.EnableLevel("error")
	logger.EnableLevel("warn")
	logger.EnableLevel("info")
	m.config = defaults.GenerateConfig()
	if err := json.Unmarshal(configjson, &m.config); err != nil {
		return err
	}
	// Setup the Ruvchain node itself.
	{
		sk, err := hex.DecodeString(m.config.PrivateKey)
		if err != nil {
			panic(err)
		}
		options := []core.SetupOption{
			core.NodeInfo(m.config.NodeInfo),
			core.NodeInfoPrivacy(m.config.NodeInfoPrivacy),
			core.NetworkDomain(m.config.NetworkDomain),
		}
		for _, peer := range m.config.Peers {
			options = append(options, core.Peer{URI: peer})
		}
		for intf, peers := range m.config.InterfacePeers {
			for _, peer := range peers {
				options = append(options, core.Peer{URI: peer, SourceInterface: intf})
			}
		}
		for _, allowed := range m.config.AllowedPublicKeys {
			k, err := hex.DecodeString(allowed)
			if err != nil {
				panic(err)
			}
			options = append(options, core.AllowedPublicKey(k[:]))
		}
		m.core, err = core.New(sk[:], logger, options...)
		if err != nil {
			panic(err)
		}
	}

	// Setup the multicast module.
	if len(m.config.MulticastInterfaces) > 0 {
		var err error
		options := []multicast.SetupOption{}
		for _, intf := range m.config.MulticastInterfaces {
			options = append(options, multicast.MulticastInterface{
				Regex:    regexp.MustCompile(intf.Regex),
				Beacon:   intf.Beacon,
				Listen:   intf.Listen,
				Port:     intf.Port,
				Priority: uint8(intf.Priority),
			})
		}
		if m.multicast, err = multicast.New(m.core, logger, options...); err != nil {
			fmt.Println("Multicast module fail:", err)
		}
	}

	// Setup the REST socket.
	{
		var err error
		if m.rest_server, err = restapi.NewRestServer(restapi.RestServerCfg{
			Core:          m.core,
			Multicast:     m.multicast,
			Log:           logger,
			ListenAddress: m.config.HttpAddress,
			WwwRoot:       m.config.WwwRoot,
			ConfigFn:      "",
		}); err != nil {
			logger.Errorln(err)
		} else {
			err = m.rest_server.Serve()
			if err != nil {
				logger.Errorln(err)
			}
		}
	}

	mtu := m.config.IfMTU

	var node_config = &c.TunnelRoutingConfig{
		Enable:            false,
		IPv4RemoteSubnets: nil,
		IPv6RemoteSubnets: nil,
	}
	mapstructure.Decode(m.config.FeaturesConfig["TunnelRouting"], node_config)

	m.iprwc = ckriprwc.NewReadWriteCloser(m.core, node_config, logger)
	if m.iprwc.MaxMTU() < mtu {
		mtu = m.iprwc.MaxMTU()
	}
	m.iprwc.SetMTU(mtu)
	return nil
}

// Send sends a packet to RiV-Ruvchain. It should be a fully formed
// IPv6 packet
func (m *Ruvchain) Send(p []byte) error {
	if m.iprwc == nil {
		return nil
	}
	_, _ = m.iprwc.Write(p)
	return nil
}

// Send sends a packet from given buffer to RiV-Ruvchain. From first byte up to length.
func (m *Ruvchain) SendBuffer(p []byte, length int) error {
	if m.iprwc == nil {
		return nil
	}
	if len(p) < length {
		return nil
	}
	_, _ = m.iprwc.Write(p[:length])
	return nil
}

// Recv waits for and reads a packet coming from RiV-Ruvchain. It
// will be a fully formed IPv6 packet
func (m *Ruvchain) Recv() ([]byte, error) {
	if m.iprwc == nil {
		return nil, nil
	}
	var buf [65535]byte
	n, _ := m.iprwc.Read(buf[:])
	return buf[:n], nil
}

// Recv waits for and reads a packet coming from RiV-Ruvchain to given buffer, returning size of packet
func (m *Ruvchain) RecvBuffer(buf []byte) (int, error) {
	if m.iprwc == nil {
		return 0, nil
	}
	n, _ := m.iprwc.Read(buf)
	return n, nil
}

// Stop the mobile Ruvchain instance
func (m *Ruvchain) Stop() error {
	logger := log.New(m.log, "", 0)
	logger.EnableLevel("info")
	logger.Infof("Stop the mobile Ruvchain instance %s", "")
	if err := m.multicast.Stop(); err != nil {
		return err
	}
	m.core.Stop()
	m.rest_server.Shutdown()
	m.rest_server = nil
	return nil
}

// Retry resets the peer connection timer and tries to dial them immediately.
func (m *Ruvchain) RetryPeersNow() {
	m.core.RetryPeersNow()
}

// GenerateConfigJSON generates mobile-friendly configuration in JSON format
func GenerateConfigJSON() []byte {
	nc := defaults.GenerateConfig()
	nc.IfName = "none"
	if json, err := json.Marshal(nc); err == nil {
		return json
	}
	return nil
}

// GetAddressString gets the node's IPv6 address
func (m *Ruvchain) GetAddressString() string {
	ip := m.core.Address()
	return ip.String()
}

// GetSubnetString gets the node's IPv6 subnet in CIDR notation
func (m *Ruvchain) GetSubnetString() string {
	subnet := m.core.Subnet()
	return subnet.String()
}

// GetPublicKeyString gets the node's public key in hex form
func (m *Ruvchain) GetPublicKeyString() string {
	return hex.EncodeToString(m.core.GetSelf().Key)
}

// GetCoordsString gets the node's coordinates
func (m *Ruvchain) GetCoordsString() string {
	return fmt.Sprintf("%v", m.core.GetSelf().Coords)
}

func (m *Ruvchain) GetPeersJSON() (result string) {
	peers := []struct {
		core.PeerInfo
		IP string
	}{}
	for _, v := range m.core.GetPeers() {
		a := m.core.AddrForKey(v.Key)
		ip := net.IP(a[:]).String()
		peers = append(peers, struct {
			core.PeerInfo
			IP string
		}{
			PeerInfo: v,
			IP:       ip,
		})
	}
	if res, err := json.Marshal(peers); err == nil {
		return string(res)
	} else {
		return "{}"
	}
}

func (m *Ruvchain) GetDHTJSON() (result string) {
	if res, err := json.Marshal(m.core.GetDHT()); err == nil {
		return string(res)
	} else {
		return "{}"
	}
}

// GetMTU returns the configured node MTU. This must be called AFTER Start.
func (m *Ruvchain) GetMTU() int {
	return int(m.core.MTU())
}

func GetVersion() string {
	return version.BuildVersion()
}
