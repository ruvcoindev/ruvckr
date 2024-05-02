//go:build !mobile
// +build !mobile

package tun

// The linux platform specific tun parts

import (
	"net"

	"github.com/vishvananda/netlink"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// Configures the TUN adapter with the correct IPv6 address and MTU.
func (tun *TunAdapter) setup(ifname string, addr string, mtu uint64) error {
	if ifname == "auto" {
		ifname = "\000"
	}
	iface, err := wgtun.CreateTUN(ifname, int(mtu))
	if err != nil {
		panic(err)
	}
	tun.iface = iface
	if mtu, err := iface.MTU(); err == nil {
		tun.mtu = getSupportedMTU(uint64(mtu))
	} else {
		tun.mtu = 0
	}
	if err := tun.setupAddress(addr); err != nil {
		return err
	}

	if link, err := netlink.LinkByName(tun.Name()); err != nil {
		return err
	} else {
		v4err := tun.setupV4Routes(link)
		v6err := tun.setupV6Routes(link)
		if v4err != nil {
			return v4err
		}
		if v6err != nil {
			return v6err
		}
	}
	return nil
}

// Configures the TUN adapter with the correct IPv6 address and MTU. Netlink
// is used to do this, so there is not a hard requirement on "ip" or "ifconfig"
// to exist on the system, but this will fail if Netlink is not present in the
// kernel (it nearly always is).
func (tun *TunAdapter) setupAddress(addr string) error {
	nladdr, err := netlink.ParseAddr(addr)
	if err != nil {
		return err
	}
	nlintf, err := netlink.LinkByName(tun.Name())
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(nlintf, nladdr); err != nil {
		return err
	}
	ip := nladdr.IP.To16()
	ip[0] = 10
	ipv4 := net.IPv4(ip[0], ip[1], ip[2], ip[3]>>1+1)

	addressIPv4, err := netlink.ParseAddr(ipv4.String() + "/8")
	if err != nil {
		tun.log.Errorf("Could not assign IPv4 address: %s", ipv4.String())
	}
	if err := netlink.AddrAdd(nlintf, addressIPv4); err != nil {
		return err
	}
	if err := netlink.LinkSetMTU(nlintf, int(tun.mtu)); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(nlintf); err != nil {
		return err
	}
	// Friendly output
	tun.log.Infof("Interface name: %s", tun.Name())
	tun.log.Infof("Interface IPv6: %s", addr)
	tun.log.Infof("Interface MTU: %d", tun.mtu)
	return nil
}

func (tun *TunAdapter) setupV4Routes(link netlink.Link) error {
	for _, r := range tun.rwc.V4Routes() {
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst: &net.IPNet{
				IP:   net.IP(r.Prefix.Addr().AsSlice()),
				Mask: net.CIDRMask(r.Prefix.Masked().Bits(), 32),
			},
		}
		if err := netlink.RouteAdd(route); err != nil {
			return err
		}
	}
	return nil
}

func (tun *TunAdapter) setupV6Routes(link netlink.Link) error {
	for _, r := range tun.rwc.V6Routes() {
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst: &net.IPNet{
				IP:   net.IP(r.Prefix.Addr().AsSlice()),
				Mask: net.CIDRMask(r.Prefix.Masked().Bits(), 128),
			},
		}
		if err := netlink.RouteAdd(route); err != nil {
			return err
		}
	}
	return nil
}
