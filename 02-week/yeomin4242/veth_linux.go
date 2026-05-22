//go:build linux

package main

import (
	"errors"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func createVethPair(name string, req createVethRequest) error {
	targetNS, err := netns.GetFromPath(netnsPath(name))
	if err != nil {
		return fmt.Errorf("open named network namespace %s: %w", netnsPath(name), err)
	}
	defer targetNS.Close()

	hostHandle, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("open host netlink handle: %w", err)
	}
	defer hostHandle.Close()

	nsHandle, err := netlink.NewHandleAt(targetNS)
	if err != nil {
		return fmt.Errorf("open namespace netlink handle: %w", err)
	}
	defer nsHandle.Close()

	if err := ensureLinkAbsent(hostHandle, req.HostIfname); err != nil {
		return err
	}

	if err := ensureLinkAbsent(nsHandle, req.PeerIfname); err != nil {
		return err
	}

	tempPeerName := tempPeerName(req.HostIfname, req.PeerIfname)
	if err := ensureLinkAbsent(hostHandle, tempPeerName); err != nil {
		return err
	}

	if err := ensureLinkAbsent(nsHandle, tempPeerName); err != nil {
		return err
	}

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: req.HostIfname},
		PeerName:  tempPeerName,
	}

	if err := hostHandle.LinkAdd(veth); err != nil {
		if isAlreadyExists(err) {
			return conflictError{message: fmt.Sprintf("link %s or %s already exists", req.HostIfname, tempPeerName)}
		}
		return fmt.Errorf("create veth pair %s/%s: %w", req.HostIfname, tempPeerName, err)
	}

	vethCreated := true
	defer func() {
		if vethCreated {
			_ = deleteVethIfExists(hostHandle, req.HostIfname)
		}
	}()

	hostLink, err := hostHandle.LinkByName(req.HostIfname)
	if err != nil {
		return fmt.Errorf("lookup host-side veth %s: %w", req.HostIfname, err)
	}

	peerLink, err := hostHandle.LinkByName(tempPeerName)
	if err != nil {
		return fmt.Errorf("lookup temporary peer veth %s: %w", tempPeerName, err)
	}

	if err := hostHandle.LinkSetNsFd(peerLink, int(targetNS)); err != nil {
		return fmt.Errorf("move peer veth %s to %s: %w", tempPeerName, netnsPath(name), err)
	}

	hostAddr, err := netlink.ParseAddr(req.HostIP)
	if err != nil {
		return fmt.Errorf("parse host_ip %q: %w", req.HostIP, err)
	}

	if err := hostHandle.AddrAdd(hostLink, hostAddr); err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("add host IP %s to %s: %w", req.HostIP, req.HostIfname, err)
	}

	if err := hostHandle.LinkSetUp(hostLink); err != nil {
		return fmt.Errorf("set host veth %s up: %w", req.HostIfname, err)
	}

	nsPeerLink, err := nsHandle.LinkByName(tempPeerName)
	if err != nil {
		return fmt.Errorf("lookup peer veth %s in %s: %w", tempPeerName, netnsPath(name), err)
	}

	if err := nsHandle.LinkSetName(nsPeerLink, req.PeerIfname); err != nil {
		return fmt.Errorf("rename peer veth %s to %s: %w", tempPeerName, req.PeerIfname, err)
	}

	nsPeerLink, err = nsHandle.LinkByName(req.PeerIfname)
	if err != nil {
		return fmt.Errorf("lookup renamed peer veth %s: %w", req.PeerIfname, err)
	}

	peerAddr, err := netlink.ParseAddr(req.PeerIP)
	if err != nil {
		return fmt.Errorf("parse peer_ip %q: %w", req.PeerIP, err)
	}

	if err := nsHandle.AddrAdd(nsPeerLink, peerAddr); err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("add peer IP %s to %s: %w", req.PeerIP, req.PeerIfname, err)
	}

	if err := nsHandle.LinkSetUp(nsPeerLink); err != nil {
		return fmt.Errorf("set peer veth %s up: %w", req.PeerIfname, err)
	}

	loLink, err := nsHandle.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("lookup lo in %s: %w", netnsPath(name), err)
	}

	if err := nsHandle.LinkSetUp(loLink); err != nil {
		return fmt.Errorf("set lo up in %s: %w", netnsPath(name), err)
	}

	vethCreated = false
	return nil
}

func deleteVethIfExists(handle *netlink.Handle, name string) error {
	link, err := handle.LinkByName(name)
	if err != nil {
		if isNotFound(err) {
			return nil
		}

		return fmt.Errorf("lookup link %s: %w", name, err)
	}

	if link.Type() != "veth" {
		return conflictError{message: fmt.Sprintf("link %s already exists as type %q; refusing to delete non-veth link", name, link.Type())}
	}

	if err := handle.LinkDel(link); err != nil {
		return fmt.Errorf("delete existing link %s: %w", name, err)
	}

	return nil
}

func ensureLinkAbsent(handle *netlink.Handle, name string) error {
	link, err := handle.LinkByName(name)
	if err != nil {
		if isNotFound(err) {
			return nil
		}

		return fmt.Errorf("lookup link %s: %w", name, err)
	}

	return conflictError{message: fmt.Sprintf("link %s already exists as type %q", name, link.Type())}
}

type conflictError struct {
	message string
}

func (e conflictError) Error() string {
	return e.message
}

func tempPeerName(hostIfname, peerIfname string) string {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(hostIfname))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(peerIfname))

	return fmt.Sprintf("tmp%x", hash.Sum32())
}

func isAlreadyExists(err error) bool {
	if err == nil {
		return false
	}

	return errors.Is(err, unix.EEXIST) || strings.Contains(strings.ToLower(err.Error()), "file exists")
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}

	lower := strings.ToLower(err.Error())
	return errors.Is(err, unix.ENODEV) ||
		strings.Contains(lower, "not found") ||
		strings.Contains(lower, "no such network interface") ||
		strings.Contains(lower, "link not found")
}
