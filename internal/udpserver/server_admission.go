package udpserver

import (
	DnsParser "cottendns-go/internal/dnsparser"
	domainMatcher "cottendns-go/internal/domainmatcher"
	VpnProto "cottendns-go/internal/vpnproto"
)

// ingressQueueCapacity bounds the queue by both request count and worst-case
// backing-buffer bytes. It protects upgraded servers whose preserved config
// still contains the historical 65,535-byte packet size and 16,384-slot queue.
func (s *Server) ingressQueueCapacity() int {
	requestLimit := s.cfg.MaxConcurrentRequests
	if requestLimit < 1 {
		requestLimit = 1
	}
	packetBytes := s.cfg.MaxPacketSize
	if packetBytes < 1 {
		packetBytes = 1
	}
	byteLimit := s.cfg.MaxIngressQueueBytes
	if byteLimit < packetBytes {
		return 1
	}
	byteCapacity := byteLimit / packetBytes
	if byteCapacity < requestLimit {
		return byteCapacity
	}
	return requestLimit
}

// admitIngressPacket performs only the cheap DNS/domain checks and tunnel frame
// decryption/header validation needed to decide whether a UDP datagram deserves
// scarce queue space. Payload decompression and all session work stay on bounded
// workers. Remembering the successful codec keeps dynamic method detection to
// one trial in steady state without tying admission to a source IP.
func (s *Server) admitIngressPacket(packet []byte) bool {
	if s == nil || s.domainMatcher == nil || len(s.codecs) == 0 {
		return false
	}
	parsed, err := DnsParser.ParseDNSRequestLite(packet)
	if err != nil || !parsed.HasQuestion {
		return false
	}
	decision := s.domainMatcher.Match(parsed)
	if decision.Action != domainMatcher.ActionProcess {
		return false
	}
	startIdx := int(s.preferredCodec.Load())
	_, codecIdx, err := VpnProto.ParseFromLabelsAny(decision.Labels, s.codecs, startIdx)
	if err == nil && codecIdx != startIdx {
		s.preferredCodec.Store(int32(codecIdx))
	}
	return err == nil
}
