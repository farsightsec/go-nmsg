package nmsg_base

//
// Compatibility definitions for code written against older versions
// of the nmsg_base .proto files.
//

type DnsQRType = DnsQR_DnsQRType

const (
	DnsQRType_UDP_INVALID              = DnsQR_UDP_INVALID
	DnsQRType_UDP_QUERY_RESPONSE       = DnsQR_UDP_QUERY_RESPONSE
	DnsQRType_UDP_UNANSWERED_QUERY     = DnsQR_UDP_UNANSWERED_QUERY
	DnsQRType_UDP_UNSOLICITED_RESPONSE = DnsQR_UDP_UNSOLICITED_RESPONSE
	DnsQRType_TCP                      = DnsQR_TCP
	DnsQRType_ICMP                     = DnsQR_ICMP
	DnsQRType_UDP_QUERY_ONLY           = DnsQR_UDP_QUERY_ONLY
	DnsQRType_UDP_RESPONSE_ONLY        = DnsQR_UDP_RESPONSE_ONLY
)

type UdpChecksum = DnsQR_UdpChecksum

const (
	UdpChecksum_ERROR     = DnsQR_ERROR
	UdpChecksum_ABSENT    = DnsQR_ABSENT
	UdpChecksum_INCORRECT = DnsQR_INCORRECT
	UdpChecksum_CORRECT   = DnsQR_CORRECT
)

type EmailType = Email_EmailType

const (
	EmailType_unknown     = Email_unknown
	EmailType_spamtrap    = Email_spamtrap
	EmailType_rej_network = Email_rej_network
	EmailType_rej_content = Email_rej_content
	EmailType_rej_user    = Email_rej_user
)

type EncodeType = Encode_EncodeType

const (
	EncodeType_TEXT    = Encode_TEXT
	EncodeType_JSON    = Encode_JSON
	EncodeType_YAML    = Encode_YAML
	EncodeType_MSGPACK = Encode_MSGPACK
	EncodeType_XML     = Encode_XML
)

type HttpType = Http_HttpType

const (
	HttpType_unknown  = Http_unknown
	HttpType_sinkhole = Http_sinkhole
)

type LinkType = Linkpair_Linktype

const (
	Linktype_anchor   = Linkpair_anchor
	Linktype_redirect = Linkpair_redirect
)

type NcapType Ncap_NcapType

const (
	NcapType_IPV4   = Ncap_IPV4
	NcapType_IPV6   = Ncap_IPV6
	NcapType_Legacy = Ncap_Legacy
)

type NcapLegacyType = Ncap_NcapLegacyType

const (
	NcapLegacyType_Ncap_UDP  = Ncap_UDP
	NcapLegacyType_Ncap_TCP  = Ncap_TCP
	NcapLegacyType_Ncap_ICMP = Ncap_ICMP
)
