#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <streambuf>
#include <sstream>

using namespace PacketAnalyzer;

static std::string json(const std::string& s) {
    std::ostringstream o; o << '"';
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') o << '\\' << c;
        else if (c < 0x20) o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
        else o << c;
    }
    o << '"'; return o.str();
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    PcapReader reader;
    std::ostringstream diagnostics;
    auto* original = std::cout.rdbuf(diagnostics.rdbuf());
    if (!reader.open(argv[1])) { std::cerr << "Invalid or unsupported PCAP file"; return 3; }
    std::cout.rdbuf(original);
    if (reader.getGlobalHeader().network != 1) { std::cerr << "Only Ethernet PCAP is supported"; return 4; }
    RawPacket raw; ParsedPacket p; uint64_t n = 0;
    while (reader.readNextPacket(raw)) {
        ++n;
        if (!PacketParser::parse(raw, p)) continue;
        std::string transport = p.has_tcp ? "TCP" : p.has_udp ? "UDP" : p.has_ip ? PacketParser::protocolToString(p.protocol) : "Other";
        std::string app = "Unknown", host;
        if (p.payload_length && p.payload_data) {
            if (p.has_tcp) {
                auto h = DPI::HTTPHostExtractor::extract(p.payload_data, p.payload_length);
                auto sni = DPI::SNIExtractor::extract(p.payload_data, p.payload_length);
                if (h) { app = "HTTP"; host = *h; }
                else if (sni) { app = "TLS"; host = *sni; }
                else if (p.src_port == 443 || p.dest_port == 443) app = "TLS";
                else if (p.src_port == 80 || p.dest_port == 80) app = "HTTP";
            } else if (p.has_udp && (p.src_port == 53 || p.dest_port == 53)) {
                app = "DNS";
                auto d = DPI::DNSExtractor::extractQuery(p.payload_data, p.payload_length);
                if (d) host = *d;
            } else if (p.has_udp && (p.src_port == 443 || p.dest_port == 443)) app = "QUIC";
        }
        if (!host.empty()) {
            const auto classified = DPI::appTypeToString(DPI::sniToAppType(host));
            if (classified != "Unknown") app = classified;
        }
        std::cout << "{\"number\":" << n << ",\"timestamp\":" << (double)p.timestamp_sec + p.timestamp_usec / 1000000.0
          << ",\"length\":" << raw.data.size() << ",\"transport\":" << json(transport)
          << ",\"application\":" << json(app) << ",\"src_ip\":" << json(p.src_ip)
          << ",\"dst_ip\":" << json(p.dest_ip) << ",\"src_port\":" << (p.has_tcp || p.has_udp ? p.src_port : 0)
          << ",\"dst_port\":" << (p.has_tcp || p.has_udp ? p.dest_port : 0)
          << ",\"src_mac\":" << json(p.src_mac) << ",\"dst_mac\":" << json(p.dest_mac)
          << ",\"ttl\":" << (p.has_ip ? (int)p.ttl : 0) << ",\"tcp_flags\":" << json(p.has_tcp ? PacketParser::tcpFlagsToString(p.tcp_flags) : "")
          << ",\"host\":" << json(host) << ",\"payload_length\":" << p.payload_length << "}\n";
    }
    return 0;
}
