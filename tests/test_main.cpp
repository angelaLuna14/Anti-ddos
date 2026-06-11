#include <iostream>
#include <cassert>
#include "packet_engine.h"
#include "rate_limiter.h"
#include "vpn_detector.h"
#include "behavioral_analyzer.h"
#include "ml_detector.h"
#include "honeypot.h"
#include "auto_responder.h"
#include "threat_intel.h"
#include "game_protector.h"
#include "asn_database.h"
#include "attack_correlator.h"
#include "utils.h"

void test_packet_engine() {
    std::cout << "Testing Packet Engine..." << std::endl;
    antiddos::PacketEngine engine;
    engine.set_threshold(100, 1000, 1048576);
    std::cout << "  Packet Engine: OK" << std::endl;
}

void test_rate_limiter() {
    std::cout << "Testing Rate Limiter..." << std::endl;
    antiddos::RateLimiter limiter;
    antiddos::RateLimitConfig config;
    config.max_requests_per_second = 100;
    limiter.set_config(config);
    
    auto action = limiter.check_request("192.168.1.1");
    assert(action == antiddos::RateLimitAction::ALLOW);
    std::cout << "  Rate Limiter: OK" << std::endl;
}

void test_vpn_detector() {
    std::cout << "Testing VPN Detector..." << std::endl;
    antiddos::VPNDetector detector;
    
    std::vector<uint8_t> payload = {0x00, 0x0e, 0x01, 0x02};
    auto result = detector.analyze_connection("10.0.0.1", "192.168.1.1", 12345, 1194, 17, payload, 4);
    
    std::cout << "  VPN Detector: OK" << std::endl;
}

void test_behavioral_analyzer() {
    std::cout << "Testing Behavioral Analyzer..." << std::endl;
    antiddos::BehavioralAnalyzer analyzer;
    analyzer.set_learning_mode(false);
    
    antiddos::RequestPattern pattern;
    pattern.method = "GET";
    pattern.endpoint = "/api/test";
    pattern.payload_size = 100;
    pattern.timestamp = std::chrono::steady_clock::now();
    pattern.headers["User-Agent"] = "Mozilla/5.0 Test";
    
    analyzer.analyze_request("192.168.1.1", pattern);
    std::cout << "  Behavioral Analyzer: OK" << std::endl;
}

void test_ml_detector() {
    std::cout << "Testing ML Detector..." << std::endl;
    antiddos::ml::MLDetector detector;
    detector.set_threshold(0.5);
    
    antiddos::ml::FeatureVector fv;
    fv.packets_per_second = 100;
    fv.bytes_per_second = 50000;
    fv.syn_ratio = 0.3;
    fv.ack_ratio = 0.5;
    
    auto prediction = detector.predict(fv);
    std::cout << "  ML Detector: OK" << std::endl;
}

void test_honeypot() {
    std::cout << "Testing Honeypot System..." << std::endl;
    antiddos::honeypot::HoneypotManager manager;
    
    antiddos::honeypot::HoneypotConfig config;
    config.type = antiddos::honeypot::HoneypotType::HTTP;
    config.port = 8080;
    
    manager.create_honeypot("test-http", config);
    std::cout << "  Honeypot System: OK" << std::endl;
}

void test_auto_responder() {
    std::cout << "Testing Auto Responder..." << std::endl;
    antiddos::response::AutoResponder responder;
    
    antiddos::response::ResponseRule rule;
    rule.name = "syn-flood-rule";
    rule.attack_type = antiddos::response::AttackType::SYN_FLOOD;
    rule.min_severity = antiddos::response::ThreatSeverity::HIGH;
    rule.actions.push_back(antiddos::response::ResponseAction::BLOCK_IP);
    rule.duration_seconds = 300;
    rule.cooldown_seconds = 60;
    rule.enabled = true;
    
    responder.add_rule(rule);
    responder.process_threat("10.0.0.1", antiddos::response::AttackType::SYN_FLOOD, antiddos::response::ThreatSeverity::HIGH, 0.9);
    
    auto blocked = responder.get_blocked_ips();
    assert(!blocked.empty());
    std::cout << "  Auto Responder: OK" << std::endl;
}

void test_threat_intel() {
    std::cout << "Testing Threat Intelligence..." << std::endl;
    antiddos::intel::ThreatIntelManager intel;
    
    intel.add_ip_to_blacklist("10.0.0.1", 24, "test");
    intel.add_ip_to_whitelist("192.168.1.1", "trusted");
    
    assert(intel.is_ip_malicious("10.0.0.1"));
    assert(!intel.is_ip_malicious("192.168.1.1"));
    
    auto blocked = intel.get_blacklisted_ips();
    assert(!blocked.empty());
    std::cout << "  Threat Intelligence: OK" << std::endl;
}

void test_cidr_blocking() {
    std::cout << "Testing CIDR/Subnet Blocking..." << std::endl;
    
    assert(antiddos::utils::IPUtils::is_ip_in_cidr("192.168.1.100", "192.168.1.0/24"));
    assert(antiddos::utils::IPUtils::is_ip_in_cidr("10.0.0.50", "10.0.0.0/8"));
    assert(!antiddos::utils::IPUtils::is_ip_in_cidr("192.168.2.1", "192.168.1.0/24"));
    
    assert(antiddos::utils::IPUtils::do_ips_share_subnet("192.168.1.1", "192.168.1.254", 24));
    assert(!antiddos::utils::IPUtils::do_ips_share_subnet("192.168.1.1", "192.168.2.1", 24));
    
    std::string key = antiddos::utils::IPUtils::get_subnet_key("192.168.1.100", 24);
    assert(key == "192.168.1.0/24");
    
    auto range = antiddos::utils::IPUtils::parse_cidr("10.0.0.0/8");
    assert(range.prefix == 8);
    assert(range.network == 0x0A000000);
    
    antiddos::VPNDetector detector;
    detector.add_blocked_cidr("192.168.100.0/24", "test block");
    assert(detector.is_ip_in_blocked_cidr("192.168.100.50"));
    assert(!detector.is_ip_in_blocked_cidr("192.168.101.50"));
    
    antiddos::RateLimiter limiter;
    limiter.add_blocked_cidr("10.10.0.0/16");
    assert(limiter.is_ip_in_blocked_cidr("10.10.5.5"));
    assert(!limiter.is_ip_in_blocked_cidr("10.11.5.5"));
    
    antiddos::response::AutoResponder responder;
    responder.block_cidr("172.16.0.0/12", 3600, "test");
    assert(responder.is_ip_in_blocked_cidr("172.20.5.5"));
    assert(!responder.is_ip_in_blocked_cidr("192.168.1.1"));
    
    antiddos::intel::ThreatIntelManager intel;
    intel.add_cidr_to_blacklist("203.0.113.0/24", 24, "test");
    assert(intel.is_ip_in_blacklisted_cidr("203.0.113.50"));
    assert(!intel.is_ip_in_blacklisted_cidr("203.0.114.50"));
    
    std::cout << "  CIDR/Subnet Blocking: OK" << std::endl;
}

void test_game_protector() {
    std::cout << "Testing Game Protector (Half-Life/CS)..." << std::endl;
    
    antiddos::game::GameProtector protector;
    
    antiddos::game::GameProtectionConfig config;
    config.max_queries_per_second = 50;
    config.max_connections_per_second = 10;
    config.auto_block_duration_seconds = 300;
    protector.set_config(config);
    
    protector.add_game_server(27015, antiddos::game::GameType::COUNTER_STRIKE_16);
    protector.add_game_server(27011, antiddos::game::GameType::SVEN_COOP);
    
    std::vector<uint8_t> a2s_info = {0xFF, 0xFF, 0xFF, 0xFF, 0x49, 0x48, 0x6C, 0x6F};
    bool allowed = protector.analyze_packet("192.168.1.100", 12345, 27015, a2s_info, a2s_info.size());
    assert(allowed);
    
    std::vector<uint8_t> a2s_player = {0xFF, 0xFF, 0xFF, 0xFF, 0x55, 0x00, 0x00, 0x00, 0x00};
    allowed = protector.analyze_packet("192.168.1.100", 12345, 27015, a2s_player, a2s_player.size());
    assert(allowed);
    
    std::vector<uint8_t> a2s_rules = {0xFF, 0xFF, 0xFF, 0xFF, 0x56, 0x00, 0x00, 0x00, 0x00};
    allowed = protector.analyze_packet("192.168.1.100", 12345, 27015, a2s_rules, a2s_rules.size());
    assert(allowed);
    
    std::vector<uint8_t> a2s_challenge = {0xFF, 0xFF, 0xFF, 0xFF, 0x41, 0x00, 0x00, 0x00, 0x00};
    allowed = protector.analyze_packet("192.168.1.100", 12345, 27015, a2s_challenge, a2s_challenge.size());
    assert(allowed);
    
    std::vector<uint8_t> connect_req = {0xFF, 0xFF, 0xFF, 0xFF, 0x09, 0x00, 0x00, 0x00, 0x00};
    allowed = protector.analyze_packet("192.168.1.100", 12345, 27015, connect_req, connect_req.size());
    assert(allowed);
    
    assert(!protector.is_blocked("192.168.1.100"));
    assert(!protector.is_blocked("10.0.0.99"));
    
    protector.add_trusted_ip("192.168.1.1");
    assert(protector.is_trusted("192.168.1.1"));
    assert(!protector.is_trusted("192.168.1.2"));
    
    assert(antiddos::game::GameProtector::is_game_query(a2s_info));
    assert(antiddos::game::GameProtector::is_game_query(a2s_player));
    assert(antiddos::game::GameProtector::is_game_query(a2s_rules));
    assert(!antiddos::game::GameProtector::is_game_query(connect_req));
    
    assert(antiddos::game::GameProtector::is_source_engine_challenge(a2s_challenge));
    
    auto game = antiddos::game::GameProtector::detect_game_from_payload(a2s_info, 27015);
    assert(game == antiddos::game::GameType::COUNTER_STRIKE_16 || game == antiddos::game::GameType::UNKNOWN);
    
    auto signatures = antiddos::game::GameProtector::get_known_signatures();
    assert(!signatures.empty());
    
    assert(antiddos::game::GameProtector::game_type_to_string(antiddos::game::GameType::HALF_LIFE) == "Half-Life");
    assert(antiddos::game::GameProtector::game_type_to_string(antiddos::game::GameType::SVEN_COOP) == "Sven Co-op");
    assert(antiddos::game::GameProtector::game_type_to_string(antiddos::game::GameType::COUNTER_STRIKE_16) == "Counter-Strike 1.6");
    assert(antiddos::game::GameProtector::game_type_to_string(antiddos::game::GameType::COUNTER_STRIKE_SOURCE) == "Counter-Strike: Source");
    
    assert(antiddos::game::GameProtector::attack_type_to_string(antiddos::game::AttackType::QUERY_FLOOD) == "Query Flood");
    assert(antiddos::game::GameProtector::attack_type_to_string(antiddos::game::AttackType::CONNECTION_FLOOD) == "Connection Flood");
    assert(antiddos::game::GameProtector::attack_type_to_string(antiddos::game::AttackType::LOGIN_FLOOD) == "Login Flood");
    
    auto stats = protector.get_stats();
    assert(stats.total_packets_analyzed > 0);
    
    std::cout << "  Game Protector: OK" << std::endl;
}

void test_asn_database() {
    std::cout << "Testing ASN Database & VPN Providers..." << std::endl;
    
    antiddos::asn::ASNDatabase db;
    
    db.block_asn(57043, "NordVPN");
    db.block_asn(57652, "NordVPN");
    assert(db.is_asn_blocked(57043));
    assert(db.is_asn_blocked(57652));
    assert(!db.is_asn_blocked(13335));
    
    db.unblock_asn(57043);
    assert(!db.is_asn_blocked(57043));
    
    assert(db.is_vpn_provider(57043));
    assert(db.is_vpn_provider(35995));
    assert(!db.is_vpn_provider(13335));
    
    antiddos::asn::VPNProvider custom;
    custom.name = "CustomVPN";
    custom.asns = {99999};
    custom.threat_score = 70;
    db.add_vpn_provider(custom);
    assert(db.is_vpn_provider(99999));
    
    db.remove_vpn_provider("CustomVPN");
    assert(!db.is_vpn_provider(99999));
    
    auto providers = db.get_vpn_providers();
    assert(!providers.empty());
    
    auto common_asns = antiddos::asn::ASNDatabase::get_common_vpn_asns();
    assert(!common_asns.empty());
    
    assert(antiddos::asn::ASNDatabase::asn_to_string(57043) == "AS57043");
    assert(antiddos::asn::ASNDatabase::string_to_asn("AS57043") == 57043);
    assert(antiddos::asn::ASNDatabase::string_to_asn("33303") == 33303);
    
    auto stats = db.get_stats();
    assert(stats.total_vpn_providers > 0);
    
    db.block_vpn_providers(true);
    assert(db.is_asn_blocked(57043));
    assert(db.is_asn_blocked(35995));
    
    std::cout << "  ASN Database: OK" << std::endl;
}

void test_attack_correlator() {
    std::cout << "Testing Attack Correlator (Cross-IP)..." << std::endl;
    
    antiddos::correlator::AttackCorrelator correlator;
    
    antiddos::correlator::CorrelatorConfig config;
    config.min_ips_for_cluster = 10;
    config.similarity_threshold = 0.3;
    config.enable_behavioral_clustering = false;
    config.enable_temporal_clustering = false;
    config.enable_campaign_tracking = false;
    config.enable_aggregate_volume = false;
    correlator.set_config(config);
    
    antiddos::correlator::BehaviorVector vec1 = 
        antiddos::correlator::AttackCorrelator::create_vector(
            0.9, 0.3, 0.95, 0.85, 0.2, 100, 5, "GET", "bot/1.0");
    
    antiddos::correlator::BehaviorVector vec2 = 
        antiddos::correlator::AttackCorrelator::create_vector(
            0.88, 0.32, 0.93, 0.87, 0.18, 95, 4, "GET", "bot/1.0");
    
    assert(vec1.is_similar(vec2, 0.3));
    
    correlator.add_snapshot("10.0.0.1", 80, vec1, true, "AS57043");
    correlator.add_snapshot("10.0.0.2", 80, vec2, true, "AS57043");
    
    auto stats = correlator.get_stats();
    assert(stats.total_snapshots == 2);
    
    auto correlated = correlator.get_correlated_ips();
    assert(correlated.size() == 2);
    
    assert(correlator.is_ip_correlated("10.0.0.1"));
    assert(!correlator.is_ip_correlated("192.168.1.100"));
    
    auto config_result = correlator.get_config();
    assert(config_result.min_ips_for_cluster == 10);
    
    correlator.reset_stats();
    auto reset_stats = correlator.get_stats();
    assert(reset_stats.total_snapshots == 0);
    
    std::cout << "  Attack Correlator: OK" << std::endl;
}

int main() {
    std::cout << "=============================================" << std::endl;
    std::cout << "  Anti-DDoS System - Unit Tests" << std::endl;
    std::cout << "=============================================" << std::endl;
    std::cout << std::endl;
    
    test_packet_engine();
    test_rate_limiter();
    test_vpn_detector();
    test_behavioral_analyzer();
    test_ml_detector();
    test_honeypot();
    test_auto_responder();
    test_threat_intel();
    test_cidr_blocking();
    test_game_protector();
    test_asn_database();
    test_attack_correlator();
    
    std::cout << std::endl;
    std::cout << "=============================================" << std::endl;
    std::cout << "  All tests passed!" << std::endl;
    std::cout << "=============================================" << std::endl;
    
    return 0;
}