/* Real per-player SDK/bridge ownership. Network-config import, CA/signature and
 * parsed-body result and a failed initial SDK allocation are explicit providers.
 * Successful certificate verification/network/media are not claimed. */
#include "../platforms/common/sns_backend.cpp"
#include <cassert>
#include <iostream>
#include "steamnetworkingsockets_messages_certs.pb.h"
static bool init_ok=true, network_ok=true, certificate_ok=true;
static unsigned init_calls, kill_calls, imports, certificates;
static std::string pending;
extern "C" bool __real_GameNetworkingSockets_Init(const SteamNetworkingIdentity *, SteamNetworkingErrMsg &);
extern "C" bool __wrap_GameNetworkingSockets_Init(const SteamNetworkingIdentity *id, SteamNetworkingErrMsg &err) {
    ++init_calls;
    return init_ok && __real_GameNetworkingSockets_Init(id, err);
}
extern "C" void __real_GameNetworkingSockets_Kill();
extern "C" void __wrap_GameNetworkingSockets_Kill() { ++kill_calls; __real_GameNetworkingSockets_Kill(); }
extern "C" bool __wrap_sl_gns_import_trust(const char *, size_t) {
    ++imports; if(network_ok) pending.clear(); return network_ok;
}
namespace SteamNetworkingSocketsLib { struct CertAuthScope; }
extern "C" const SteamNetworkingSocketsLib::CertAuthScope *
__wrap__ZN25SteamNetworkingSocketsLib19CertStore_CheckCertERK34CMsgSteamDatagramCertificateSignedR28CMsgSteamDatagramCertificatelRA1024_c(
    const CMsgSteamDatagramCertificateSigned &in, CMsgSteamDatagramCertificate &out,
    time_t, SteamNetworkingErrMsg &) {
    ++certificates;
    if(certificate_ok) assert(out.ParseFromString(in.cert()));
    else out.Clear();
    // Explicit parsed-body/null-scope provider (e.g. late expiry), not an
    // unknown CA that the real cert store would reject before parsing.
    return nullptr;
}
static std::string synthetic_cert(bool alternate=false, const char *identity="str:fixture") {
    const unsigned char pub[32]={0x03,0xa1,0x07,0xbf,0xf3,0xce,0x10,0xbe,
        0x1d,0x70,0xdd,0x18,0xe7,0x4b,0xc0,0x99,0x67,0xe4,0xd6,0x30,0x9b,0xa5,0x0d,0x5f,
        0x1d,0xdc,0x86,0x64,0x12,0x55,0x31,0xb8};
    const unsigned char other_pub[32]={0x29,0xac,0xba,0xe1,0x41,0xbc,0xca,0xf0,
        0xb2,0x2e,0x1a,0x94,0xd3,0x4d,0x0b,0xc7,0x36,0x1e,0x52,0x6d,0x0b,0xfe,0x12,0xc8,
        0x97,0x94,0xbc,0x93,0x22,0x96,0x6d,0xd7};
    CMsgSteamDatagramCertificate cert;
    cert.set_key_type(CMsgSteamDatagramCertificate::ED25519);
    cert.set_key_data(alternate ? other_pub : pub,32);
    cert.set_identity_string(identity);cert.add_app_ids(353380);
    cert.set_time_created(100);cert.set_time_expiry(0xffffffff);
    CMsgSteamDatagramCertificateSigned signed_cert;signed_cert.set_cert(cert.SerializeAsString());
    std::string key;for(unsigned i=0;i<32;++i)key+=char(i+(alternate ? 32 : 0));
    signed_cert.set_private_key_data(key);signed_cert.set_ca_key_id(123);
    signed_cert.set_ca_signature(std::string(64,'\0'));
    auto binary=signed_cert.SerializeAsString();
    std::vector<unsigned char> out((binary.size()+2)/3*4+1);size_t size=0;
    assert(!mbedtls_base64_encode(out.data(),out.size(),&size,
        reinterpret_cast<const unsigned char *>(binary.data()),binary.size()));
    return std::string(reinterpret_cast<const char *>(out.data()),size);
}
int main() {
    assert(curl_global_init(CURL_GLOBAL_DEFAULT)==CURLE_OK);
    uint8_t secret[32]{};
    IHS_ClientConfig c{};c.deviceId=42;c.secretKey=secret;
    sl_remote_material material{};material.client_id=123;material.steam_id=456;
    material.transport=4;material.key_size=32;
    int init,network,certificate,decode,has_cert,stun,webrtc,generation;
    std::string data;
    while(std::cin>>init>>network>>certificate>>decode>>has_cert>>stun>>webrtc>>generation>>data) {
        (void)webrtc; // Native GNS ICE is a separate implementation boundary.
        init_ok=init;network_ok=network;certificate_ok=certificate;
        pending=data=="-" ? std::string{} : data;
        auto cert=synthetic_cert(generation!=0,generation ? "str:next-player" : "str:fixture");
        material.cert=has_cert==2 ? "" : has_cert ? (decode ? cert.c_str() : "?") : nullptr;
        material.stun_servers=stun ? "stun:fixture.invalid" : nullptr;
        assert(!sdk_owned);
        char error[256]{};
        auto b=sl_sns_create_configured(&c,&material,true,error,sizeof(error),pending.data(),pending.size());
        bool result=b!=nullptr;
        if(b) assert(b->config_ready && !b->connection && !b->request);
        sl_sns_destroy(b);
        assert(!sdk_owned);
        printf("{\"result\":%s,\"initialized\":%s,\"initializations\":%u,\"destructions\":%u,"
               "\"imports\":%u,\"certificates\":%u,\"pending\":\"%s\"}\n",
               result?"true":"false",SteamNetworkingSockets()?"true":"false",
               init_calls,kill_calls,imports,certificates,pending.c_str());
    }
    // Defensive fixture cleanup also makes a deliberately missing-Kill mutant
    // exit normally; the comparison, rather than a crash/leak, must reject it.
    __real_GameNetworkingSockets_Kill();SteamNetworkingSockets_SetManualPollMode(false);
    curl_global_cleanup();puts("{\"clean\":true}");
}
