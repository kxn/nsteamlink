/* Actual pinned SDK parser, cert store and SetCertificate, with synthetic keys
 * and unknown/missing CA. No patches, signature bypass, HTTP or connections. */
#include <steam/steamnetworkingsockets.h>
#include <steam/isteamnetworkingutils.h>
#include "steamnetworkingsockets_messages_certs.pb.h"
#include <cassert>
#include <cstdio>
#include <ctime>
#include <string>
namespace SteamNetworkingSocketsLib {
struct CertAuthScope;
const CertAuthScope *CertStore_CheckCert(const CMsgSteamDatagramCertificateSigned &,
    CMsgSteamDatagramCertificate &, time_t, SteamNetworkingErrMsg &);
}
extern "C" void SteamNetworkingSockets_SetManualPollMode(bool);
extern "C" void sl_gns_set_steam_link_app_id();
int main() {
    SteamNetworkingSockets_SetManualPollMode(true);
    SteamNetworkingIdentity identity; identity.SetLocalHost();
    SteamNetworkingErrMsg error{};
    assert(GameNetworkingSockets_Init(&identity, error));
    SteamNetworkingUtils()->SetDebugOutputFunction(k_ESteamNetworkingSocketsDebugOutputType_None, nullptr);
    sl_gns_set_steam_link_app_id();
    // Public key for the synthetic seed bytes 0..31; independently tested in test_sns_crypto.
    const unsigned char public_key[32] = {0x03,0xa1,0x07,0xbf,0xf3,0xce,0x10,0xbe,
        0x1d,0x70,0xdd,0x18,0xe7,0x4b,0xc0,0x99,0x67,0xe4,0xd6,0x30,0x9b,0xa5,0x0d,0x5f,
        0x1d,0xdc,0x86,0x64,0x12,0x55,0x31,0xb8};
    std::string private_key; for (unsigned i = 0; i < 32; ++i) private_key += char(i);
    CMsgSteamDatagramCertificate cert;
    cert.set_key_type(CMsgSteamDatagramCertificate::ED25519);
    cert.set_key_data(public_key, sizeof(public_key)); cert.set_identity_string("str:fixture");
    cert.add_app_ids(353380); cert.set_time_created(100); cert.set_time_expiry(0xffffffff);
    for (unsigned mode = 0; mode < 3; ++mode) {
        CMsgSteamDatagramCertificateSigned signed_cert;
        signed_cert.set_cert(cert.SerializeAsString()); signed_cert.set_private_key_data(private_key);
        signed_cert.set_ca_key_id(mode == 1 ? 0 : 123);
        if (mode != 2) signed_cert.set_ca_signature(std::string(64, '\0'));
        CMsgSteamDatagramCertificate parsed;
        auto scope = SteamNetworkingSocketsLib::CertStore_CheckCert(signed_cert, parsed, 1000, error);
        assert(!scope);
        auto encoded = signed_cert.SerializeAsString();
        bool accepted = SteamNetworkingSockets()->SetCertificate(encoded.data(), int(encoded.size()), error);
        SteamNetworkingIdentity after; assert(SteamNetworkingSockets()->GetIdentity(&after));
        printf("{\"mode\":%u,\"scope\":%s,\"parsed\":%s,\"accepted\":%s,\"localhost\":%s}\n",
            mode, scope ? "true" : "false", parsed.has_key_data() ? "true" : "false",
            accepted ? "true" : "false", after.IsLocalHost() ? "true" : "false");
    }
    GameNetworkingSockets_Kill(); SteamNetworkingSockets_SetManualPollMode(false);
}
