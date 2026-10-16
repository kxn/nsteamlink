/* Fixed Steam Link 1.3.32 x86_64; the runner verifies its ELF hash.
 * Captures contain metadata. Explicit overrides are connection ICE config 104
 * and, if requested, CNetworkTest's frame clock. No SDR selector is replaced. */
'use strict';
const module = Process.getModuleByName('libshell_x86_64.so');
const symbols = module.enumerateExports();
let forceSDR = false, timeoutHoldSeconds = 0, holdUntil = 0, faultEndpoint = '';
let previousSelection = '', lastValid = 0;
const seenSources = new Set();

function address(name) {
    const symbol = symbols.find(item => item.type === 'function' && item.name === name);
    if (!symbol) throw Error('Missing export: ' + name);
    return symbol.address;
}

function relay(pointer) {
    if (pointer.add(28).readU16() !== 3) throw Error('Unsupported relay address family');
    const ipv4 = pointer.add(8).readU32();
    const cluster = pointer.add(32).readPointer();
    return {
        ip: [24, 16, 8, 0].map(bit => (ipv4 >>> bit) & 255).join('.'),
        port: pointer.add(30).readU16(),
        pop: cluster.add(8).readPointer().add(8).readU32(),
        failures: pointer.add(256).readU32()
    };
}

function sessionInfo(pointer) {
    const value = relay(pointer.readPointer());
    value.session_failures = pointer.add(4136).readU32();
    return value;
}

rpc.exports.configure = function (force, seconds) {
    forceSDR = force;
    timeoutHoldSeconds = seconds;
    send({kind: 'configuration', force_sdr: force, frame_timeout_hold_seconds: seconds});
};
rpc.exports.armfault = function (ip, port) {
    faultEndpoint = ip + ':' + port;
    seenSources.clear();
    if (timeoutHoldSeconds) {
        holdUntil = Date.now() + 1000 * timeoutHoldSeconds;
        send({kind: 'network_test_timeout_held', seconds: timeoutHoldSeconds,
              sdr_selector_unmodified: true});
    }
};

// The small CStreamTransportSDR getter may be inlined. Observe and modify the
// actual configuration array received by ConnectP2PCustomSignaling instead.
Interceptor.attach(address('_ZN25SteamNetworkingSocketsLib23CSteamNetworkingSockets25ConnectP2PCustomSignalingEP35ISteamNetworkingConnectionSignalingPK23SteamNetworkingIdentityiiPK28SteamNetworkingConfigValue_t'), {
    onEnter(args) {
        if (!forceSDR) return;
        const count = args[4].toInt32(), values = args[5];
        if (count < 0 || count > 32) throw Error('Invalid configuration count');
        let found = false;
        for (let i = 0; i < count; ++i) {
            const value = values.add(i * 16);
            if (value.readU32() === 104 && value.add(4).readU32() === 1) {
                const original = value.add(8).readS32();
                value.add(8).writeS32(0);
                send({kind: 'ice_disabled_config', original, actual: 0});
                found = true;
            }
        }
        if (!found) send({kind: 'ice_override_failed', count});
    }
});

// cff6b6-cff6c9 compares the frame clock at +0x150. Holding only this
// application clock keeps its owner alive for a bounded SDK-only experiment.
const streamTimestamp = new NativeFunction(address('_Z18GetStreamTimestampv'), 'uint32', []);
Interceptor.attach(address('_ZN12CNetworkTest17HandleNetworkTestEv'), {
    onEnter(args) {
        if (Date.now() < holdUntil) args[0].add(0x150).writeU32(streamTimestamp());
    }
});

const ping = symbols.find(item => item.type === 'function' &&
    item.name.includes('RelayServer15SendPingRequest'));
if (!ping) throw Error('Missing root ping export');
Interceptor.attach(ping.address, {
    onEnter(args) {
        this.observe = false;
        if (!faultEndpoint) return;
        this.relay = args[0];
        const value = relay(this.relay);
        this.observe = faultEndpoint === value.ip + ':' + value.port;
        this.tos = args[5].toInt32();
    },
    onLeave() {
        if (!this.observe) return;
        const cluster = this.relay.add(32).readPointer();
        send({kind: 'root_ping', tos: this.tos, relay: relay(this.relay),
              pending_root_us: this.relay.add(136).readS64().toString(),
              cluster_failures: cluster.add(552).readU32(),
              reachability: cluster.add(560).readS32()});
    }
});

Interceptor.attach(address('_ZN25SteamNetworkingSocketsLib27CConnectionTransportSDRBase38ThinkSelectServer_SelectActiveSessionsEx'), {
    onEnter(args) { this.self = args[0]; },
    onLeave() {
        try {
            const count = this.self.add(36).readU32();
            if (count > 2) throw Error('Unsupported active-session count');
            const primary = count >= 1 ? sessionInfo(this.self.add(20).readPointer()) : null;
            const backup = count === 2 ? sessionInfo(this.self.add(28).readPointer()) : null;
            const value = JSON.stringify({active: count, primary, backup});
            if (value !== previousSelection) {
                previousSelection = value;
                send({kind: 'selection', active: count, primary, backup,
                      controlling: this.self.add(8).readPointer().add(344).readU8()});
            }
        } catch (error) {
            send({kind: 'read_error', where: 'selection', error: String(error)});
        }
    }
});

Interceptor.attach(address('_ZN25SteamNetworkingSocketsLib26CConnectionTransportP2PSDR23RecvValidEndToEndPacketExPKcPNS_12RelaySessionE'), {
    onEnter(args) {
        const now = Date.now(), source = args[3].toString();
        if (seenSources.has(source) && now - lastValid < 250) return;
        seenSources.add(source);
        lastValid = now;
        try {
            send({kind: 'valid_e2e', relay: relay(args[3].readPointer())});
        } catch (error) {
            send({kind: 'read_error', where: 'valid', error: String(error)});
        }
    }
});
send({kind: 'ready', captures_only_metadata: true});
