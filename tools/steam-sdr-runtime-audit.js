/* Fixed Steam Link 1.3.32 x86_64; the runner verifies its ELF hash.
 * Captures contain metadata. Explicit overrides are connection ICE config 104
 * and, if requested, CNetworkTest's frame clock. No SDR selector is replaced. */
'use strict';
let forceSDR = false, timeoutHoldSeconds = 0, holdUntil = 0, faultEndpoint = '';
const states = new Map();
const samples = {
    'libshell_x86_64.so': 0x4b2ed5,
    'libmain.so': 0x3b11eb
};
rpc.exports.configure = function (force, seconds) {
    forceSDR = force;
    timeoutHoldSeconds = seconds;
    send({kind: 'configuration', force_sdr: force, frame_timeout_hold_seconds: seconds});
};
rpc.exports.armfault = function (ip, port) {
    faultEndpoint = ip + ':' + port;
    for (const state of states.values()) state.seenSources.clear();
    if (timeoutHoldSeconds) {
        holdUntil = Date.now() + 1000 * timeoutHoldSeconds;
        send({kind: 'network_test_timeout_held', seconds: timeoutHoldSeconds,
              sdr_selector_unmodified: true});
    }
};
function install(module) {
    const symbols = module.enumerateExports();
    let previousSelection = '', lastValid = 0, decoderCalls = 0, lastDecoder = 0, closeEvents = 0, stateEvents = 0;
    const seenSources = new Set(), receivingData = new Map(), hooks = [];
    states.set(module.name, {seenSources, hooks});
    const emit = event => send({module: module.name, ...event});
    const attach = (target, callbacks) => hooks.push(Interceptor.attach(target, callbacks));
    // A data packet with inline stats reaches RecvValidEndToEndPacket through
    // RecvStatsCommon and is labelled "Stats" there. Track the enclosing data
    // receive call instead of treating that reason literal as the packet type.
    attach(address('_ZN25SteamNetworkingSocketsLib26CConnectionTransportP2PSDR19RecvValidDataPacketERNS_28SDRClientRecvPacketContext_tE'), {
        onEnter() {
            this.thread = Process.getCurrentThreadId();
            receivingData.set(this.thread, (receivingData.get(this.thread) || 0) + 1);
        },
        onLeave() {
            const depth = receivingData.get(this.thread) - 1;
            if (depth) receivingData.set(this.thread, depth);
            else receivingData.delete(this.thread);
        }
    });

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
        // BSetSessionForwardTargetToken in the fixed player/shell ELFs:
        // desired POP +40h, sent POP +60h, revision +64h, ACK +68h.
        value.desired_pop = pointer.add(64).readU32();
        value.sent_pop = pointer.add(96).readU32();
        value.forward_revision = pointer.add(100).readU32();
        value.forward_acked = pointer.add(104).readU8();
        return value;
    }

    // Verified separately in both pinned x64 ELFs: peer-close/FinWait read the
    // SDK state at shell+1ad8 / player+1ac0. End reason is +1458 in both.
    // ConnectionClosed reads protobuf relay_mode+5c / reason+60. No debug text,
    // peer identifiers, or protobuf buffers are copied.
    const stateOffset = module.name === 'libmain.so' ? 0x1ac0 : 0x1ad8;
    attach(address('_ZN25SteamNetworkingSocketsLib27CSteamNetworkConnectionBase8SetStateE31ESteamNetworkingConnectionStatex'), {
        onEnter(args) {
            if (++stateEvents <= 64) emit({kind: 'sdk_state', before: args[0].add(stateOffset).readS32(),
                next: args[1].toInt32(), reason: args[0].add(0x1458).readS32()});
        }
    });
    attach(address('_ZN25SteamNetworkingSocketsLib27CSteamNetworkConnectionBase18APICloseConnectionEiPKcb'), {
        onEnter(args) {
            if (++closeEvents <= 32) emit({kind: 'api_close', reason: args[1].toInt32(),
                state: args[0].add(stateOffset).readS32(), linger: args[3].toInt32() !== 0});
        }
    });
    for (const [kind, name] of [
        ['peer_closed', '_ZN25SteamNetworkingSocketsLib27CSteamNetworkConnectionBase28ConnectionState_ClosedByPeerEiPKc'],
        ['local_problem', '_ZN25SteamNetworkingSocketsLib27CSteamNetworkConnectionBase38ConnectionState_ProblemDetectedLocallyE22ESteamNetConnectionEndPKcz'],
        ['fin_wait', '_ZN25SteamNetworkingSocketsLib27CSteamNetworkConnectionBase23ConnectionState_FinWaitEv']
    ]) attach(address(name), {
        onEnter(args) {
            this.observe = ++closeEvents <= 32;
            if (!this.observe) return;
            this.connection = args[0];
            this.before = args[0].add(stateOffset).readS32();
            this.reason = kind === 'fin_wait' ? args[0].add(0x1458).readS32() : args[1].toInt32();
        },
        onLeave() {
            if (this.observe) emit({kind: 'sdk_terminal', source: kind, reason: this.reason,
                state_before: this.before, state_after: this.connection.add(stateOffset).readS32()});
        }
    });
    attach(address('_ZN25SteamNetworkingSocketsLib27CConnectionTransportSDRBase31ProcessMessage_ConnectionClosedEPNS_12RelaySessionERK33CMsgSteamDatagramConnectionClosedix'), {
        onEnter(args) {
            if (++closeEvents <= 32) emit({kind: 'relay_closed', reason: args[2].add(0x60).readS32(),
                relay_mode: args[2].add(0x5c).readU32(), relay: relay(args[1].readPointer())});
        }
    });
    attach(address('_ZN25SteamNetworkingSocketsLib27CConnectionTransportSDRBase27ProcessMessage_NoConnectionEPNS_12RelaySessionERK29CMsgSteamDatagramNoConnectionix'), {
        onEnter(args) {
            if (++closeEvents <= 32) emit({kind: 'relay_no_connection', relay: relay(args[1].readPointer())});
        }
    });

    // The small CStreamTransportSDR getter may be inlined. Observe and modify the
    // actual configuration array received by ConnectP2PCustomSignaling instead.
    attach(address('_ZN25SteamNetworkingSocketsLib23CSteamNetworkingSockets25ConnectP2PCustomSignalingEP35ISteamNetworkingConnectionSignalingPK23SteamNetworkingIdentityiiPK28SteamNetworkingConfigValue_t'), {
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
                    emit({kind: 'ice_disabled_config', original, actual: 0});
                    found = true;
                }
            }
            if (!found) emit({kind: 'ice_override_failed', count});
        }
    });

    // cff6b6-cff6c9 compares the frame clock at +0x150. Holding only this
    // application clock keeps its owner alive for a bounded SDK-only experiment.
    if (module.name === 'libshell_x86_64.so') {
    const streamTimestamp = new NativeFunction(address('_Z18GetStreamTimestampv'), 'uint32', []);
    attach(address('_ZN12CNetworkTest17HandleNetworkTestEv'), {
        onEnter(args) {
            if (Date.now() < holdUntil) args[0].add(0x150).writeU32(streamTimestamp());
        }
    });

    }

    const ping = symbols.find(item => item.type === 'function' &&
        item.name.includes('RelayServer15SendPingRequest'));
    if (!ping) throw Error('Missing root ping export');
    attach(ping.address, {
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
            emit({kind: 'root_ping', tos: this.tos, relay: relay(this.relay),
                  pending_root_us: this.relay.add(136).readS64().toString(),
                  cluster_failures: cluster.add(552).readU32(),
                  reachability: cluster.add(560).readS32()});
        }
    });

    attach(address('_ZN25SteamNetworkingSocketsLib27CConnectionTransportSDRBase38ThinkSelectServer_SelectActiveSessionsEx'), {
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
                    emit({kind: 'selection', active: count, primary, backup,
                          controlling: this.self.add(8).readPointer().add(344).readU8()});
                }
            } catch (error) {
                emit({kind: 'read_error', where: 'selection', error: String(error)});
            }
        }
    });

    attach(address('_ZN25SteamNetworkingSocketsLib26CConnectionTransportP2PSDR23RecvValidEndToEndPacketExPKcPNS_12RelaySessionE'), {
        onEnter(args) {
            const now = Date.now();
            const category = receivingData.has(Process.getCurrentThreadId()) ? 'data' :
                args[2].equals(module.base.add(samples[module.name])) ? 'stats' : 'unknown';
            const source = args[3].toString() + ':' + category;
            if (seenSources.has(source) && now - lastValid < 250) return;
            seenSources.add(source);
            lastValid = now;
            try {
                emit({kind: 'valid_e2e', category, relay: relay(args[3].readPointer())});
            } catch (error) {
                emit({kind: 'read_error', where: 'valid', error: String(error)});
            }
        }
    });
    if (module.name === 'libmain.so') {
        attach(address('_ZN19CStreamDecoderVideo11DecodeFrameER12CStreamFrame'), {
            onEnter() {
                ++decoderCalls;
                const now = Date.now();
                if (now-lastDecoder >= 1000) {
                    lastDecoder = now;
                    emit({kind: 'video_decoder_input', calls: decoderCalls});
                }
            }
        });
    }
    emit({kind: 'module_ready', captures_only_metadata: true});
}
Process.attachModuleObserver({
    onAdded(module) {
        if (Object.hasOwn(samples, module.name)) install(module);
    },
    onRemoved(module) {
        const state = states.get(module.name);
        if (state) {
            for (const hook of state.hooks) hook.detach();
            states.delete(module.name);
        }
    }
});
send({kind: 'ready', captures_only_metadata: true});
