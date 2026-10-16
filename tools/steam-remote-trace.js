/* Observe the supplied official Steam Link sample; never replace return values.
 * Only control/signaling buffers are captured. The runner stores them privately.
 */
'use strict';

const sendDepth = new Map();
const receiveDepth = new Map();
const attached = new Set();
let frames = 0;
const maxFrames = 512;
const maxBytes = 65536;

function scope(map, symbol, module) {
    Interceptor.attach(symbol.address, {
        onEnter() {
            map.set(this.threadId, (map.get(this.threadId) || 0) + 1);
        },
        onLeave() {
            const depth = (map.get(this.threadId) || 1) - 1;
            if (depth === 0) map.delete(this.threadId);
            else map.set(this.threadId, depth);
        }
    });
    send({kind: 'hook', module: module.name, symbol: symbol.name});
}

function capture(direction, channel, pointer, size, module) {
    if (frames >= maxFrames) {
        if (frames === maxFrames) send({kind: 'capture_budget_exhausted', max_frames: maxFrames});
        frames++;
        return;
    }
    if (size < 0 || size > maxBytes) {
        send({kind: 'capture_rejected', direction, channel, size});
        return;
    }
    frames++;
    try {
        send({kind: 'wire', direction, channel, size, module: module.name},
             pointer.readByteArray(size));
    } catch (error) {
        send({kind: 'capture_error', message: String(error)});
    }
}

function install(module) {
    if (!/^lib(main|shell.*)\.so$/.test(module.name) || attached.has(module.path)) return;
    attached.add(module.path);
    const exports = module.enumerateExports();
    function find(part) {
        return exports.find(item => item.type === 'function' && item.name.includes(part));
    }
    const sender = find('CRemoteClientSession13SendWebSocket');
    const receiver = find('CRemoteClientSession22HandleWebSocketPackets');
    const clientVtable = exports.find(item => item.name.startsWith('_ZTV') &&
                                           item.name.endsWith('CCMRemoteClient_ClientMessage'));
    const serverVtable = exports.find(item => item.name.startsWith('_ZTV') &&
                                           item.name.endsWith('CCMRemoteClient_ServerMessage'));
    function hasVtable(object, symbol) {
        return symbol !== undefined && object.readPointer().equals(
            symbol.address.add(Process.pointerSize * 2));
    }
    if (sender) scope(sendDepth, sender, module);
    if (receiver) scope(receiveDepth, receiver, module);
    const serialize = find('SerializeWithCachedSizesToArray');
    if (serialize) Interceptor.attach(serialize.address, {
        onEnter(args) {
            this.active = sendDepth.has(this.threadId) && hasVtable(args[0], clientVtable);
            this.buffer = args[1];
        },
        onLeave(end) {
            if (this.active) capture('out', 'cm', this.buffer,
                                     end.sub(this.buffer).toInt32(), module);
        }
    });
    const parse = find('MessageLite14ParseFromArray');
    if (parse) Interceptor.attach(parse.address, {
        onEnter(args) {
            this.active = receiveDepth.has(this.threadId) && hasVtable(args[0], serverVtable);
            this.buffer = args[1];
            this.size = args[2].toInt32();
        },
        onLeave(ok) {
            if (this.active && ok.toInt32()) capture('in', 'cm', this.buffer, this.size, module);
        }
    });
    const packet = find('CRemoteClientSession11SendMessage');
    if (packet) Interceptor.attach(packet.address, {
        onEnter(args) {
            capture('out', 'remote_packet', args[2], args[3].toInt32(), module);
        }
    });
    const reply = find('CServerManager13OnReplyPacket');
    if (reply) Interceptor.attach(reply.address, {
        onEnter(args) {
            capture('in', 'remote_packet', args[1], args[2].toInt32(), module);
        }
    });
    for (const part of ['CRemoteClientSession12StartPairing',
                        'CRemoteClientSession13CancelPairing',
                        'CRemoteClientSession14SetPairingInfo',
                        'CRemoteClientSession24RegisterForStatusUpdates']) {
        const symbol = find(part);
        if (symbol) Interceptor.attach(symbol.address, {
            onEnter() { send({kind: 'call', module: module.name, symbol: symbol.name}); }
        });
    }
    const relay = find('CStreamTransportSDR11BUsingRelay');
    let previousRelay;
    if (relay) Interceptor.attach(relay.address, {
        onLeave(value) {
            const usingRelay = !!value.toInt32();
            if (usingRelay !== previousRelay) {
                previousRelay = usingRelay;
                send({kind: 'relay_observation', using_relay: usingRelay, module: module.name});
            }
        }
    });
    send({kind: 'module_ready', module: module.name, base: String(module.base),
          websocket_send: !!sender, websocket_receive: !!receiver,
          serializer: !!serialize, parser: !!parse,
          client_vtable: !!clientVtable, server_vtable: !!serverVtable});
}

Process.attachModuleObserver({onAdded(module) { install(module); }});
send({kind: 'ready', pid: Process.id, arch: Process.arch,
      max_frames: maxFrames, max_frame_bytes: maxBytes});
