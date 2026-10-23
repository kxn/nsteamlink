'use strict';
// Read-only Frida hooks for the bundled Qt5 x86_64 network notification path.
// No NativeFunction calls, replacement returns, UI actions or packet contents.
// A companion runner rejects errors/dropped events and restores guest radios.
const attached = new Set();
const metas = new Map();
const counts = {};
const getterStates = new Map();
let sequence = 0, dropped = 0;
const allowedClasses = new Set(['QtAndroidNetwork', 'QAndroidBearerEngine',
  'QNetworkConfigurationManager', 'QNetworkConfigurationManagerPrivate',
  'QNetworkAccessManager', 'CServerManagerNetworkWatcher']);
function emit(kind, values) {
  counts[kind] = (counts[kind] || 0) + 1;
  if (sequence >= 1600) { dropped++; return; }
  send({sequence: ++sequence, time_ms: Date.now(), kind, ...values});
}
function hook(address, callbacks, label) {
  const key = address.toString();
  if (attached.has(key)) return;
  try {
    Interceptor.attach(address, callbacks);
  } catch (error) {
    emit('observer_error', {where: label, error: String(error)});
    return;
  }
  attached.add(key);
  emit('hook', {label, address: key});
}
function meta(pointer) {
  const key = pointer.toString();
  if (metas.has(key)) return metas.get(key);
  try {
    const strings = pointer.add(8).readPointer(), data = pointer.add(16).readPointer();
    if (data.readU32() !== 8) return null;
    function text(index) {
      const entry = strings.add(index * 24), length = entry.add(4).readU32();
      if (length > 512) throw Error('metadata string limit');
      return entry.add(Number(entry.add(16).readS64())).readUtf8String(length);
    }
    const name = text(data.add(4).readU32());
    if (!allowedClasses.has(name)) { metas.set(key, null); return null; }
    const number = data.add(16).readU32(), offset = data.add(20).readU32(), methods = [];
    if (number > 64) return null;
    for (let i = 0; i < number; i++) {
      const entry = data.add((offset + i * 5) * 4);
      methods.push({name: text(entry.readU32()), argc: entry.add(4).readU32()});
    }
    const result = {name, methods, call: pointer.add(24).readPointer()};
    metas.set(key, result);
    return result;
  } catch (error) { return null; }
}
function scalar(method, argv) {
  if (argv.isNull() || method.argc === 0) return null;
  const value = argv.add(8).readPointer();
  if (method.name.toLowerCase().includes('online')) return value.readU8();
  if (method.name.includes('Accessible')) return value.readS32();
  return null;
}
function observeModule(module) {
  const exports = module.enumerateExports();
  if (module.name === 'libart.so') {
    const natives = exports.filter(x => x.type === 'function' && x.name.includes('15RegisterNatives'));
    for (const symbol of natives) hook(symbol.address, {onEnter(args) {
      const n = args[3].toInt32();
      if (n < 1 || n > 64) return;
      try {
        for (let i = 0; i < n; i++) {
          const entry = args[2].add(i * 24), name = entry.readPointer().readCString();
          if (name !== 'activeNetworkInfoChanged') continue;
          const signature = entry.add(8).readPointer().readCString(), fn = entry.add(16).readPointer();
          emit('jni_registration', {name, signature, function: String(fn)});
          hook(fn, {onEnter() { emit('native_network_notification', {thread: this.threadId}); }}, name);
        }
      } catch (error) { emit('observer_error', {where: 'RegisterNatives', error: String(error)}); }
    }}, symbol.name);
    emit('art_ready', {register_natives_exports: natives.length});
  }
  if (module.name.includes('Qt5Core')) {
    for (const symbol of exports) {
      if (symbol.name === 'JNI_OnLoad') hook(symbol.address, {
        onEnter(args) {
          // Observe the app's own GetEnv/RegisterNatives. Calling JNI helpers
          // ourselves could change initialization; hooking the tiny conversion
          // operator is unsupported on this exact x86 build. JNI table slots
          // are ABI-defined, not offsets inferred from the ARM64 code image.
          const getEnv = args[0].readPointer().add(6 * Process.pointerSize).readPointer();
          hook(getEnv, {
            onEnter(values) { this.output = values[1]; },
            onLeave(result) {
              if (result.toInt32() !== 0) return;
              const env = this.output.readPointer();
              const register = env.readPointer().add(215 * Process.pointerSize).readPointer();
              hook(register, {onEnter(values) {
                const n = values[3].toInt32();
                if (n < 1 || n > 64) return;
                for (let i = 0; i < n; i++) {
                  const entry = values[2].add(i * 24), name = entry.readPointer().readCString();
                  if (name !== 'activeNetworkInfoChanged') continue;
                  const signature = entry.add(8).readPointer().readCString(), fn = entry.add(16).readPointer();
                  emit('jni_registration', {name, signature, function: String(fn), via: 'JNIEnv.RegisterNatives'});
                  hook(fn, {onEnter() { emit('native_network_notification', {thread: this.threadId}); }}, name);
                }
              }}, 'JNIEnv.RegisterNatives');
            }
          }, 'JavaVM.GetEnv');
        }
      }, 'QtCore.JNI_OnLoad');
      if (symbol.name === '_ZN11QMetaObject8activateEP7QObjectPKS_iPPv') hook(symbol.address, {
        onEnter(args) {
          const info = meta(args[1]), id = args[2].toInt32();
          if (!info || id < 0 || id >= info.methods.length) return;
          const method = info.methods[id];
          emit('qt_signal', {class: info.name, method: method.name, sender: String(args[0]), value: scalar(method, args[3]), thread: this.threadId});
        }
      }, symbol.name);
      if (symbol.name === '_ZN7QObject7connectEPKS_PKcS1_S3_N2Qt14ConnectionTypeE') hook(symbol.address, {
        onEnter(args) {
          try {
            const signal = args[1].readCString();
            if (!/onlineStateChanged|networkAccessibleChanged|configurationChanged|activeNetworkChanged/.test(signal)) return;
            emit('qt_connect', {signal, slot: args[3].readCString(), sender: String(args[0]), receiver: String(args[2]), type: args[4].toInt32()});
          } catch (error) { emit('observer_error', {where: 'connect', error: String(error)}); }
        }
      }, symbol.name);
    }
  }
  if (module.name.includes('Qt5Network')) {
    for (const symbol of exports) {
      if (symbol.name === '_ZN21QNetworkAccessManager16staticMetaObjectE') {
        const info = meta(symbol.address);
        if (info) hook(info.call, {
          onEnter(args) {
            const id = args[2].toInt32();
            if (args[1].toInt32() !== 0 || id < 0 || id >= info.methods.length) return;
            const method = info.methods[id];
            if (!/^_q_(onlineStateChanged|configurationChanged|networkSession)/.test(method.name)) return;
            this.method = method.name;
            emit('nam_slot', {method: method.name, value: scalar(method, args[3]), object: String(args[0]), thread: this.threadId});
          },
          onLeave() { if (this.method) emit('nam_slot_return', {method: this.method}); }
        }, 'QNetworkAccessManager.static_metacall');
      }
      if (symbol.name === '_ZNK21QNetworkConfiguration5stateEv') hook(symbol.address, {
        onEnter(args) { this.key = String(args[0].readPointer()); },
        onLeave(value) {
          const n = value.toInt32();
          if (getterStates.get(this.key) === n) return;
          getterStates.set(this.key, n);
          emit('configuration_state', {object: this.key, value: n});
        }
      }, symbol.name);
    }
  }
  if (/^lib(main|shell.*)\.so$/.test(module.name)) {
    const relevant = exports.filter(x => x.type === 'function' &&
      (x.name.includes('CServerManager') && /BStart|HandleNetworkChanged|OnNetworkStateChanged/.test(x.name)));
    for (const symbol of relevant) hook(symbol.address, {
      onEnter(args) {
        this.name = symbol.name;
        emit('server_manager_call', {symbol: symbol.name, module: module.name, object: String(args[0]), thread: this.threadId,
          value: symbol.name.includes('OnNetworkStateChanged') ? args[1].toInt32() : null});
      },
      onLeave(value) {
        // Only BStart returns bool. The other methods return void; arbitrary
        // register contents after their return are not result/error codes.
        emit('server_manager_return', {symbol: this.name,
          result: this.name.includes('6BStartEv') ? (value.toUInt32() & 255) : null});
      }
    }, symbol.name);
    emit('steam_module_ready', {module: module.name, path: module.path, base: String(module.base), size: module.size, matching_symbols: relevant.map(x => x.name)});
  }
  if (/Qt5Network|Qt5Core|qandroidbearer/.test(module.name)) emit('qt_module_ready', {module: module.name, path: module.path, base: String(module.base), size: module.size});
}
Process.attachModuleObserver({onAdded(module) { observeModule(module); }});
rpc.exports = {snapshot() { return {counts, dropped, hooks: attached.size, pid: Process.id, arch: Process.arch}; }};
emit('ready', {pid: Process.id, arch: Process.arch});
