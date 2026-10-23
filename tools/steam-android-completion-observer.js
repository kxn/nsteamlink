/* Controlled Android completion experiment, NOT a natural streaming failure.
 * The runner verifies a fresh read-only AVD and pinned APK. Only nativeRunMain
 * is replaced: it must never enter the player or request a real Steam host.
 * Native StartStreaming gets an empty QStringList on its own Qt event thread;
 * normal Run/Quit/manager destruction precedes the original Java handoff.
 * Java Activity transitions and streamingComplete -> System.exit run original
 * code. This controlled launch bypasses host ticket admission, not teardown.
 */
'use strict';
const Java = bridge;
let shell = null;
let launched = false;
let resultCode = -1;
let count = 0;
let nativeShell = null, nativeThread = null, armed = false;
let nativeStart = null, emptyArguments = null;
function record(kind, data = {}) {
  if (++count > 1000) throw new Error('bounded event limit exceeded');
  send(Object.assign({kind, pid: Process.id, time_ms: Date.now()}, data));
}
Process.attachModuleObserver({onAdded(module) {
  // Resolving through a dlopen-backed getExportByName during loader onAdded
  // can re-enter Android's linker. Enumerate the already mapped ELF instead.
  const exported = (name) => {
    const match = module.enumerateExports().find(symbol => symbol.name === name);
    if (!match) throw new Error('missing pinned export: ' + name);
    return match.address;
  };
  if (module.name === 'libshell_x86_64.so') {
    nativeStart = new NativeFunction(exported(
      '_ZN17CShellApplication14StartStreamingERK11QStringList'), 'void', ['pointer', 'pointer']);
    for (const [symbol, name] of [
      ['_ZN17CShellApplication3RunEv', 'Run'],
      ['_ZN17CShellApplication4QuitEv', 'Quit'],
      ['_ZN14CServerManagerD2Ev', 'manager-destructor']]) {
      Interceptor.attach(exported(symbol), {
        onEnter(args) {
          record('native_shell_enter', {method: name});
          if (name === 'Run') { nativeShell = args[0]; nativeThread = this.threadId; }
        },
        onLeave() { record('native_shell_leave', {method: name}); }
      });
    }
  }
  if (module.name === 'libQt5Core_x86_64.so') {
    emptyArguments = Memory.alloc(Process.pointerSize);
    emptyArguments.writePointer(exported('_ZN9QListData11shared_nullE'));
    Interceptor.attach(exported('_ZN7QObject5eventEP6QEvent'), {
      onLeave() {
        if (!armed || this.threadId !== nativeThread) return;
        armed = false;
        record('invoke_original_native_start_streaming');
        nativeStart(nativeShell, emptyArguments);
      }
    });
  }
}});
Java.perform(function () {
  const Shell = Java.use('com.valvesoftware.steamlink.SteamShellActivity');
  const Link = Java.use('com.valvesoftware.steamlink.SteamLink');
  const SDL = Java.use('org.libsdl.app.SDL');
  const Activity = Java.use('org.libsdl.app.SDLActivity');
  const Thread = Java.use('java.lang.Thread');
  const javaStart = Shell.startStreaming.overload('[Ljava.lang.String;', 'int');
  javaStart.implementation = function (args, mode) {
    record('original_java_start_streaming', {argument_count: args.length, mode});
    return javaStart.call(this, args, mode);
  };
  for (const [cls, name] of [[Shell, 'shell'], [Link, 'player']]) {
    for (const [method, signature] of [
      ['onCreate', ['android.os.Bundle']], ['onResume', []],
      ['onPause', []], ['onDestroy', []]]) {
      const original = cls[method].overload(...signature);
      original.implementation = function (...args) {
        record('lifecycle', {activity: name, method, task: this.getTaskId()});
        const result = original.call(this, ...args);
        if (name === 'shell' && method === 'onCreate') shell = Java.retain(this);
        return result;
      };
    }
  }
  for (const name of ['setLowLatencyAudio', 'disableWiFiLock', 'streamingComplete']) {
    const method = Link[name].overloads[0];
    method.implementation = function (...args) {
      record('completion_call', {method: name, arguments: args});
      return method.call(this, ...args);
    };
  }
  const onResult = Shell.onStreamingResult.overload('int');
  onResult.implementation = function (code) {
    record('completion_result', {code});
    return onResult.call(this, code);
  };
  const exit = Java.use('java.lang.System').exit.overload('int');
  exit.implementation = function (code) {
    record('system_exit', {code});
    return exit.call(this, code);
  };
  Activity.nativeRunMain.overload('java.lang.String', 'java.lang.String', 'java.lang.Object')
    .implementation = function (library, method, args) {
      record('controlled_player_boundary', {library: String(library), method: String(method)});
      Thread.sleep(800);
      const context = SDL.getContext();
      if (context === null || context.getClass().getName().toString() !==
          'com.valvesoftware.steamlink.SteamLink')
        throw new Error('unexpected SDL context; native player remains suppressed');
      record('invoke_original_completion', {code: resultCode});
      Java.cast(context, Link).streamingComplete(resultCode);
      record('unexpected_completion_return');
      return 0;
    };
  rpc.exports = {
    snapshot() { return {ready: shell !== null && nativeShell !== null,
                         launched, events: count}; },
    launch(code) {
      if (shell === null || nativeShell === null || launched)
        throw new Error('shell not ready / already launched');
      resultCode = code;
      launched = true;
      armed = true;
    }
  };
  record('hooks_ready');
});
