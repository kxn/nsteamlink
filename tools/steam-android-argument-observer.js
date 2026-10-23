/* Append to the pinned completion observer. Old observer stays byte-for-byte
 * unchanged for §188. Player nativeRunMain is still suppressed in EVERY PID.
 * New process CLI parsing/constructor run, but restored BInit is held before
 * any native resource/network admission. No claim of a natural media failure.
 */
resultCode = globalThis.nslArgumentResult;
Process.attachModuleObserver({onAdded(module) {
  if (module.name !== 'libshell_x86_64.so') return;
  const exports = module.enumerateExports();
  const find = name => {
    const symbol = exports.find(item => item.name === name);
    if (!symbol) throw new Error('missing pinned export ' + name);
    return symbol.address;
  };
  Interceptor.attach(find('main'), {onEnter(args) {
    const argc = args[0].toInt32();
    if (argc < 0 || argc > 64) throw new Error('argv bound');
    const argv = [];
    for (let i = 0; i < argc; i++)
      argv.push(args[1].add(i * Process.pointerSize).readPointer().readUtf8String());
    record('native_shell_argv', {argc, argv});
  }});
  Interceptor.attach(find('_ZN17CShellApplication5BInitERiPPc'), {onEnter(args) {
    record('native_binit_arguments', {
      generation: globalThis.nslArgumentGeneration,
      argc: args[1].readS32(), autoconnect: args[0].add(0x98).readU8(),
      initial_state: args[0].add(0x60).readU32()
    });
    if (globalThis.nslArgumentGeneration !== 0) {
      record('restored_binit_held');
      recv('never-release-restored-binit').wait();
      throw new Error('restored admission must never be released');
    }
  }});
}});
Java.perform(function () {
  const Activity = Java.use('org.qtproject.qt5.android.bindings.QtActivity');
  const create = Activity.onCreateHook.overload('android.os.Bundle');
  create.implementation = function (saved) {
    const intent = this.getIntent();
    const extras = intent.getExtras();
    const keys = [];
    if (extras !== null) {
      const iterator = extras.keySet().iterator();
      while (iterator.hasNext()) keys.push(iterator.next().toString());
    }
    const argument = intent.getStringExtra('applicationArguments');
    const data = intent.getDataString();
    record('shell_argument_intent', {
      task: this.getTaskId(), action: String(intent.getAction()),
      data: data === null ? null : String(data), extra_keys: keys.sort(),
      applicationArguments: argument === null ? null : String(argument),
      saved_bundle_present: saved !== null
    });
    return create.call(this, saved);
  };
  const Loader = Java.use('org.qtproject.qt5.android.bindings.QtLoader');
  const load = Loader.loadApplication.overload('android.os.Bundle');
  load.implementation = function (bundle) {
    const parameters = bundle.getString('application.parameters');
    record('qt_loader_parameters', {parameters: parameters === null ? null : String(parameters)});
    return load.call(this, bundle);
  };
  const Native = Java.use('org.qtproject.qt5.android.QtNative');
  const start = Native.startApplication.overload('java.lang.String', 'java.lang.String', 'java.lang.String');
  start.implementation = function (parameters, environment, library) {
    record('qt_native_parameters', {
      parameters: parameters === null ? null : String(parameters),
      library: library === null ? null : String(library)
    });
    return start.call(this, parameters, environment, library);
  };
  const Link = Java.use('com.valvesoftware.steamlink.SteamLink');
  const get = Link.getArguments.overload();
  get.implementation = function () {
    const args = get.call(this);
    record('player_argument_array', {args: Array.from(args, item => String(item))});
    return args;
  };
  record('argument_hooks_ready');
});
