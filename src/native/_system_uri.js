const path = require('path');
const FFI = require('ffi');

const dir = path.dirname(__filename);

const h = require('./helpers');
const t = require('./types');
const makeFfiString = h.makeFfiString;

console.log(t.FfiString)

const ffi = FFI.Library(path.join(dir, 'libsystem_uri'), {
  open: [t.i32, [t.FfiString] ],
  install: [t.i32, [t.FfiString, //bundle
                    t.FfiString, //exec
                    t.FfiString, //vendor
                    t.FfiString, //name
                    t.FfiString, //icon
                    t.FfiString, //schemes
                    ] ],
});

function openUri(str) {
  const ret = ffi.open(makeFfiString(str));
  if (!ret) {
    throw new Error("Error occured opening " + str + " : " + ret);
  }
}


function registerUriScheme(appInfo, schemes) {
  const bundle = makeFfiString(appInfo.bundle || appInfo.id);
  const exec = makeFfiString(appInfo.exec ? appInfo.exec : process.execPath);
  const vendor = makeFfiString(appInfo.vendor);
  const name = makeFfiString(appInfo.name);
  const icon = makeFfiString(appInfo.icon);
  const joinedSchemes = makeFfiString(schemes.join ? schemes.join(',') : schemes);

  const ret = ffi.install(bundle, exec, vendor, name, icon, joinedSchemes);
  if (!ret) {
    throw new Error("Error occured installing: " + ret);
  }

}

// FIXME: As long as `safe-app` doesn't expose system uri itself, we'll
// patch it directly on it. This should later move into its own sub-module
// and take care of mobile support for other platforms, too.
module.exports = function(other) {
  other.openUri = openUri;
  other.registerUriScheme = registerUriScheme;
}
