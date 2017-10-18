const os = require('os');

const inTesting = (process.env.NODE_ENV || '').match(/dev|development|testing|test/) || typeof global.it === 'function';

const TAG_TYPE_DNS = 15001;
const TAG_TYPE_WWW = 15002;

const NET_STATE_UNKNOWN = -100;
const NET_STATE_INIT = -99;
const NET_STATE_DISCONNECTED = -1;
const NET_STATE_CONNECTED = 0;

// NFS_FILE_START and NFS_FILE_END may be used /
// with nfs.read(fileContextHandle, NFS_FILE_START, NFS_FILE_END)

/**
* @typedef {Object} CONSTANTS
* Constants available for the applications to be used in a few cases
* as values of input parameters.
*
* @param {Number} NFS_FILE_MODE_OVERWRITE NFS File open in overwrite mode.
* When used as the `openMode` parameter for `nfs.open(<fileName>, <openMode>)` the entire content
* of the file will be replaced when writing data to it.
*
* @param {Number} NFS_FILE_MODE_APPEND NFS File open in append mode.
* When used as the `openMode` param for `nfs.open(<fileName>, <openMode>)` any new content
* written to the file will be appended to the end without modifying existing data.
*
* @param {Number} NFS_FILE_MODE_READ NFS File open in read-only mode.
* When used as the `openMode` param for `nfs.open(<fileName>, <openMode>)` only the read
* operation is allowed.
*
* @param {Number} NFS_FILE_START Read the file from the beginning.
* When used as the `position` param for the NFS `file.read(<position>, <length>)`
* function, the file will be read from the beginning.
*
* @param {Number} NFS_FILE_END Read until the end of a file.
* When used as the `length` param for the NFS `file.read(<position>, <length>)`
* function, the file will be read from the position provided until the end
* of its content. E.g. if `NFS_FILE_START` and `NFS_FILE_END` are passed in as
* the `position` and `length` parameters respectively, then the whole content of the
* file will be read.
*
* @param {Number} USER_ANYONE Any user.
* When used as the `signkey` param in any of the MutableData functions to
* manipulate user permissions, like `getUserPermissions`, `setUserPermissions`,
* `delUserPermissions`, etc., this will associate the permissions operation to
* any user rather than to a particular sign key.
* E.g. if this constant is used as the `signkey` param of
* the `setUserPermissions(<signKey>, <permissionSet>, <version>)` function,
* the permissions in the `permissionSet` provided will be granted to anyone
* rather to a specific user's/aplication's sign key.
*
* @param {Number} MD_METADATA_KEY MutableData's entry key where its metadata is stored.
* The MutableData's metadata can be set either when invoking the `quickSetup`
* function or by invking the `setMetadata` function.
* The metadata is stored as an encoded entry in the MutableData which key
* is `MD_METADATA_KEY`, thus this constant can be used to realise which of the
* entries is not application's data but the MutableData's metadata instead.
* The metadata is particularly used by the Authenticator when another
* application has requested mutation permissions on a MutableData,
* displaying this information to the user, so the user can make a better
* decision to either allow or deny such a request based on it.
*/
const pubConsts = {
  NFS_FILE_MODE_OVERWRITE: 1,
  NFS_FILE_MODE_APPEND: 2,
  NFS_FILE_MODE_READ: 4,
  NFS_FILE_START: 0,
  NFS_FILE_END: 0,
  USER_ANYONE: 0,
  MD_METADATA_KEY: '_metadata',
};

const LIB_FILENAME = {
  win32: 'safe_app.dll',
  darwin: 'libsafe_app.dylib',
  linux: 'libsafe_app.so'
}[os.platform()];

const SYSTEM_URI_LIB_FILENAME = {
  win32: './system_uri.dll',
  darwin: './libsystem_uri.dylib',
  linux: './libsystem_uri.so'
}[os.platform()];

const INDEX_HTML = 'index.html';

module.exports = {
  LIB_FILENAME,
  SYSTEM_URI_LIB_FILENAME,

  TAG_TYPE_DNS,
  TAG_TYPE_WWW,

  NET_STATE_UNKNOWN,
  NET_STATE_INIT,
  NET_STATE_DISCONNECTED,
  NET_STATE_CONNECTED,

  INDEX_HTML,
  inTesting,
  pubConsts
};
