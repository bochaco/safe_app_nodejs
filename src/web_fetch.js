const consts = require('./consts');
const errConst = require('./error_const');
const makeError = require('./native/_error.js');
const { parse: parseUrl } = require('url');
const mime = require('mime');
const nodePath = require('path');
const multihash = require('multihashes');
const CID = require('cids');

const MIME_TYPE_BYTERANGES = 'multipart/byteranges';
const MIME_TYPE_OCTET_STREAM = 'application/octet-stream';
const MIME_TYPE_JSON = 'application/json';
const HEADERS_CONTENT_TYPE = 'Content-Type';
const HEADERS_CONTENT_LENGTH = 'Content-Length';
const HEADERS_CONTENT_RANGE = 'Content-Range';

// Helper function to fetch the Container
// treating the public ID container as an RDF
async function readPublicIdAsRdf(servicesContainer, pubName, servName) {
  let serviceMd;
  try {
    const graphId = `safe://${servName}.${pubName}`;

    const rdfEmulation = await servicesContainer.emulateAs('rdf');
    await rdfEmulation.nowOrWhenFetched([graphId]);
    const SAFETERMS = rdfEmulation.namespace('http://safenetwork.org/safevocab/');
    let match = rdfEmulation.statementsMatching(rdfEmulation.sym(graphId), SAFETERMS('xorName'), undefined);
    const xorName = match[0].object.value.split(',');
    match = rdfEmulation.statementsMatching(rdfEmulation.sym(graphId), SAFETERMS('typeTag'), undefined);
    const typeTag = match[0].object.value;
    serviceMd = await this.mutableData.newPublic(xorName, parseInt(typeTag, 10));
  } catch (err) {
    const error = {};
    error.code = errConst.ERR_SERVICE_NOT_FOUND.code;
    error.message = errConst.ERR_SERVICE_NOT_FOUND.msg;
    throw makeError(error.code, error.message);
  }

  return { serviceMd, type: 'RDF' };
}

// Helper function to fetch the Container
// from a public ID and service name provided
async function getContainerFromPublicId(pubName, servName) {
  let servicesContainer;
  let serviceInfo;

  try {
    const address = await this.crypto.sha3Hash(pubName);
    servicesContainer = await this.mutableData.newPublic(address, consts.TAG_TYPE_DNS);
    serviceInfo = await servicesContainer.get(servName || 'www'); // default it to www
  } catch (err) {
    if (err.code === errConst.ERR_NO_SUCH_DATA.code) {
      // there is no container stored at the location
      throw makeError(errConst.ERR_CONTENT_NOT_FOUND.code, errConst.ERR_CONTENT_NOT_FOUND.msg);
    } else if (err.code === errConst.ERR_NO_SUCH_ENTRY.code) {
      // Let's then try to read it as an RDF container
      return readPublicIdAsRdf.call(this, servicesContainer, pubName, servName);
    }
    throw err;
  }

  if (serviceInfo.buf.length === 0) {
    throw makeError(errConst.ERR_SERVICE_NOT_FOUND.code, errConst.ERR_SERVICE_NOT_FOUND.msg);
  }

  let serviceMd;
  try {
    serviceMd = await this.mutableData.fromSerial(serviceInfo.buf);
  } catch (e) {
    serviceMd = await this.mutableData.newPublic(serviceInfo.buf, consts.TAG_TYPE_WWW);
  }

  return { serviceMd, type: 'NFS' };
}

// Helper function to try different paths to find and
// fetch the index file from a web site container
const tryDifferentPaths = async (fetchFn, initialPath) => {
  const handleNfsFetchException = (error) => {
    // only if it's an unexpected error throw it
    if (error.code !== errConst.ERR_FILE_NOT_FOUND.code) {
      throw error;
    }
  };

  let file;
  let filePath;
  try {
    filePath = initialPath;
    file = await fetchFn(filePath);
  } catch (e) {
    handleNfsFetchException(e);
  }
  if (!file && initialPath.startsWith('/')) {
    try {
      filePath = initialPath.replace('/', '');
      file = await fetchFn(filePath);
    } catch (e) {
      handleNfsFetchException(e);
    }
  }
  if (!file && initialPath.split('/').length > 1) {
    try {
      filePath = `${initialPath}/${consts.INDEX_HTML}`;
      file = await fetchFn(filePath);
    } catch (e) {
      handleNfsFetchException(e);
    }
  }
  if (!file) {
    try {
      filePath = `${initialPath}/${consts.INDEX_HTML}`.replace('/', '');
      file = await fetchFn(filePath);
    } catch (error) {
      if (error.code !== errConst.ERR_FILE_NOT_FOUND.code) {
        throw error;
      }
      throw makeError(error.code, errConst.ERR_FILE_NOT_FOUND.msg);
    }
  }

  const mimeType = mime.getType(nodePath.extname(filePath));
  return { file, mimeType };
};

// Helper function to read the file's content, and return an
// http compliant response based on the mime-type and options provided
const readContentFromFile = async (openedFile, defaultMimeType, opts) => {
  let mimeType = defaultMimeType;
  if (!mimeType) {
    mimeType = MIME_TYPE_OCTET_STREAM;
  }
  let range;
  let start = consts.pubConsts.NFS_FILE_START;
  let end;
  let fileSize;
  let lengthToRead = consts.pubConsts.NFS_FILE_END;
  let endByte;
  let data;
  let multipart;

  if (opts && opts.range) {
    fileSize = await openedFile.size();
    range = opts.range;
    const rangeIsArray = Array.isArray(range);
    multipart = rangeIsArray && range.length > 1;
    start = range.start || consts.pubConsts.NFS_FILE_START;
    end = range.end || fileSize - 1;
    if (rangeIsArray && range.length === 1) {
      start = range[0].start || consts.pubConsts.NFS_FILE_START;
      end = range[0].end || fileSize - 1;
    }
    lengthToRead = (end - start) + 1; // account for 0 index
  }

  if (opts && opts.range && multipart) {
    // handle the multipart range requests
    data = await Promise.all(range.map(async (part) => {
      const partStart = part.start || consts.pubConsts.NFS_FILE_START;
      const partEnd = part.end || fileSize - 1;
      const partLengthToRead = (partEnd - partStart) + 1; // account for 0 index
      const byteSegment = await openedFile.read(partStart, partLengthToRead);
      return {
        body: byteSegment,
        headers: {
          [HEADERS_CONTENT_TYPE]: mimeType,
          [HEADERS_CONTENT_RANGE]: `bytes ${partStart}-${partEnd}/${fileSize}`
        }
      };
    }));
  } else {
    // handles non-partial requests and also single partial content requests
    data = await openedFile.read(start, lengthToRead);
  }

  if (multipart) {
    mimeType = MIME_TYPE_BYTERANGES;
  }

  const response = {
    headers: {
      [HEADERS_CONTENT_TYPE]: mimeType
    },
    body: data
  };

  if (range && multipart) {
    response.headers[HEADERS_CONTENT_LENGTH] = JSON.stringify(data).length;
    delete response.body;
    response.parts = data;
  } else if (range) {
    endByte = (end === fileSize - 1) ? fileSize - 1 : end;
    response.headers[HEADERS_CONTENT_LENGTH] = lengthToRead;
    response.headers[HEADERS_CONTENT_RANGE] = `bytes ${start}-${endByte}/${fileSize}`;
  }
  return response;
};

// Helper function to fetch the Container/content from a CID
async function getContainerFromCid(cidString, typeTag) {
  let content;
  let type;
  let codec;
  try {
    // console.log('CID STR:', cidString);
    const cid = new CID(cidString);
    // console.log('CID:', cid);
    const encodedHash = multihash.decode(cid.multihash);
    const address = encodedHash.digest;
    codec = cid.codec;
    if (typeTag) {
      // it's supposed to be a MutableData
      // console.log('VALID MD CID - MULTIHASH:', address);
      content = await this.mutableData.newPublic(address, typeTag);
      await content.getEntries();
      type = 'MD';
    } else {
      // then it's supposed to be an ImmutableData
      // console.log('VALID ImmD CID - MULTIHASH:', address);
      content = await this.immutableData.fetch(address);
      type = 'ImmD';
    }
  } catch (err) {
    // only if it was looking up specifically for a MD thru a CID
    // we report it as failing to find content
    if (typeTag && err.code === errConst.ERR_NO_SUCH_DATA.code) {
      throw makeError(errConst.ERR_CONTENT_NOT_FOUND.code, errConst.ERR_CONTENT_NOT_FOUND.msg);
    }
    // it's not a valid CID then
    throw err;
  }

  return { content, type, codec };
}

async function fetch(url) {
  if (!url) return Promise.reject(makeError(errConst.MISSING_URL.code, errConst.MISSING_URL.msg));

  const parsedUrl = parseUrl(url);
  if (!parsedUrl.protocol) return Promise.reject(makeError(errConst.INVALID_URL.code, `${errConst.INVALID_URL.msg}, complete with protocol.`));

  // let's decompose and normalise the path
  const originalPath = parsedUrl.pathname;
  let path = originalPath ? decodeURI(originalPath) : '';
  const tokens = path.split('/');
  if (!tokens[tokens.length - 1] && tokens.length > 1) {
    tokens.pop();
    tokens.push(consts.INDEX_HTML);
  }
  path = tokens.join('/') || `/${consts.INDEX_HTML}`;

  // let's decompose the hostname
  const hostname = parsedUrl.hostname;
  const hostParts = hostname.split('.');
  const publicName = hostParts.pop(); // last one is 'domain'
  const serviceName = hostParts.join('.'); // all others are 'service'

  if (serviceName.length === 0) {
    // this could be a CID URL,
    // let's first try to decode the publicName as a CID
    try {
      const content = await getContainerFromCid.call(this, publicName,
                                                      parseInt(parsedUrl.port, 10));
      if (content.type === 'MD') {
        // console.log('MD FOUND');
        return {
          content: content.content,
          type: 'NFS',
          path,
          originalPath,
          mimeType: content.codec
        };
      }
      // content.type === 'ImmD'
      // console.log('ImmD FOUND');
      // we simply then return the ImmD object so the content can be read
      return {
        content: content.content,
        type: 'ImmD',
        // path: we ignore any path provided as it's a file
        originalPath,
        mimeType: content.codec
      };
    } catch (err) {
      if (err.code === errConst.ERR_CONTENT_NOT_FOUND.code) {
        // it was meant to be found as a CID but content wasn't found,
        // so let's throw the error
        throw (err);
      }
      // then just fallback to public name lookup
    }
  }

  // Let's then try to find the container by a public name lookup
  // and read its content using the helpers functions
  const md = await getContainerFromPublicId.call(this, publicName, serviceName);
  return {
    content: md.serviceMd,
    type: md.type,
    path,
    originalPath,
    mimeType: null
  };
}

/**
* @typedef {Object} WebFetchOptions
* holds additional options for the `webFetch` function.
* @param {Object} range range of bytes to be retrieved.
* The `start` attribute is expected to be the start offset, while the
* `end` attribute of the `range` object the end position (both inclusive)
* to be retrieved, e.g. with `range: { start: 2, end: 3 }` the 3rd
* and 4th bytes of data will be retrieved.
* If `end` is not specified, the bytes retrived will be from the `start` offset
* untill the end of the file.
* The ranges values are also used to populate the `Content-Range` and
* `Content-Length` headers in the response.
*/

/**
* Helper to lookup a given `safe://`-url in accordance with the
* convention and find the requested object.
*
* @param {String} url the url you want to fetch
* @param {WebFetchOptions} [options=null] additional options
* @returns {Promise<Object>} the object with body of content and headers
*/
async function webFetch(url, options) {
  const { content, type, path, originalPath, mimeType } = await fetch.call(this, url);
  if (type === 'RDF') {
    const emulation = await content.emulateAs('RDF');
    await emulation.nowOrWhenFetched();

    // TODO: support qvalue in the Accept header with multile mime types and weights
    const reqMimeType = (options && options.accept) ? options.accept : 'text/turtle';

    const serialisedRdf = await emulation.serialise(reqMimeType);
    const response = {
      headers: {
        [HEADERS_CONTENT_TYPE]: reqMimeType,
        //'Accept-Post': 'text/turtle, application/ld+json, application/rdf+xml, application/nquads'
      },
      body: serialisedRdf
    };
    return response;
  } else if (type === 'ImmD') {
    const data = await readContentFromFile(content, mimeType, options);
    return data;
  }

  // then it's expected to be an NFS container
  try {
    const emulation = await content.emulateAs('NFS');
    const { file, mimeType: fileMimeType } =
                      await tryDifferentPaths(emulation.fetch.bind(emulation), path);
    const openedFile = await emulation.open(file, consts.pubConsts.NFS_FILE_MODE_READ);
    const data = await readContentFromFile(openedFile, fileMimeType, options);
    return data;
  } catch (err) {
    if (originalPath) {
      // it was meant to fetch a path so throw the error
      throw (err);
    }

    // then let's just return it as a raw list of MutableData's entries
    const entries = await content.getEntries();
    const entriesList = await entries.listEntries();
    const mdObj = {};
    // TODO: confirm this will be ok for any type of data stored in MD entries,
    // e.g. binary data or different charset encodings, etc.
    entriesList.forEach((entry) => {
      const key = entry.key.toString();
      const value = entry.value.buf.toString();
      const version = entry.value.version;
      mdObj[key] = { value, version };
    });

    const response = {
      headers: {
        [HEADERS_CONTENT_TYPE]: MIME_TYPE_JSON
      },
      body: mdObj
    };
    return response;
  }
}

module.exports = {
  fetch,
  webFetch,
  getContainerFromPublicId,
  tryDifferentPaths,
  readContentFromFile
};
