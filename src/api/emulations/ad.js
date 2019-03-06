// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under
// the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT> or
// the Modified BSD license <LICENSE-BSD or https://opensource.org/licenses/BSD-3-Clause>,
// at your option.
//
// This file may not be copied, modified, or distributed except according to those terms.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.


const errConst = require('../../error_const');
const makeError = require('../../native/_error.js');
const { EXPOSE_AS_EXPERIMENTAL_API } = require('../../helpers');

const AD_TYPE_TAG = 15555;
const AD_METADATA = '_ad_metadata';
const AD_MAX_ENTRIES = 3; // 999;
const AD_NUM_OF_CHILDREN = 3;
const initRootADMetadata = {
  versionRangeEnd: -1,
  availableSlots: AD_MAX_ENTRIES,
  latestVersion: undefined,
  children: [],
};

/**
* Experimental AD emulation on top of a {@link MutableData}
* @hideconstructor
*/
class AD {
  constructor(mData) {
    this.rootAData = mData;
    this.rootADXorName = null;
  }

  async append(value) {
    // let's get the metadata from the root AD
    let rootADMetadata;
    let metadataVersion = -1;
    try {
      let metadata = await this.rootAData.get(AD_METADATA);
      rootADMetadata = JSON.parse(metadata.buf);
      metadataVersion = metadata.version;
    } catch (err) {
      // it's the first time this MD is used to append a version
      // we'll need to initialise the MD accordingly
      rootADMetadata = initRootADMetadata;
      if (err.code === -103) { // -103: Requested data not found
        // TODO: set insert only permissions to mimic type tag restrictions/rules/enforcement
        await this.rootAData.quickSetup({ [AD_METADATA]: JSON.stringify(rootADMetadata) });
        metadataVersion = 0;
      } else if (err.code != -106) { // -106: Requested entry not found
        // if the error is different from just missing the metadata entry, then throw
        throw err;
      }
      const { xorUrl } = await this.rootAData.getNameAndTag();
      this.rootADXorName = xorUrl;
    }

    // the root AD will now have an additional version so bump up
    // the version range value
    let updatedADMetadata = {
      ...rootADMetadata,
      versionRangeEnd: rootADMetadata.versionRangeEnd + 1,
    };

    // do we still have available slots for a new version in the root AD?
    if (rootADMetadata.availableSlots > 0) {
      // cool, we can add a new version to root AD chunk
      updatedADMetadata.availableSlots -= 1;
    } else {
      // we need to create a new AD chunk then
      let newADChunk = await this.rootAData.app.mutableData.newRandomPublic(AD_TYPE_TAG);

      // first create new AD's metadata and copy all entries
      const newADMetadata = {
        ...rootADMetadata,
        latestVersion: this.rootADXorName.xorUrl, // we can opt out from keeping a pointer to root AD
      };

      // copy all entries
      let entries = await this.rootAData.getEntries();
      let entriesList = await entries.listEntries();
      let olderVersionData = {};
      entriesList.forEach((entry) => {
        if (entry.key.toString() === AD_METADATA) {
          olderVersionData[AD_METADATA] = JSON.stringify(newADMetadata);
        } else {
          olderVersionData[entry.key] = entry.value.buf;
        }
      });
      // TODO: set insert only permissions to mimic type tag restrictions/rules/enforcement
      await newADChunk.quickSetup(olderVersionData);
      const { xorUrl: newChunkXorUrl } = await newADChunk.getNameAndTag();

      // new values for the root AD chunk metadata
      updatedADMetadata.availableSlots = AD_MAX_ENTRIES - 1;
      updatedADMetadata.children.unshift(newChunkXorUrl); // add new link to the front
      if (updatedADMetadata.children.length > AD_NUM_OF_CHILDREN) { // keep a fixed max amount of children
        updatedADMetadata.children.pop(); // remove the oldest
      }
    }

    // store new data in a new ImD
    const idWriter = await this.rootAData.app.immutableData.create();
    await idWriter.write(value);
    const cipherOpt = await this.rootAData.app.cipherOpt.newPlainText();
    const { xorUrl } = await idWriter.close(cipherOpt, true, 'text/plain'); // the Content-type is just for demo purposes

    // add link to the new ImD in the array of links within the root AD
    const mutation = await this.rootAData.app.mutableData.newMutation();
    if (updatedADMetadata.versionRangeEnd < AD_MAX_ENTRIES) {
      // we haven't ever filled it up completly yet, so it means we have to insert
      await mutation.insert(updatedADMetadata.versionRangeEnd.toString(), xorUrl);
    } else {
      // we are updating root AD versions, we need to mutate the corresponding entry
      let slotToUse = (updatedADMetadata.versionRangeEnd % AD_MAX_ENTRIES).toString();
      let slot = await this.rootAData.get(slotToUse);
      // each entry's key is not the version being linked by the entry's value,
      // but it's an offset used in conjunction with the `versionedRangeEnd` value
      await mutation.update(slotToUse, xorUrl, slot.version + 1);
    }

    // if it's the first time we populate it with AD metadata,
    // then do an insert mutation, else an update mutation is required
    if (metadataVersion >= 0) {
      await mutation.update(AD_METADATA, JSON.stringify(updatedADMetadata), metadataVersion + 1);
    } else {
      await mutation.insert(AD_METADATA, JSON.stringify(updatedADMetadata));
    }

    await this.rootAData.applyEntriesMutation(mutation);
  }

  async fetch(version) {
    const metadata = await this.rootAData.get(AD_METADATA);
    let rootADMetadata = JSON.parse(metadata.buf);
    if (version != 0 && !version) {
      version = rootADMetadata.versionRangeEnd;
    }

    if (version < 0 || version > rootADMetadata.versionRangeEnd) {
      return Error("version doesn't exist");
    }

    let curMd = this.rootAData;
    let curADMetadata = rootADMetadata;
    let hops = 1;
    // traverse the children pointers until we find the
    // chunk which contains the version we are looking for
    while (version <= curADMetadata.versionRangeEnd - AD_MAX_ENTRIES) { // while version is not in current AD chunk
      let numOfCurChildren = curADMetadata.children.length;
      let minVerImmediateChildren = numOfCurChildren * AD_MAX_ENTRIES;
      if (version <= curADMetadata.versionRangeEnd - minVerImmediateChildren) {
        // version is in last child or in any of its own children
        let oldestChild = curADMetadata.children[numOfCurChildren - 1];
        // console.log("GETTING OLDEST ->", oldestChild);
        const md = await this.rootAData.app.fetch(oldestChild);
        curMd = md.content;
      } else {
        // the version is one of the current children, jump to it and we are done traversing
        let pickedChildIndex = Math.floor((curADMetadata.versionRangeEnd - version) / AD_MAX_ENTRIES) - 1;
        let pickedChild = curADMetadata.children[pickedChildIndex];
        // console.log("GETTING CHILD #", pickedChildIndex,"->", pickedChild);
        const md = await this.rootAData.app.fetch(pickedChild);
        curMd = md.content;
      }
      hops += 1;
      // let's get the metadata for the current AD chunk
      const metadata = await curMd.get(AD_METADATA);
      curADMetadata = JSON.parse(metadata.buf);
    }
    // console.log("NUMBER OF HOPS MADE:", hops)

    // ok, we have the AD chunk which holds the version we are looking for,
    // let's just find out the offset to know which entry holds the link to the data
    const slotToFetch = (version % AD_MAX_ENTRIES).toString();
    let value = await curMd.get(slotToFetch);
    // and finally fetch the ImmD content
    const imd = await this.rootAData.app.fetch(value.buf.toString());
    const idData = await imd.content.read();
    return idData.toString();
  }
}

class adEmulationFactory {
  /**
  * @private
  * Instantiate the AD emulation layer wrapping a MutableData instance,
  * hiding the whole AD emulation class behind the experimental API flag
  *
  * @param {MutableData} mData the MutableData to wrap around
  */
  constructor(mData) {
    /* eslint-disable camelcase, prefer-arrow-callback */
    return EXPOSE_AS_EXPERIMENTAL_API.call(mData.app, function AD_Emulation() {
      return new AD(mData);
    });
  }
}

module.exports = adEmulationFactory;
