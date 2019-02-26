// Copyright 2018 MaidSafe.net limited.
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

const should = require('should');
const h = require('../helpers');
const errConst = require('../../src/error_const');

describe('Experimental AD emulation', () => {
  let app;
  let md;
  let xorname;
  let ad;
  const AD_TYPE_TAG = 15555;

  before(async () => {
    app = await h.createAuthenticatedTestApp(null, null, null, { enableExperimentalApis: true });
  });

  beforeEach(async () => {
    xorname = h.createRandomXorName();
    md = await app.mutableData.newPublic(xorname, AD_TYPE_TAG);
    ad = md.emulateAs('ad');
  });

  it('fail if experimental apis flag is not set', async () => {
    let error;
    const safeApp = await h.createUnregisteredTestApp({ enableExperimentalApis: false });
    try {
      const name = h.createRandomXorName();
      const mdata = await safeApp.mutableData.newPublic(name, AD_TYPE_TAG);
      await mdata.quickSetup({});
      mdata.emulateAs('ad');
    } catch (err) {
      error = err;
    }
    return should(error.message).equal(errConst.EXPERIMENTAL_API_DISABLED.msg('AD Emulation'));
  });

  it('create AD emulation from MD', async () => {
    await md.quickSetup({});
    const rdf2 = md.emulateAs('ad');
    return should(rdf2).not.be.undefined();
  });

  it.skip('append version to AD', async () => {
    await ad.append('value-version-0');
    await ad.append('value-version-1');
  });

  it.skip('append MAX_ENTRIES+1 versions', async () => {
    await ad.append('value-version-0');
    await ad.append('value-version-1');
    await ad.append('value-version-2');
    // next append should create a second AD chunk
    await ad.append('value-version-3');
  });

  it.skip('append MAX_ENTRIES+1 versions', async () => {
    await ad.append('value-version-0');
    await ad.append('value-version-1');
    await ad.append('value-version-2');
    // next append should create a second AD chunk
    await ad.append('value-version-3');
    await ad.append('value-version-4');
    await ad.append('value-version-5');

    await ad.append('value-version-6');
    await ad.append('value-version-7');
    await ad.append('value-version-8');

    await ad.append('value-version-9');
  });

  it.only('get versions', async () => {
    const numOfVersions = 12;
    for (let v = 0; v <= numOfVersions; v++) {
      await ad.append(`value-version-${v}`);
    }

    for (let v = 0; v <= numOfVersions; v++) {
      let val = await ad.fetch(v);
      console.log("VALUE AT VERSION", v, ":", val);
    }

    console.log("Fetching latest version...");
    let val = await ad.fetch();
    console.log("VALUE AT LATEST VERSION:", val);

  }).timeout(100000);

  it.skip('fetch entries with AD emulation from empty MD', async () => {
    await md.quickSetup();
    return should(rdf.nowOrWhenFetched()).be.fulfilled();
  });
});
