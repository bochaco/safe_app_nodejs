const safeApp = require('../../../src/index.js');
const { waitUntil } = require('wait');
const { spawnSync } = require('child_process');
const crypto = require('crypto');
const h = require('../../../test/helpers');

let EXIT_CONDITION = false;

const run = async () => {
	const APP = {
        info: {
            id: 'net.safe.auth.demo.app',
            name: 'safe-api-tutorial',
            vendor: 'MaidSafe.net Ltd',
            scope: 'scope',
        },
        permissions: {}
    };

  try {
      console.log();
      console.log('Authorising application with authenticator CLI');
      console.log('**********************************************');

      // Let's first create a random account with the Authenticator CLI
      let secretStr = crypto.randomBytes(10).toString('hex');
      let pwdStr = crypto.randomBytes(10).toString('hex');
      let inviteToken = crypto.randomBytes(10).toString('hex');
      const result = spawnSync('/opt/safe/safe_auth', [
        `--secret=${secretStr}`,
        `--password=${pwdStr}`,
        `--invite-token=${inviteToken}`,
      ]);
      let cmdErr = result.stderr.toString();
      if (cmdErr.length > 0) {
        throw Error("Failed to create a random account. " + cmdErr);
      }
      console.log("Account successfully created with secret:", secretStr, "and password:", pwdStr);

      //----------------Initialise and Authorise client App-------------------//

      // App has been created and initialised
      const app = await safeApp.initialiseApp(APP.info)

      // Generate authorisation request with no specific permissions
      let authReq = await app.auth.genAuthUri({ _public: ['Read'] });
      // Remove the `safe://` prefix
      let reqString = authReq.uri.replace(/^safe-[^:]*:?[/]*/g, '');
      console.log("Authorisation request string generated: ", reqString);

      // Send authorisation request to the authenticator CLI
      let args = [
        `--secret=${secretStr}`,
        `--password=${pwdStr}`,
        `--req=${reqString}`,
      ];
      const safeAuthCli = spawnSync('/opt/safe/safe_auth', args);

      let authCmdErr = safeAuthCli.stderr.toString();
      if (authCmdErr.length > 0) {
        throw Error("Failed to obtain authorisation response. " + authCmdErr);
      }

      let authRes = safeAuthCli.stdout.toString();
      console.log("Authorisation response obatined", authRes);

      await app.auth.loginFromUri(authRes);
      console.log("Application is connected to the network!");

      //----------Authorise permissions on additional containers--------------//

      // Generate authorisation request for containers
      authReq = await app.auth.genContainerAuthUri({ _publicNames: ['Read', 'Insert'] });
      // Remove the `safe://` prefix
      reqString = authReq.uri.replace(/^safe-[^:]*:?[/]*/g, '');
      console.log("Containers authorisation request string generated: ", reqString);

      // Send containers authorisation request to the authenticator CLI
      args = [
        `--secret=${secretStr}`,
        `--password=${pwdStr}`,
        `--req=${reqString}`,
      ];
      const safeContAuthCli = spawnSync('/opt/safe/safe_auth', args);

      authCmdErr = safeContAuthCli.stderr.toString();
      if (authCmdErr.length > 0) {
        throw Error("Failed to obtain containers authorisation response. " + authCmdErr);
      }

      authRes = safeContAuthCli.stdout.toString();
      console.log("Authorisation response obatined", authRes);

      await app.auth.loginFromUri(authRes);
      console.log("Permissions on additional container were granted!");

      //----------------Show list of granted permissions----------------------//
      console.log("Retrieve list of permissions granted...")
      args = [
        `--secret=${secretStr}`,
        `--password=${pwdStr}`,
        `--apps`,
        `--pretty`
      ];
      const res = spawnSync('/opt/safe/safe_auth', args);
      cmdErr = res.stderr.toString();
      if (cmdErr.length > 0) {
        throw Error("Failed to obtain containers authorisation response. " + cmdErr);
      }
      console.log(res.stdout.toString());
	} catch(e) {
		console.log("Execution failed", e);
	}
  EXIT_CONDITION = true;
};

run();

waitUntil(() => EXIT_CONDITION === true, 1000, () => {});
