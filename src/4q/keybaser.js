const child_process = require("child_process");
const fs = require("fs");
const Promise = require("bluebird");
const toolkit = require("stream-toolkit");
const util = require("util");

// keybase support!

const KEYBASE_BINARY = "keybase";

class Keybaser {
  constructor(cli) {
    this.cli = cli;
    this.identity = null;
  }

  // return non-error if keybase is actually installed and we got an identity.
  check() {
    if (this.identity != null) return Promise.resolve();
    this.identity = this.findIdentityFromKeybaseConfig();
    if (this.identity != null) return Promise.resolve();

    this.cli.status("Checking keybase...");
    const p = child_process.spawn(KEYBASE_BINARY, [ "status" ], { stdio: [ "ignore", "pipe", "pipe" ] });
    // in io.js, the pipe must happen concurrently with the process, or the data will be thrown away. :(
    return Promise.all([
      toolkit.pipeToBuffer(p.stdout),
      waitForProcess(p)
    ]).then(([ stdout, code ]) => {
      if (code != 0) throw new Error(`Keybase exit code ${code}`);
      const status = JSON.parse(stdout);
      if (!status || !status.status || !status.status.configured) throw new Error("Keybase is not configured.");
      if (!status.status.logged_in) throw new Error("You aren't currently logged in to keybase.");
      if (!status.user || !status.user.name) throw new Error("Can't determine your keybase username.");
      this.cli.status();
      this.identity = status.user.name;
    }).catch((error) => {
      // translate a particularly odd error.
      if (error.code == "ENOENT" && error.syscall == "spawn") {
        throw new Error("Can't find keybase binary.");
      }
      throw error;
    });
  }

  // if we can find a keybase 'config.json' file, that's a loooooot faster than hitting their service.
  findIdentityFromKeybaseConfig() {
    const home = process.env["HOME"] || process.env["USERPROFILE"];
    if (!home) return null;

    let json = this.readKeybaseConfig(home + "/.config/keybase/config.json");
    if (json && json.user && json.user.name) return json.user.name;

    // older location:
    json = this.readKeybaseConfig(home + "/.keybase/config.json");
    if (json && json.user && json.user.name) return json.user.name;

    return null;
  }

  readKeybaseConfig(filename) {
    try {
      return JSON.parse(fs.readFileSync(filename));
    } catch (error) {
      return null;
    }
  }

  encrypt(key, target, options = {}) {
    const args = [ "encrypt", "-b" ];
    if (options.sign) args.push("--sign");
    args.push(target);
    this.cli.status(`Encrypting key for ${target} ...`);
    // can't just send 'spawn' a stream, because it counts on having an underlying file descriptor.
    const p = child_process.spawn(KEYBASE_BINARY, args, { stdio: [ "pipe", "pipe", process.stderr ] });
    toolkit.pipeFromBuffer(key, p.stdin);
    return Promise.all([
      toolkit.pipeToBuffer(p.stdout),
      waitForProcess(p)
    ]).then(([ stdout, code ]) => {
      this.cli.status();
      if (code != 0) throw new Error(`Keybase exit code ${code}`);
      return stdout;
    });
  }

  decrypt(encrypted) {
    const args = [ "decrypt" ];
    this.cli.status(`Decrypting key as ${this.identity} ...`);
    const p = child_process.spawn(KEYBASE_BINARY, args, { stdio: [ "pipe", "pipe", process.stderr ] });
    toolkit.pipeFromBuffer(encrypted, p.stdin);
    return Promise.all([
      toolkit.pipeToBuffer(p.stdout),
      waitForProcess(p)
    ]).then(([ stdout, code ]) => {
      this.cli.status();
      if (code != 0) throw new Error(`Keybase exit code ${code}`);
      return stdout;
    });
  }
}


function waitForProcess(p) {
  return new Promise((resolve, reject) => {
    p.on("error", (error) => {
      try {
        reject(error);
      } catch (e) {
        // fine.
      }
    });

    p.on("exit", (code, signal) => {
      if (signal) {
        reject("Process exited abnormally: " + signal);
      } else {
        resolve(code);
      }
    });
  });
}


exports.Keybaser = Keybaser;
