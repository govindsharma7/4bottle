"use strict";

import crypto from "crypto";
import fs from "fs";
import Keybaser from "./keybaser";
import minimist from "minimist";
import path from "path";
import Promise from "bluebird";
import read from "read";
import sprintf from "sprintf";
import stream from "stream";
import strftime from "strftime";
import toolkit from "stream-toolkit";
import { clicolor } from "clicolor";
import { COLORS, messageForError, SALT } from "./helpers";
import * as lib4bottle from "lib4bottle";

import "source-map-support/register";

const PACKAGE = require("../../package.json");
const NOW = Date.now();

const USAGE = `
usage: 4pack [options] <filename(s)...>
    create a 4bottle archive from a set of files (or folders)

options:
    --help
    -o <filename>
        archive filename to write
    -v, --verbose
        verbose: display files as they're written
    -q, --quiet
        quiet: display nothing unless there's an error
    -Z, --no-compress
        do not compress the contents
    -S, --snappy
        use snappy compression instead of LZMA2
    -H, --no-hash
        do not compute a check hash (let go and use the force)
    -e <user>, --encrypt <user>
        encrypt archive for a keybase user (may be used multiple times to
        send to multiple recipients)
    -p, --password
        prompt for a password and use it to encrypt (not as good as -e)
    --no-color
        turn off cool console colors
`;

function main() {
  const cli = clicolor();
  const keybaser = new Keybaser(cli);

  const argv = minimist(process.argv.slice(2), {
    alias: {
      e: "encrypt",
      H: "no-hash",
      P: "password-here",
      p: "password",
      q: "quiet",
      S: "snappy",
      v: "verbose",
      Z: "no-compress"
    },
    boolean: [
      "color",
      "compress",
      "debug",
      "help",
      "password",
      "quiet",
      "snappy",
      "verbose",
      "version"
    ],
    default: { color: true, compress: true, hash: true }
  });

  // minimist isn't great at decoding -Z:
  if (argv["no-compress"]) argv.compress = false;
  if (argv["no-hash"]) argv.hash = false;
  if (argv.color) cli.useColor(true);
  if (argv["no-color"]) cli.useColor(false);

  if (argv.help || argv._.length == 0) {
    console.log(USAGE);
    process.exit(0);
  }
  if (argv.version) {
    console.log(`4pack ${PACKAGE.version}`);
    process.exit(0);
  }
  if (argv._.length == 0) {
    console.log("Required: filename(s) to archive");
    process.exit(1);
  }
  cli.quiet(argv.q);
  if (argv.o == null) {
    if (argv._.length > 1) {
      argv.o = "archive.4b";
    } else {
      let archiveFolder = argv._[0];
      if (archiveFolder[archiveFolder.length - 1] == "/") {
        archiveFolder = archiveFolder.slice(0, archiveFolder.length - 1);
      }
      argv.o = archiveFolder + ".4b";
    }
  }

  // this is kind of just a hack for tests, so undocumented.
  if (argv["password-here"]) argv.password = argv["password-here"];

  // quick sanity check: do all these files exist?
  let okay = true;
  argv._.forEach(filename => {
    if (!fs.existsSync(filename)) {
      console.log(`Can't find file: ${filename}`);
      okay = false;
    }
  });
  if (!okay) process.exit(1);

  function die(error) {
    cli.displayError(messageForError(error));
    if (argv.debug) console.log(error.stack);
    process.exit(1);
  }

  if (argv.encrypt && !Array.isArray(argv.encrypt)) argv.encrypt = [ argv.encrypt ];
  return keybaser.check().catch(error => {
    throw new NestedError("Keybase error", error);
  }).then(() => {
    let fd = null;
    try {
      fd = fs.openSync(argv.o, "w");
    } catch (error) {
      throw new NestedError(`Unable to write ${argv.o}`, error);
    }
    const outStream = fs.createWriteStream("", { fd });
    toolkit.promisify(outStream);

    const countingOutStream = toolkit.countingStream();
    countingOutStream.pipe(outStream);

    return assemblePipes(countingOutStream, keybaser, die, {
      hash: argv.hash ? lib4bottle.HASH_SHA512 : null,
      recipients: argv.encrypt,
      password: argv.password,
      compression: argv.encrypt ? (argv.snappy ? lib4bottle.COMPRESSION_SNAPPY : lib4bottle.COMPRESSION_LZMA2) : null
    }).then(targetStream => {
      return writeArchive(cli, countingOutStream, argv._, argv.o, die, { verbose: argv.v }).then(({ bottle, state }) => {
        bottle.pipe(targetStream);
        return outStream.finishPromise().then(() => {
          const compressionStatus = argv.compress ?
            cli.paint(" -> ", cli.color(COLORS.file_size, cli.toMagnitude(state.totalBytesOut, 1024) + "B")) : "";
          const inStatus = cli.color(
            COLORS.file_size,
            `(${state.fileCount} files, ${cli.toMagnitude(state.totalBytesIn)}B)`
          );
          cli.displayVerbose(`${argv.o} ${inStatus}${compressionStatus}`);
        });
      });
    });
  }).catch(error => {
    cli.displayError(messageForError(error));
    if (argv.debug) console.log(error.stack);
    process.exit(1);
  });
}

function assemblePipes(stream, keybaser, die, { hash, password, recipients, compression }) {
  let targetStream = stream;

  if (hash) {
    const hashBottle = new lib4bottle.HashBottleWriter(hash);
    hashBottle.pipe(targetStream);
    targetStream = hashBottle;
  }

  return (recipients ?
    setupKeybaseEncryption(targetStream, keybaser, die, recipients) :
    (password ? setupPasswordEncryption(targetStream, die, password) : Promise.resolve(targetStream))
  ).then(targetStream => {
    if (!compression) return targetStream;
    const compressedBottle = new lib4bottle.CompressedBottleWriter(compression);
    compressedBottle.pipe(targetStream);
    return compressedBottle;
  });
}

function setupKeybaseEncryption(stream, keybaser, die, recipients) {
  const encrypter = (recipient, buffer) => {
    const [ scheme, name ] = recipient.split(":");
    if (scheme != "keybase") throw new Error(`Expected keybase scheme, got ${scheme}`);
    return keybaser.encrypt(buffer, name);
  };

  // keybase is the only encryption recipient type, so far.
  return lib4bottle.writeEncryptedBottle(
    lib4bottle.ENCRYPTION_AES_256_CTR,
    { recipients: recipients.map(name => `keybase:${name}`), encrypter }
  ).then(encryptedBottle => {
    encryptedBottle.pipe(stream);
    encryptedBottle.on("error", error => die("Encryption error", error));
    return encryptedBottle;
  });
}

function setupPasswordEncryption(stream, die, password) {
  const readOptions = { prompt: "Password: ", silent: true, replace: "\u2022" };
  return ((typeof password == "string") ?
    Promise.resolve(password) :
    Promise.promisify(read)(readOptions).then(([ password ]) => password)
  ).then(password => {
    return lib4bottle.writeEncryptedBottle(
      lib4bottle.ENCRYPTION_AES_256_CTR,
      { password }
    );
  }).then(encryptedBottle => {
    encryptedBottle.pipe(stream);
    encryptedBottle.on("error", error => die("Encryption error", error));
    return encryptedBottle;
  });
}

function writeArchive(cli, countingOutStream, filenames, targetFilename, die, { verbose }) {
  const state = {
    fileCount: 0,
    totalBytesOut: 0,
    totalBytesIn: 0,
    currentFileBytes: 0,
    currentFileTotalBytes: 0,
    currentFilename: null
  };

  countingOutStream.on("count", n => {
    state.totalBytesOut = n;
    cli.status(statusMessage(cli, state));
  });

  const writer = new lib4bottle.ArchiveWriter();
  writer.on("filename", (filename, header) => {
    if (verbose) printFinishedFile(cli, state);
    state.currentFileBytes = 0;
    state.currentFileTotalBytes = header.size;
    state.currentFilename = filename;
    state.isFolder = header.folder;
    if (!header.folder) {
      state.fileCount += 1;
      state.totalBytesIn += header.size;
    }
    cli.status(statusMessage(cli, state));
  });
  writer.on("status", (filename, byteCount) => {
    state.currentFileBytes = byteCount;
    cli.status(statusMessage(cli, state));
  });
  writer.on("error", error => die("Error", error));

  let bottlePromise = null;
  if (filenames.length > 1) {
    // multiple files: just make a fake folder
    const folderName = path.basename(targetFilename, ".4b");
    bottlePromise = writer.archiveFiles(folderName, filenames);
  } else {
    bottlePromise = writer.archiveFile(filenames[0]);
  }

  return bottlePromise.then(bottle => {
    bottle.finishPromise().then(() => {
      if (verbose) printFinishedFile(cli, state);
    });

    return { bottle, state };
  });
}

function statusMessage(cli, state) {
  if (!state.currentFilename) return;
  const count = cli.color(COLORS.status_count, sprintf("%6s", state.fileCount));
  const totalProgress = cli.color(
    COLORS.status_total_progress,
    sprintf("%5s -> %5s", cli.toMagnitude(state.totalBytesIn, 1024), cli.toMagnitude(state.totalBytesOut, 1024))
  );
  const fileProgress = state.currentFileBytes > 0 && state.currentFileTotalBytes ?
    cli.color(
      COLORS.status_file_progress,
      `(${Math.floor(100 * state.currentFileBytes / state.currentFileTotalBytes)}%)`
    ) :
    "";
  return cli.paint(count, ": (", totalProgress, ")  ", state.currentFilename, " ", fileProgress);
}

function printFinishedFile(cli, state) {
  if (!state.currentFilename) return;
  const bytes = state.isFolder ? "     " :
    cli.color(COLORS.file_size, sprintf("%5s", cli.toMagnitude(state.currentFileTotalBytes)));
  cli.displayVerbose(cli.paint("  ", bytes, "  ", state.currentFilename));
}


class NestedError extends Error {
  constructor(message, cause) {
    super(message);
    this.message = message;
    this.cause = cause;
    Error.captureStackTrace(this, this.constructor);
  }
}


exports.main = main;
