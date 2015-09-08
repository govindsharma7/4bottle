"use strict";

import crypto from "crypto";
import fs from "fs";
import Keybaser from "./keybaser";
import minimist from "minimist";
import path from "path";
import Promise from "bluebird";
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
usage: qpack [options] <filename(s)...>
    create a 4bottle archive from a set of files (or folders)

options:
    --help
    -o <filename>
        archive filename to write
    -v
        verbose: display files as they're written
    -q
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
    --no-color
        turn off cool console colors
`;

function main() {
  const cli = clicolor();
  const keybaser = new Keybaser(cli);

  const argv = minimist(process.argv.slice(2), {
    alias: { "Z": "no-compress", "H": "no-hash", "S": "snappy", "e": "encrypt" },
    boolean: [ "help", "version", "v", "q", "color", "compress", "snappy", "debug" ],
    default: { color: true, compress: true, hash: true }
  });
  // minimist isn't great at decoding -Z:
  if (argv["no-compress"]) argv.compress = false;
  if (argv["no-hash"]) argv.hash = false;
  if (argv.help || argv._.length == 0) {
    console.log(USAGE);
    process.exit(0);
  }
  if (argv.version) {
    console.log(`qpack ${PACKAGE.version}`);
    process.exit(0);
  }
  if (argv._.length == 0) {
    console.log("Required: filename(s) to archive");
    process.exit(1);
  }
  if (!argv.color) cli.useColor(false);
  cli.quiet(argv.q);
  if (argv.o == null) {
    if (argv._.length > 1) {
      argv.o = "archive.4q";
    } else {
      let archiveFolder = argv._[0];
      if (archiveFolder[archiveFolder.length - 1] == "/") {
        archiveFolder = archiveFolder.slice(0, archiveFolder.length - 1);
      }
      argv.o = archiveFolder + ".4q";
    }
  }

  // quick sanity check: do all these files exist?
  let okay = true;
  argv._.forEach((filename) => {
    if (!fs.existsSync(filename)) {
      console.log(`Can't find file: ${filename}`);
      okay = false;
    }
  });
  if (!okay) process.exit(1);

  function die(message, error) {
    cli.displayError(`${message}: ${messageForError(error)}`);
    if (argv.debug) console.log(error.stack);
    process.exit(1);
  };

  conditionally(
    argv.encrypt,
    () => {
      if (!Array.isArray(argv.encrypt)) argv.encrypt = [ argv.encrypt ];
      return keybaser.check().catch((error) => {
        die("Keybase error", error);
      });
    }
  ).then(() => {
    let fd = null;
    try {
      fd = fs.openSync(argv.o, "w");
    } catch (error) {
      die(`Unable to write ${argv.o}`, error);
    }
    const outStream = fs.createWriteStream("", { fd });
    toolkit.promisify(outStream);

    const state = {
      fileCount: 0,
      totalBytesOut: 0,
      totalBytesIn: 0,
      currentFileBytes: 0,
      currentFileTotalBytes: 0,
      currentFilename: null
    };
    const countingOutStream = toolkit.countingStream();
    countingOutStream.on("count", (n) => {
      state.totalBytesOut = n;
      cli.status(statusMessage(cli, state));
    });
    countingOutStream.pipe(outStream);
    let targetStream = countingOutStream;

    if (argv.hash) {
      const hashBottle = new lib4bottle.HashBottleWriter(lib4bottle.HASH_SHA512);
      hashBottle.pipe(targetStream);
      targetStream = hashBottle;
    }

    return conditionally(
      argv.encrypt || argv.password,
      () => {
        return (argv.encrypt ?
          setupEncryptBottle(keybaser, argv.encrypt) :
          setupPasswordBottle(argv.password)
        ).then((encryptedBottle) => {
          encryptedBottle.pipe(targetStream);
          encryptedBottle.on("error", (error) => die("Encryption error", error));
          targetStream = encryptedBottle;
        })
      }
    ).then(() => {
      if (argv.compress) {
        const compressionType = argv.snappy ? lib4bottle.COMPRESSION_SNAPPY : lib4bottle.COMPRESSION_LZMA2;
        const compressedBottle = new lib4bottle.CompressedBottleWriter(compressionType);
        compressedBottle.pipe(targetStream);
        targetStream = compressedBottle;
      }

      const writer = new lib4bottle.ArchiveWriter();
      writer.on("filename", (filename, header) => {
        if (argv.v) printFinishedFile(cli, state);
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
      writer.on("error", (error) => die("Error", error));

      let nextPromise = null;
      if (argv._.length > 1) {
        // multiple files: just make a fake folder
        const folderName = path.basename(argv.o, ".4q");
        nextPromise = writer.archiveFiles(folderName, argv._);
      } else {
        nextPromise = writer.archiveFile(argv._[0]);
      }
      return nextPromise.then((bottle) => {
        bottle.pipe(targetStream);
        return outStream.finishPromise();
      }).then(() => {
        if (argv.v) printFinishedFile(cli, state);
        const compressionStatus = argv.compress ?
          cli.paint(" -> ", cli.color(COLORS.file_size, cli.toMagnitude(state.totalBytesOut, 1024) + "B")) : "";
        const inStatus = cli.color(
          COLORS.file_size,
          `(${state.fileCount} files, ${cli.toMagnitude(state.totalBytesIn)}B)`
        );
        cli.displayVerbose(`${argv.o} ${inStatus}${compressionStatus}`);
      });
    });
  }).catch((error) => {
    cli.displayError(`Unable to write ${argv.o}: ${messageForError(error)}`);
    if (argv.debug) console.log(error.stack);
    process.exit(1);
  });
}

function setupEncryptBottle(keybaser, recipients, targetStream) {
  const encrypter = (recipient, buffer) => {
    const [ scheme, name ] = recipient.split(":");
    if (scheme != "keybase") throw new Error(`Expected keybase scheme, got ${scheme}`);
    return keybaser.encrypt(buffer, name);
  };

  // keybase is the only encryption recipient type, so far.
  recipients = recipients.map((name) => `keybase:${name}`);
  return lib4bottle.writeEncryptedBottle(lib4bottle.ENCRYPTION_AES_256_CTR, recipients, encrypter);
}

// this is really bad. don't use it.
function setupPasswordBottle(password, targetStream) {
  return Promise.promisify(crypto.pbkdf2)(password, SALT, 10000, 48).then((keyBuffer) => {
    return lib4bottle.writeEncryptedBottle(lib4bottle.ENCRYPTION_AES_256_CTR, [], keyBuffer);
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

function conditionally(predicate, f) {
  return predicate ? f() : Promise.resolve();
}


exports.main = main;
