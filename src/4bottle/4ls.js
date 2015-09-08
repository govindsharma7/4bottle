"use strict";

import crypto from "crypto";
import fs from "fs";
import Keybaser from "./keybaser";
import minimist from "minimist";
import Promise from "bluebird";
import toolkit from "stream-toolkit";
import { clicolor } from "clicolor";
import * as helpers from "./helpers";
import * as lib4bottle from "lib4bottle";

import "source-map-support/register";

const PACKAGE = require("../../package.json");
const COLORS = helpers.COLORS;

const USAGE = `
usage: 4ls [options] <filename(s)...>
    displays contents of 4bottle archives

options:
    --help
    -l
        long form: display date/time, user/group, and posix permissions
    -q
        quiet: display only the summary line at the end
    --structure
        show the bottle structure of the archive, instead of the listing
    --no-color
        turn off cool console colors
`;

let password = null;

export function main() {
  const cli = clicolor();
  const keybaser = new Keybaser(cli);

  const argv = minimist(process.argv.slice(2), {
    boolean: [ "help", "version", "l", "q", "color", "structure", "debug" ],
    default: { color: true }
  });
  if (argv.help || argv._.length == 0) {
    console.log(USAGE);
    process.exit(0);
  }
  if (argv.version) {
    console.log(`4ls ${PACKAGE.version}`);
    process.exit(0);
  }
  if (argv._.length == 0) {
    console.log("required: filename of 4bottle archive file(s)");
    process.exit(1);
  }
  if (!argv.color) cli.useColor(false);
  cli.quiet(argv.q);
  if (argv.password) password = argv.password;

  const loudness = { isVerbose: argv.l, isQuiet: argv.q, cli, keybaser };
  (argv.structure ? dumpArchiveStructures(argv._, loudness) : dumpArchiveFiles(argv._, loudness)).catch((error) => {
    cli.displayError(`Unable to read archive: ${helpers.messageForError(error)}`);
    if (argv.debug) console.log(error.stack);
    process.exit(1);
  });
}

function dumpArchiveStructures(filenames, loudness) {
  return Promise.map(filenames, ((filename) => dumpArchiveStructure(filename, loudness)), { concurrency: 1 });
}

function dumpArchiveStructure(filename, { isVerbose, isQuiet, cli, keybaser }) {
  let indent = 0;
  const pad = () => {
    let rv = "";
    while (rv.length < indent) rv += " ";
    return rv;
  };

  const reader = new lib4bottle.ArchiveReader();

  reader.decryptKey = (keymap) => {
    if (Object.keys(keymap).length == 0) {
      if (password == null) throw new Error("No password provided.");
      return Promise.promisify(crypto.pbkdf2)(password, helpers.SALT, 10000, 48);
    }
    return keybaser.check().then(() => {
      const self = `keybase:${keybaser.identity}`;
      const allowed = Object.keys(keymap).join(", ");
      if (!keymap[self]) throw new Error(`No encryption key for ${self} (only: ${allowed})`);
      return keybaser.decrypt(keymap[self]);
    });
  };

  reader.on("start-bottle", bottle => {
    const typeName = cli.color("purple", bottle.typeName());
    let extra = "";
    switch (bottle.typeName()) {
      case "file":
        extra = `${bottle.header.filename} (${bottle.header.size})`;
        break;
      case "folder":
        extra = bottle.header.filename;
        break;
    }
    cli.display(cli.paint(pad(), "+ ", typeName, " ", extra));
    indent += 2;
  });

  reader.on("end-bottle", bottle => {
    indent -= 2;
  });

  reader.on("hash", (bottle, isValid, hex) => {
    const validString = isValid ? cli.color("green", "valid") : cli.color("red", "INVALID");
    cli.display(cli.paint(pad(), "[", validString, " hash: ", hex, "]"));
  });

  reader.on("encrypt", (bottle) => {
    cli.display(cli.paint(pad(), "[encrypted for: ", bottle.header.recipients.join(", "), "]"));
  });

  return reader.scanStream(helpers.readStream(cli, filename));
}

function dumpArchiveFiles(filenames, loudness) {
  return Promise.map(filenames, ((filename) => dumpArchiveFile(filename, loudness)), { concurrency: 1 });
}

function dumpArchiveFile(filename, { cli, keybaser, isVerbose, isQuiet }) {
  // count total bytes packed away
  const state = { totalBytesIn: 0, totalBytes: 0, totalFiles: 0, prefix: [] };

  const countingInStream = toolkit.countingStream();
  countingInStream.on("count", (n) => {
    state.totalBytesIn = n;
  });
  helpers.readStream(cli, filename).pipe(countingInStream);
  const reader = new lib4bottle.ArchiveReader();

  reader.decryptKey = keymap => {
    if (Object.keys(keymap).length == 0) {
      if (password == null) throw new Error("No password provided.");
      return Promise.promisify(crypto.pbkdf2)(password, helpers.SALT, 10000, 48);
    }
    return keybaser.check().then(() => {
      const self = `keybase:${keybaser.identity}`;
      const allowed = Object.keys(keymap).join(", ");
      if (!keymap[self]) throw new Error(`No encryption key for ${self} (only: ${allowed})`);
      return keybaser.decrypt(keymap[self]);
    });
  };

  reader.on("start-bottle", bottle => {
    switch (bottle.typeName()) {
      case "file":
      case "folder":
        const nicePrefix = state.prefix.join("/") + (state.prefix.length > 0 ? "/" : "");
        cli.displayVerbose(helpers.summaryLineForFile(cli, bottle.header, nicePrefix, isVerbose));
        state.prefix.push(bottle.header.filename);
        if (!bottle.header.folder) {
          state.totalFiles += 1;
          state.totalBytes += bottle.header.size;
        }
        break;
    }
  });

  reader.on("end-bottle", bottle => {
    switch (bottle.typeName()) {
      case "file":
      case "folder":
        state.prefix.pop();
        break;
    }
  });

  reader.on("hash", (bottle, isValid, hex) => {
    // FIXME display something if this is per-file
    if (!isValid) throw new Error("Invalid hash; archive is probably corrupt.");
    if (state.prefix.length == 0) state.validHash = bottle.header.hashName;
  });

  reader.on("compress", (bottle) => {
    // FIXME display something if this is per-file
    if (state.prefix.length == 0) state.compression = bottle.header.compressionName;
  });

  reader.on("encrypt", (bottle) => {
    // FIXME display something if this is per-file
    if (state.prefix.length == 0) {
      state.encryption = bottle.header.encryptionName;
      if (bottle.header.recipients.length > 0) state.encryptedFor = bottle.header.recipients.join(" & ");
    }
  });

  return reader.scanStream(countingInStream).then(() => {
    const annotations = [];
    const importante = [];
    if (state.encryption != null) {
      importante.push(state.encryption + (state.encryptedFor != null ? ` for ${state.encryptedFor}` : ""));
    }
    if (state.compression != null) annotations.push(state.compression);
    if (state.validHash != null) annotations.push(state.validHash);
    const compressionStatus =
      state.compression != null ?
      cli.paint(" -> ", cli.color(COLORS.file_size, cli.toMagnitude(state.totalBytesOut, 1024) + "B")) :
      "";
    const sizes = cli.color(COLORS.file_size, `(${state.totalFiles} files, ${cli.toMagnitude(state.totalBytesIn)}B)`);
    let extras = importante.length > 0 ? cli.color(COLORS.importante, ` [${importante.join("; ")}]`) : "";
    extras += annotations.length > 0 ? cli.color(COLORS.annotations, ` [${annotations.join(", ")}]`) : "";

    cli.display(`${filename} ${sizes}${extras}`);
  }).catch(error => {
    cli.displayError(error.stack);
  });
}
