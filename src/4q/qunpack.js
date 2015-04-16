const clicolor = require("clicolor");
const crypto = require("crypto");
const fs = require("fs");
const helpers = require("./helpers");
const keybaser = require("./keybaser");
const lib4q = require("lib4q");
const minimist = require("minimist");
const path = require("path");
const Promise = require("bluebird");
const sprintf = require("sprintf");
const strftime = require("strftime");
const toolkit = require("stream-toolkit");
const util = require("util");

require("source-map-support").install();

const PACKAGE = require("../../package.json");
const COLORS = helpers.COLORS;
const NOW = Date.now();
const HOURS_20 = 20 * 60 * 60 * 1000;
const DAYS_250 = 250 * 24 * 60 * 60 * 1000;

const USAGE = `
usage: qunpack [options] <filename(s)...>
    unpacks contents of 4Q archives

options:
    --help
    -f, --force
        overwrite any existing files when unpacking
    -o <folder>
        unpack files into a target folder instead of the current folder
    -v
        verbose: display files as they're written
    -q
        quiet: display only the summary line at the end
    --no-color
        turn off cool console colors
`;

function main() {
  const cli = clicolor.cli();
  const keybaser = new (require("./keybaser").Keybaser)(cli);

  const argv = minimist(process.argv.slice(2), {
    boolean: [ "help", "version", "q", "v", "color", "debug", "force" ],
    alias: { "f": "force" },
    default: { color: true, force: false }
  });
  if (argv.help || argv._.length == 0) {
    console.log(USAGE);
    process.exit(0);
  }
  if (argv.version) {
    console.log(`qunpack ${PACKAGE.version}`)
    process.exit(0);
  }
  if (argv._.length == 0) {
    console.log("required: filename of 4Q archive file(s)");
    process.exit(1);
  }
  if (!argv.color) cli.useColor(false);
  cli.quiet(argv.q);
  if (!argv.o) argv.o = process.cwd();

  const outputFolder = argv.o;
  if (!fs.existsSync(outputFolder)) {
    try {
      fs.mkdirSync(outputFolder);
    } catch (error) {
      cli.displayError(`Can't create folder ${outputFolder}: ${helpers.messageForError(error)}`);
      if (argv.debug) console.log(error.stack);
      process.exit(1);
    }
  }
  if (!fs.statSync(outputFolder).isDirectory) {
    cli.displayError(`Not a folder: ${outputFolder}`)
    process.exit(1);
  }

  const options = {
    isQuiet: argv.q,
    isVerbose: argv.v,
    debug: argv.debug,
    force: argv.force,
    password: argv.password,
    keybaser,
    cli
  };
  unpackArchiveFiles(argv._, outputFolder, options).catch((error) => {
    cli.displayError(`Unable to unpack archive: ${helpers.messageForError(error)}`);
    if (argv.debug) console.log(error.stack);
    process.exit(1);
  });
}

function unpackArchiveFiles(filenames, outputFolder, options) {
  return Promise.map(filenames, (filename) => unpackArchiveFile(filename, outputFolder, options), { concurrency: 1 });
}

function unpackArchiveFile(filename, outputFolder, options) {
  const state = {
    totalFiles: 0,
    totalBytesOut: 0,
    totalBytesIn: 0,
    currentFileBytes: 0,
    currentFileTotalBytes: 0,
    currentFilename: null,
    currentDestFilename: null,
    prefix: [ ],
    validHash: null,
    compression: null
  };

  const countingInStream = toolkit.countingStream();
  countingInStream.on("count", (n) => {
    state.totalBytesIn = n;
    displayStatus(options.cli, state);
  });
  helpers.readStream(options.cli, filename, options.debug).pipe(countingInStream);
  let ultimateOutputFolder = outputFolder;

  const reader = new lib4q.ArchiveReader();

  reader.decryptKey = (keymap) => {
    if (Object.keys(keymap).length == 0) {
      if (!options.password) throw new Error("No password provided.");
      return Promise.promisify(crypto.pbkdf2)(options.password, helpers.SALT, 10000, 48);
    }
    return options.keybaser.check().then(() => {
      const self = `keybase:${options.keybaser.identity}`;
      const allowed = Object.keys(keymap).join(", ");
      if (!keymap[self]) throw new Error(`No encryption key for ${self} (only: ${allowed})`);
      return options.keybaser.decrypt(keymap[self]);
    });
  };

  reader.on("start-bottle", (bottle) => {
    switch (bottle.typeName()) {
      case "file":
      case "folder":
        const nicePrefix = state.prefix.join("/") + (state.prefix.length > 0 ? "/" : "");
        const niceFilename = nicePrefix + bottle.header.filename;
        state.currentFileBytes = 0;
        state.currentFileTotalBytes = bottle.header.size;
        state.currentFilename = niceFilename;
        state.currentDestFilename = path.join(outputFolder, niceFilename);
        state.isFolder = bottle.header.folder;
        state.mode = bottle.header.mode;
        if (state.isFolder && !ultimateOutputFolder) ultimateOutputFolder = state.currentDestFilename;
        if (!state.isFolder) state.totalFiles += 1;
        displayStatus(options.cli, state);
        if (state.isFolder) ensureFolder(state.currentDestFilename);
        state.prefix.push(bottle.header.filename);
    }
  });

  reader.on("end-bottle", (bottle) => {
    switch (bottle.typeName()) {
      case "file":
      case "folder":
        if (options.isVerbose) {
          options.cli.status();
          if (bottle.typeName() == "file") printFinishedFile(options.cli, state);
        }
        if (bottle.typeName() == "file") state.totalBytesOut += state.currentFileTotalBytes;
        state.currentFileBytes = 0;
        state.currentFileTotalBytes = 0;
        state.prefix.pop();
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
    if (state.prefix.length == 0) {
      state.encryption = bottle.header.encryptionName;
      if (bottle.header.recipients.length > 0) state.encryptedFor = bottle.header.recipients.join(" & ");
    }
  });

  reader.on("error", (error) => {
    options.cli.displayError(`Can't write ${state.currentDestFilename || '?'}: ${helpers.messageForError(error)}`);
    const code = error.code || (error.cause || {}).code;
    if (code == "EEXIST") options.cli.displayError("Use -f or --force to overwrite existing files.");
    if (options.debug) console.log(error.stack);
    process.exit(1);
  });

  reader.processFile = (dataStream) => {
    const countingOutStream = new toolkit.countingStream();
    countingOutStream.on("count", (n) => {
      state.currentFileBytes = n;
      displayStatus(options.cli, state);
    });

    const realFilename = path.join(outputFolder, state.currentFilename);

    const access = options.force ? "w" : "wx";
    return Promise.promisify(fs.open)(realFilename, access, state.mode || parseInt("666", 8)).then((fd) => {
      const outStream = fs.createWriteStream(realFilename, { fd });
      toolkit.promisify(outStream);
      outStream.on("error", (error) => reader.emit("error", error));
      dataStream.pipe(countingOutStream).pipe(outStream);
      return outStream.finishPromise();
    }).catch((error) => {
      reader.emit("error", error);
    });
  };

  const ensureFolder = (realFilename) => {
    if (!(fs.existsSync(realFilename) && fs.statSync(realFilename).isDirectory())) {
      fs.mkdirSync(realFilename);
    }
  };

  return reader.scanStream(countingInStream).then(() => {
    const bytesInHuman = options.cli.toMagnitude(state.totalBytesIn, 1024);
    const bytesOutHuman = options.cli.toMagnitude(state.totalBytesOut, 1024);
    const byteTraffic = `${bytesInHuman} -> ${bytesOutHuman} bytes`;
    const annotations = [];
    const importante = [];
    if (state.encryption) {
      importante.push(state.encryption + (state.encryptedFor ? ` for ${state.encryptedFor}` : ""));
    }
    if (state.compression) annotations.push(state.compression);
    if (state.validHash) annotations.push(state.validHash);
    let extras = importante.length > 0 && options.isVerbose ?
      options.cli.color(COLORS.importante, ` [${importante.join("; ")}]`) : "";
    extras += annotations.length > 0 && options.isVerbose ?
      options.cli.color(COLORS.annotations, ` [${annotations.join(", ")}]`) : "";
    const inStatus = options.cli.paint(filename, " ",
      options.cli.color(COLORS.file_size, `(${options.cli.toMagnitude(state.totalBytesIn, 1024)})`));
    const outStatus = options.cli.paint(ultimateOutputFolder, " ",
      options.cli.color(
        COLORS.file_size,
        `(${state.totalFiles} files, ${options.cli.toMagnitude(state.totalBytesOut, 1024)}B)`
      )
    );
    options.cli.display(`${filename} -> ${outStatus}${extras}`);
  });
}


function displayStatus(cli, state) {
  if (!state.currentFilename) return;
  const count = cli.color(COLORS.status_count, sprintf("%6s", state.totalFiles));
  const totalProgress = cli.color(
    COLORS.status_total_progress,
    sprintf(
      "%5s -> %5s",
      cli.toMagnitude(state.totalBytesIn, 1024),
      cli.toMagnitude(state.totalBytesOut + state.currentFileBytes, 1024)
    )
  );
  const fileProgress = (state.currentFileBytes > 0 && state.currentFileTotalBytes > 0) ?
    cli.color(
      COLORS.status_file_progress,
      `(${Math.floor(100 * state.currentFileBytes / state.currentFileTotalBytes)}%)`
    ) :
    "";
  cli.status(cli.paint(count, ": (", totalProgress, ")  ", state.currentFilename, " ", fileProgress));
}

function printFinishedFile(cli, state) {
  if (!state.currentFilename) return;
  const bytes = state.isFolder ?
    "     " :
    cli.color(
      COLORS.file_size,
      sprintf("%5s", cli.toMagnitude(state.currentFileTotalBytes)
    )
  );
  cli.display(cli.paint("  ", bytes, "  ", state.currentFilename));
}


exports.main = main;
