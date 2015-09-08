"use strict";

import errno from "errno";
import fs from "fs";
import Promise from "bluebird";
import sprintf from "sprintf";
import strftime from "strftime";

// some helpers for the command-line tools.

export const COLORS = {
  annotations: "99c",
  executable: "red",
  file_size: "green",
  importante: "c92",
  mode: "088",
  status_count: "0c8",
  status_file_progress: "0af",
  status_total_progress: "0c8",
  timestamp: "blue",
  user_group: "088"
};

// read a file into a stream, bailing with sys.exit(1) on errors.
export function readStream(cli, filename, showStack = false) {
  let fd = null;
  try {
    fd = fs.openSync(filename, "r");
  } catch (error) {
    console.log(`ERROR reading ${filename}: ${messageForError(error)}`);
    if (showStack) console.log(error.stack);
    process.exit(1);
  }

  const stream = fs.createReadStream(filename, { fd });
  stream.on("error", (error) => {
    cli.displayError(`Can't read ${filename}: ${messageForError(error)}`);
    if (showStack) console.log(error.stack);
    process.exit(1);
  });
  return stream;
}

export function messageForError(error) {
  if (error.cause) return error.message + ": " + messageForError(error.cause);
  if (error.code) return (errno.code[error.code] || {}).description || error.message;
  return error.message;
}

// NOW = Date.now()
// HOURS_20 = 20 * 60 * 60 * 1000
// DAYS_250 = 250 * 24 * 60 * 60 * 1000

// # either "13:45" or "10 Aug" or "2014"
// # (25 Aug 2014: this is stupid.)
// relativeDate = (nanos) ->
//   d = new Date(nanos / Math.pow(10, 6))
//   if d.getTime() > NOW or d.getTime() < NOW - DAYS_250
//     strftime("%Y", d)
//   else if d.getTime() < NOW - HOURS_20
//     strftime("%b %d", d)
//   else
//     strftime("%H:%M", d)

function fullDate(nanos) {
  const d = new Date(nanos / Math.pow(10, 6));
  return strftime("%Y-%m-%d %H:%M", d);
}

// convert a numeric mode into the "-rw----" wire
function modeToWire(mode, isFolder) {
  const octize = (n) => {
    return [
      (n & 4) != 0 ? "r" : "-",
      (n & 2) > 0 ? "w" : "-",
      (n & 1) != 0 ? "x" : "-"
    ].join("");
  }
  const d = isFolder ? "d" : "-";
  return d + octize((mode >> 6) & 7) + octize((mode >> 3) & 7) + octize(mode & 7);
}

export function summaryLineForFile(cli, stats, prefix, isVerbose) {
  const username = (stats.username || "nobody").slice(0, 8);
  const groupname = (stats.groupname || "nobody").slice(0, 8);
  const size = stats.size != null ? cli.toMagnitude(stats.size, 1024) : "     ";
  const time = fullDate(stats.modifiedNanos);
  const filename = stats.folder ?
    prefix + stats.filename + "/" : (
      (stats.mode & 0x40) != 0 ?
      cli.paint(cli.color(COLORS.executable, prefix + stats.filename + "*")) :
      prefix + stats.filename
    );
  const mode = cli.color(COLORS.mode, modeToWire(stats.mode || 0, stats.folder));
  const userdata = cli.color(COLORS.user_group, sprintf("%-8s %-8s", username, groupname));
  const colortime = cli.color(COLORS.timestamp, sprintf("%6s", time));
  const colorsize = cli.color(COLORS.file_size, sprintf("%5s", size));
  if (isVerbose) {
    return cli.paint(mode, "  ", userdata, " ", colortime, "  ", colorsize, "  ", filename);
  } else {
    return cli.paint("  ", colorsize, "  ", filename);
  }
}
