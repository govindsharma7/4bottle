fs = require "fs"
minimist = require "minimist"
path = require "path"
Q = require "q"
sprintf = require "sprintf"
stream = require "stream"
strftime = require "strftime"
toolkit = require "stream-toolkit"
util = require "util"

display = require "./display"
lib4q = require "./lib4q"
paint = require("./paint").paint

NOW = Date.now()

VERSION = "1.0.0"

COLORS =
  status_count: "cyan"
  status_size: "cyan"
  verbose_size: "green"

USAGE = """
usage: qpack [options] <filename(s)...>
    create a 4Q archive from a set of files (or folders)

options:
    --help
    -o <filename>
        archive filename to write
    -v
        verbose: display files as they're written
    -q
        quiet: display nothing unless there's an error
"""

main = ->
  argv = minimist(process.argv[2...], boolean: [ "help", "version" ])
  if argv.help or argv._.length == 0
    console.log USAGE
    process.exit(0)
  if argv.version
    console.log "qpack #{VERSION}"
    process.exit(0)
  if argv._.length == 0
    console.log "Required: filename(s) to archive"
    process.exit(1)
  if not argv.o?
    argv.o = if argv._.length > 1 then "archive.4q" else argv._[0] + ".4q"

  # quick sanity check: do all these files exist?
  okay = true
  for filename in argv._
    if not fs.existsSync(filename)
      console.log "Can't find file: #{filename}"
      okay = false
  if not okay then process.exit(1)

  try
    fd = fs.openSync(argv.o, "w")
  catch err
    console.log "ERROR writing #{argv.o}: #{err.message}"
    process.exit(1)
  outStream = fs.createWriteStream(filename, fd: fd)

  updater = new StatusUpdater(verbose: argv.v, quiet: argv.q)
  countingOutStream = new toolkit.CountingStream()
  countingOutStream.on "count", (n) ->
    updater.totalBytes = n
    updater.update()
  countingOutStream.pipe(outStream)

  promise = if argv._.length > 1
    # multiple files: just make a fake folder
    folderName = path.join(path.dirname(argv.o), path.basename(argv.o, ".4q"))
    nowNanos = Date.now() * Math.pow(10, 6)
    stats =
      folder: true
      filename: folderName
      mode: 0x1c0
      createdNanos: nowNanos
      modifiedNanos: nowNanos
      accessedNanos: nowNanos
    s = lib4q.writeFileBottle(stats, null)
    Q.all([
      pushBottle(countingOutStream, s)
      archiveFiles(s, updater, null, argv._, folderName).then ->
        s.close()
    ])
  else
    archiveFile(countingOutStream, updater, argv._[0], null).then ->
      countingOutStream.end()
      toolkit.qfinish(countingOutStream)
  promise.then ->
    toolkit.qfinish(outStream)
  .then ->
    updater.clear()
    if not argv.q then process.stdout.write "#{argv.o} (#{updater.fileCount} files, #{display.humanize(updater.totalBytes)} bytes)\n"
  .fail (err) ->
    console.log "\nERROR: #{err.message}"
    process.exit(1)
  .done()


archiveFiles = (outStream, updater, folder, filenames, prefix) ->
  if filenames.length == 0 then return Q()
  filename = filenames.shift()
  filepath = if folder? then path.join(folder, filename) else filename
  archiveFile(outStream, updater, filepath, prefix).then ->
    archiveFiles(outStream, updater, folder, filenames, prefix)

archiveFile = (outStream, updater, filename, prefix) ->
  basename = path.basename(filename)
  qify(fs.stat)(filename).then (stats) ->
    stats = lib4q.fileHeaderFromStats(filename, basename, stats)
    displayName = if prefix? then path.join(prefix, basename) else basename
    updater.setName(displayName)
    if stats.folder
      archiveFolder(outStream, updater, filename, prefix, stats, displayName)
    else
      updater.fileCount += 1
      qify(fs.open)(filename, "r").then (fd) ->
        fileStream = fs.createReadStream(filename, fd: fd)
        countingFileStream = new toolkit.CountingStream()
        countingFileStream.on "count", (n) ->
          updater.currentBytes = n
          updater.update()
        fileStream.pipe(countingFileStream)
        pushBottle(outStream, lib4q.writeFileBottle(stats, countingFileStream)).then ->
          updater.finishedFile()

archiveFolder = (outStream, updater, folder, prefix, stats, displayName) ->
  folderOutStream = lib4q.writeFileBottle(stats, null)
  qify(fs.readdir)(folder).then (files) ->
    Q.all([
      pushBottle(outStream, folderOutStream)
      archiveFiles(folderOutStream, updater, folder, files, displayName).then ->
        folderOutStream.close()
    ])

pushBottle = (outStream, bottle) ->
  if outStream instanceof lib4q.WritableBottle
    outStream.writeData(bottle)
  else
    toolkit.qpipe(bottle, outStream, end: false)

qify = (f) ->
  (arg...) ->
    deferred = Q.defer()
    f arg..., (err, rv) ->
      if err? then return deferred.reject(err)
      deferred.resolve(rv)
    deferred.promise


class StatusUpdater
  constructor: (@options) ->
    @totalBytes = 0
    @currentBytes = 0
    @fileCount = 0
    @lastUpdate = 0
    @frequency = 500

  setName: (filename) ->
    @currentBytes = 0
    @filename = filename
    @forceUpdate()

  finishedFile: ->
    if not @options.verbose then return
    @clear()
    bytes = paint.color(COLORS.verbose_size, sprintf("%5s", display.humanize(@currentBytes)))
    process.stdout.write paint("  ", bytes, "  ", @filename).toString() + "\n"

  clear: ->
    @lastUpdate = 0
    if not @options.quiet then display.displayStatus ""

  forceUpdate: ->
    @lastUpdate = 0
    @update()

  update: ->
    if @options.quiet then return
    now = Date.now()
    if now > @lastUpdate + @frequency and @filename?
      @lastUpdate = now
      count = paint.color(COLORS.status_count, sprintf("%6s", @fileCount))
      progress = paint.color(COLORS.status_size, sprintf("%5s/%5s", display.humanize(@currentBytes), display.humanize(@totalBytes)))
      display.displayStatus paint(count, ": (", progress, ")  ", @filename, " ")


exports.main = main