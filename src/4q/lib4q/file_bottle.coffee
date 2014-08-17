bottle_header = require "./bottle_header"
bottle_stream = require "./bottle_stream"
fs = require "fs"
posix = require "posix"
Q = require "q"
util = require "util"
zint = require "./zint"

FIELDS =
  STRINGS:
    FILENAME: 0
    MIME_TYPE: 1
    POSIX_USERNAME: 2
    POSIX_GROUPNAME: 3
  NUMBERS:
    SIZE: 0
    POSIX_MODE: 1
    CREATED_NANOS: 2
    MODIFIED_NANOS: 3
    ACCESSED_NANOS: 4
  BOOLS:
    IS_FOLDER: 0


fileHeaderFromFilename = (filename) ->
  deferred = Q.defer()
  fs.stat filename, (err, stats) ->
    if err? then return deferred.reject(err)
    stats.filename = filename
    stats.mode = stats.mode & 0x1ff
    stats.createdNanos = stats.ctime.getTime() * 1000000
    stats.modifiedNanos = stats.mtime.getTime() * 1000000
    stats.accessedNanos = stats.atime.getTime() * 1000000
    stats.folder = stats.isDirectory()
    stats.username = try
      posix.getpwnam(stats.uid).name
    catch e
      null
    stats.groupname = try
      posix.getgrnam(stats.gid).name
    catch e
      null
    deferred.resolve(stats)
  deferred.promise

encodeFileHeader = (stats) ->
  m = new bottle_header.Header()
  m.addString(FIELDS.STRINGS.FILENAME, stats.filename)
  if stats.mode? then m.addNumber(FIELDS.NUMBERS.POSIX_MODE, stats.mode)
  if stats.createdNanos? then m.addNumber(FIELDS.NUMBERS.CREATED_NANOS, stats.createdNanos)
  if stats.modifiedNanos? then m.addNumber(FIELDS.NUMBERS.MODIFIED_NANOS, stats.modifiedNanos)
  if stats.accessedNanos? then m.addNumber(FIELDS.NUMBERS.ACCESSED_NANOS, stats.accessedNanos)
  if stats.folder
    m.addBool(FIELDS.BOOLS.IS_FOLDER)
  else
    m.addNumber(FIELDS.NUMBERS.SIZE, stats.size)
  if stats.username? then m.addString(FIELDS.STRINGS.POSIX_USERNAME, stats.username)
  if stats.groupname? then m.addString(FIELDS.STRINGS.POSIX_GROUPNAME, stats.groupname)
  m

decodeFileHeader = (m) ->
  rv = { folder: false }
  for field in m.fields
    switch field.type
      when bottle_header.TYPE_STRING
        switch field.id
          when FIELDS.STRINGS.FILENAME then rv.filename = field.list[0]
          when FIELDS.STRINGS.MIME_TYPE then rv.mimeType = field.list[0]
          when FIELDS.STRINGS.POSIX_USERNAME then rv.username = field.list[0]
          when FIELDS.STRINGS.POSIX_GROUPNAME then rv.groupname = field.list[0]
      when bottle_header.TYPE_ZINT
        switch field.id
          when FIELDS.NUMBERS.SIZE then rv.size = field.number
          when FIELDS.NUMBERS.POSIX_MODE then rv.mode = field.number
          when FIELDS.NUMBERS.CREATED_NANOS then rv.createdNanos = field.number
          when FIELDS.NUMBERS.MODIFIED_NANOS then rv.modifiedNanos = field.number
          when FIELDS.NUMBERS.ACCESSED_NANOS then rv.accessedNanos = field.number
      when bottle_header.TYPE_BOOL
        switch field.id
          when FIELDS.BOOLS.IS_FOLDER then rv.folder = true
  rv

writeFileBottle = (stats, stream) ->
  s = new bottle_stream.WritableBottle(bottle_stream.TYPE_FILE, encodeFileHeader(stats))
  s.writeData(stream, stats.size).then ->
    s.close()
  s

writeFileBottleFromFile = (filename) ->
  fileHeaderFromFilename(filename).then (stats) ->
    writeFileBottle(stats, fs.createReadStream(filename))


exports.decodeFileHeader = decodeFileHeader
exports.encodeFileHeader = encodeFileHeader
exports.fileHeaderFromFilename = fileHeaderFromFilename
exports.writeFileBottle = writeFileBottle
exports.writeFileBottleFromFile = writeFileBottleFromFile