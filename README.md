# 4bottle

4bottle: the final archive format.

4bottle is a data & file format for archiving collections of files & folders, like "tar", "zip", and "winrar". Its primary differentiating features are:

- All important unix/posix attributes are preserved (owner, group, permissions, create/modify timestamps).
- The format is streamable: Files may be unpacked as an archive is read, and an archive may be written with minimal buffering.
- Compression may occur per-file or over the whole archive, using snappy (very fast) or LZMA2 (very compact).
- Modern crypto is used: SHA-512 for verification, and AES-256 for encryption. Encryption uses the keybase.io registry (and library).

## Status

As of today (January 2015), I'm pretty satisfied with the data format, so it's unlikely to change, but I reserve the right to make some last-minute adjustments over the next few months if I feel they're necessary. When I bump the version to 1.0, I'll promise not to change the underlying data format anymore, which should ensure all archive files are supported from then on.

There are some missing features that I'd like (listed in the TODO section below). Most are small things, but being able to (cryptographically) sign an archive is one feature I'd like to finish before declaring 1.0 victory. If you have any pet features (or bugs) that you consider a hard requirement, let me know, so I can take that into consideration.

## Usage

All of the command-line tools respond to `--help`.

To create an archive of the folder `myfiles`, called `myfiles.4b`:

    $ 4pack myfiles

To encrypt a folder of source code for keybase user robey, into an archive named `secret.4b`:

    $ 4pack -e robey -o secret.4b src/main/wibble/

To list the files in an archive called `myfiles.4b`:

    $ 4ls myfiles.4b

To unpack the archive `secret.4b` into a new temporary folder:

    $ 4unpack secret.4b -o temp


## TODO

- fix bullshit salt on password
- signed bottles
- force-overwrite mode for 4unpack

### blockers for 1.0

### later

- support symbolic links
- 4unpack should preserve ownership by default when running as root
- 4unpack should have an option to ignore ownership, and one to ignore permissions
- sparse files
