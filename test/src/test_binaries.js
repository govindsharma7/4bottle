"use strict";

import crypto from "crypto";
import fs from "fs";
import { exec, future, withTempFolder } from "mocha-sprinkles";
import path from "path";

import "should";
import "source-map-support/register";

const pack = `${process.cwd()}/bin/4pack`;
const ls = `${process.cwd()}/bin/4ls`;
const unpack = `${process.cwd()}/bin/4unpack`;

const sourceFolder = `${process.cwd()}/src`;
const xzFolder = `${process.cwd()}/node_modules/lib4bottle/node_modules/xz`;

function hashFile(filename) {
  const h = crypto.createHash("sha512");
  h.update(fs.readFileSync(filename));
  return h.digest();
}

// uh? this really isn't builtin?
function arraysAreEqual(x, y) {
  if (x.length != y.length) return false;
  for (let i = 0; i < x.length; i++) if (x[i] != y[i]) return false;
  return true;
}

function compareFolders(folder1, folder2) {
  const files1 = fs.readdirSync(folder1).sort();
  const files2 = fs.readdirSync(folder2).sort();
  if (!arraysAreEqual(files1, files2)) throw new Error(`Different file sets in ${folder1} vs ${folder2}`);
  files1.forEach((filename) => {
    const fullFilename1 = path.join(folder1, filename);
    const fullFilename2 = path.join(folder2, filename);
    if (fs.statSync(fullFilename1).isDirectory()) {
      if (!fs.statSync(fullFilename2).isDirectory()) {
        throw new Error(`Expected folder: ${fullFilename1} is, ${fullFilename2} is not.`);
      }
      return compareFolders(fullFilename1, fullFilename2);
    } else {
      if (fs.statSync(fullFilename2).isDirectory()) {
        throw new Error(`Expected folder: ${fullFilename1} is not, ${fullFilename2} is.`);
      }
      if (hashFile(fullFilename1).toString("hex") != hashFile(fullFilename2).toString("hex")) {
        throw new Error(`File ${fullFilename1} != ${fullFilename2}`);
      }
    }
  });
}


//
// effectively, these are integration tests.
// verify the behavior of "4pack", "4ls", and "4unpack".
//
describe("bin/4pack", () => {
  it("responds to --help", future(() => {
    return exec(`${pack} --help`).then((p) => {
      p.stderr.toString().should.eql("");
      p.stdout.toString().should.match(/usage:/);
      p.stdout.toString().should.match(/options:/);
    });
  }));

  it("packs, lists, and unpacks a single file", future(withTempFolder((folder) => {
    fs.writeFileSync(`${folder}/file1`, "nothing\n");
    return exec(`${pack} ${folder}/file1`).then(() => {
      fs.existsSync(`${folder}/file1.4b`).should.eql(true);
      return exec(`${ls} -l ${folder}/file1.4b`);
    }).then(p => {
      p.stdout.should.match(/\sfile1\s/);
      p.stdout.should.match(/\s8\s/);   // file length
      return exec(`${unpack} -o ${folder}/out ${folder}/file1.4b`);
    }).then((p) => {
      fs.existsSync(`${folder}/out/file1`).should.eql(true);
      fs.readFileSync(`${folder}/out/file1`).toString().should.eql("nothing\n");
    });
  })));

  it("packs, lists, and unpacks a set of files", future(withTempFolder((folder) => {
    fs.writeFileSync(`${folder}/file1`, "nothing\n");
    fs.writeFileSync(`${folder}/file2`, "nothing\n");
    fs.writeFileSync(`${folder}/file3`, "nothing\n");
    return exec(`${pack} -o ${folder}/test.4b ${folder}/file1 ${folder}/file2 ${folder}/file3`).then(() => {
      fs.existsSync(`${folder}/test.4b`).should.eql(true);
      return exec(`${ls} -l ${folder}/test.4b`);
    }).then((p) => {
      // three files, each length 8
      p.stdout.should.match(/\s8\s*test\/file1\s/);
      p.stdout.should.match(/\s8\s*test\/file2\s/);
      p.stdout.should.match(/\s8\s*test\/file3\s/);
      return exec(`${unpack} -o ${folder}/out ${folder}/test.4b`);
    }).then((p) => {
      fs.existsSync(`${folder}/out/test/file1`).should.eql(true);
      fs.readFileSync(`${folder}/out/test/file1`).toString().should.eql("nothing\n");
      fs.existsSync(`${folder}/out/test/file2`).should.eql(true);
      fs.readFileSync(`${folder}/out/test/file2`).toString().should.eql("nothing\n");
      fs.existsSync(`${folder}/out/test/file3`).should.eql(true);
      fs.readFileSync(`${folder}/out/test/file3`).toString().should.eql("nothing\n");
    });
  })));

  it("packs, lists, and unpacks a folder of files", (future(withTempFolder((folder) => {
    fs.mkdirSync(`${folder}/in`);
    fs.writeFileSync(`${folder}/in/file1`, "part 1\n");
    fs.writeFileSync(`${folder}/in/file2`, "part two\n");
    fs.writeFileSync(`${folder}/in/file3`, "part 333333\n");
    return exec(`${pack} -o ${folder}/test.4b ${folder}/in`).then(() => {
      fs.existsSync(`${folder}/test.4b`).should.eql(true);
      return exec(`${ls} -l ${folder}/test.4b`);
    }).then((p) => {
      // three files, each length 8.
      p.stdout.should.match(/\s7\s*in\/file1\s/);
      p.stdout.should.match(/\s9\s*in\/file2\s/);
      p.stdout.should.match(/\s12\s*in\/file3\s/);
      return exec(`${unpack} -o ${folder}/out ${folder}/test.4b`);
    }).then((p) => {
      fs.existsSync(`${folder}/out/in/file1`).should.eql(true);
      fs.readFileSync(`${folder}/out/in/file1`).toString().should.eql("part 1\n");
      fs.existsSync(`${folder}/out/in/file2`).should.eql(true);
      fs.readFileSync(`${folder}/out/in/file2`).toString().should.eql("part two\n");
      fs.existsSync(`${folder}/out/in/file3`).should.eql(true);
      fs.readFileSync(`${folder}/out/in/file3`).toString().should.eql("part 333333\n");
    });
  }))));

  it("encrypts and decrypts", future(withTempFolder((folder) => {
    fs.writeFileSync(`${folder}/file1`, "secrets!\n");
    return exec(`${pack} --password-here MrSparkle ${folder}/file1`).then(() => {
      fs.existsSync(`${folder}/file1.4b`).should.eql(true);
      return exec(`${ls} --password-here NOPE -l ${folder}/file1.4b`);
    }).then(p => {
      p.stdout.should.match(/error/i);
      return exec(`${ls} -l --password-here MrSparkle ${folder}/file1.4b`);
    }).then(p => {
      p.stdout.should.match(/\sfile1\s/i);
    });
  })));

  describe("preserves file contents", () => {
    it("source, with --snappy", future(withTempFolder((folder) => {
      return exec(`${pack} -q -o ${folder}/src.4b ${sourceFolder} -S`).then(() => {
        fs.existsSync(`${folder}/src.4b`).should.eql(true);
        return exec(`${unpack} -q -o ${folder}/src2 ${folder}/src.4b`);
      }).then(() => {
        return exec(`${ls} -q ${folder}/src.4b`).then((p) => {
          console.log(p.stdout);
          compareFolders(sourceFolder, `${folder}/src2/src`);
        });
      });
    })));

    it("node_modules, with --snappy", future(withTempFolder((folder) => {
      return exec(`${pack} -q -o ${folder}/xz.4b ${xzFolder} -S`).then(() => {
        fs.existsSync(`${folder}/xz.4b`).should.eql(true);
        return exec(`${unpack} -q -o ${folder}/xz ${folder}/xz.4b`);
      }).then(() => {
        return exec(`${ls} -q ${folder}/xz.4b`).then((p) => {
          console.log(p.stdout);
          compareFolders(xzFolder, `${folder}/xz/xz`);
        });
      });
    })));

    it("source, with xz", future(withTempFolder((folder) => {
      return exec(`${pack} -q -o ${folder}/src.4b ${sourceFolder}`).then(() => {
        fs.existsSync(`${folder}/src.4b`).should.eql(true);
        return exec(`${unpack} -q -o ${folder}/src2 ${folder}/src.4b`);
      }).then(() => {
        return exec(`${ls} -q ${folder}/src.4b`).then((p) => {
          console.log(p.stdout);
          compareFolders(sourceFolder, `${folder}/src2/src`);
        });
      });
    })));

    it("node_modules, with xz", future(withTempFolder((folder) => {
      return exec(`${pack} -q -o ${folder}/xz.4b ${xzFolder}`).then(() => {
        fs.existsSync(`${folder}/xz.4b`).should.eql(true);
        return exec(`${unpack} -q -o ${folder}/xz ${folder}/xz.4b`);
      }).then(() => {
        return exec(`${ls} -q ${folder}/xz.4b`).then((p) => {
          console.log(p.stdout);
          compareFolders(xzFolder, `${folder}/xz/xz`);
        });
      });
    })));
  });
});
