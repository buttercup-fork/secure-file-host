const fs = require("fs");
const os = require("os");
const path = require("path");
const request = require("supertest");
const { encryptString } = require("../../source/crypto.js");
const { getNewApp } = require("../app.js");

describe("request size", function() {
    let host;

    beforeEach(function() {
        host = getNewApp();
    });

    afterEach(function() {
        host.stop();
    });

    describe("POST /put/file", function() {
        const target = path.join(os.tmpdir(), "secure-file-host-limits.txt");

        afterEach(function() {
            try {
                fs.unlinkSync(target);
            } catch (err) {
                // not written
            }
        });

        it("writes a file of 2 MB (a large vault)", async function() {
            this.timeout(20000);
            const contents = "a".repeat(2 * 1024 * 1024);
            const payload = await encryptString(JSON.stringify({ filename: target, contents }), "testing");
            await request(host.app).post("/put/file").send({ payload }).expect(200);
            expect(fs.readFileSync(target, "utf8")).to.equal(contents);
        });

        it("answers 413 when the body is far too large", async function() {
            this.timeout(20000);
            await request(host.app)
                .post("/put/file")
                .send({ payload: "x".repeat(26 * 1024 * 1024) })
                .expect(413);
        });
    });
});
