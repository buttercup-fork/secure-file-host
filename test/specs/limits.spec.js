const fs = require("fs");
const os = require("os");
const path = require("path");
const request = require("supertest");
const { encryptString } = require("../../source/crypto.js");
const { getNewApp } = require("../app.js");

describe("request size and error answers", function() {
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

        it("answers 413 as plain text when the body is far too large", async function() {
            this.timeout(20000);
            const res = await request(host.app)
                .post("/put/file")
                .send({ payload: "x".repeat(26 * 1024 * 1024) })
                .expect(413);
            expect(res.headers["content-type"]).to.match(/^text\/plain/);
            expect(res.text).to.equal("Payload Too Large");
        });
    });

    describe("error answers", function() {
        it("answers invalid JSON with 400 as plain text, without a stack trace", async function() {
            const res = await request(host.app)
                .post("/get/file")
                .set("Content-Type", "application/json")
                .send("{not json")
                .expect(400);
            expect(res.headers["content-type"]).to.match(/^text\/plain/);
            expect(res.text).to.equal("Bad Request");
        });
    });

    describe("pairing", function() {
        it("does not block pairing when a wrong code is tried and no code is pending", async function() {
            let failures = 0;
            host.emitter.on("connectionFailed", () => (failures += 1));
            await request(host.app).get("/connect/ABC123").expect(400);
            expect(failures).to.equal(0);
            await request(host.app).get("/connect").expect(200);
        });

        it("still blocks pairing after a wrong code while a code is pending", async function() {
            let failures = 0;
            host.emitter.on("connectionFailed", () => (failures += 1));
            await request(host.app).get("/connect").expect(200);
            await request(host.app).get("/connect/ABC123").expect(401);
            expect(failures).to.equal(1);
            await request(host.app).get("/connect").expect(503);
        });

        it("rejects a code of the wrong length", async function() {
            await request(host.app).get("/connect").expect(200);
            await request(host.app).get("/connect/ABC").expect(401);
        });
    });
});
