const net = require("net");
const os = require("os");
const request = require("supertest");
const {
    CIPHER_KEY_CHARACTERS,
    CODE_CHARACTERS,
    generateCipherKey,
    generateConnectCode
} = require("../../source/code.js");
const { createHost } = require("../../source/host.js");
const { getNewApp } = require("../app.js");

function getFreePort() {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.on("error", reject);
        server.listen(0, "127.0.0.1", () => {
            const { port } = server.address();
            server.close(() => resolve(port));
        });
    });
}

function tryConnect(host, port) {
    return new Promise(resolve => {
        const socket = net.connect({ host, port });
        socket.on("connect", () => {
            socket.destroy();
            resolve(true);
        });
        socket.on("error", () => resolve(false));
    });
}

describe("security", function() {
    describe("listening address", function() {
        let host;

        afterEach(function() {
            if (host) {
                host.stop();
                host = null;
            }
        });

        it("listens on the IPv4 loopback address only", async function() {
            const port = await getFreePort();
            host = createHost(port, "testing");
            await new Promise(resolve => host.server.on("listening", resolve));
            expect(host.server.address()).to.have.property("address", "127.0.0.1");
        });

        it("is not reachable on the machine's other addresses", async function() {
            const external = Object.values(os.networkInterfaces())
                .flat()
                .find(iface => iface.family === "IPv4" && iface.internal === false);
            if (!external) {
                this.skip();
            }
            const port = await getFreePort();
            host = createHost(port, "testing");
            await new Promise(resolve => host.server.on("listening", resolve));
            expect(await tryConnect("127.0.0.1", port)).to.equal(true);
            expect(await tryConnect(external.address, port)).to.equal(false);
        });
    });

    describe("Host and Origin headers", function() {
        let host;

        beforeEach(function() {
            host = getNewApp();
        });

        afterEach(function() {
            host.stop();
        });

        it("serves requests addressed to localhost", function() {
            return request(host.app).get("/").set("Host", "localhost:12821").expect(200);
        });

        it("serves requests addressed to the loopback addresses", async function() {
            await request(host.app).get("/").set("Host", "127.0.0.1:12821").expect(200);
            await request(host.app).get("/").set("Host", "[::1]:12821").expect(200);
        });

        it("rejects a Host that is not this machine (DNS rebinding)", function() {
            return request(host.app).get("/").set("Host", "evil.example.com:12821").expect(403);
        });

        it("rejects a Host that only starts with an allowed name", function() {
            return request(host.app).get("/").set("Host", "localhost.evil.example.com").expect(403);
        });

        it("rejects a request from a web page", function() {
            return request(host.app).get("/").set("Origin", "https://evil.example.com").expect(403);
        });

        it("rejects an Origin of null", function() {
            return request(host.app).get("/").set("Origin", "null").expect(403);
        });

        it("serves browser extension origins", async function() {
            await request(host.app).get("/").set("Origin", "chrome-extension://abcdefghijklmnop").expect(200);
            await request(host.app).get("/").set("Origin", "moz-extension://1234-5678-90ab").expect(200);
        });

        it("serves requests without an Origin", function() {
            return request(host.app).get("/").expect(200);
        });

        // A web page's no-cors GET (fetch, <img>, <script>) carries no Origin header. Chromium and
        // Firefox mark it with Sec-Fetch-Mode: no-cors (checked in browser.spec.js).
        it("rejects a no-cors request from a web page, which has no Origin", async function() {
            let codes = 0;
            host.emitter.on("codeReady", () => (codes += 1));
            await request(host.app)
                .get("/connect")
                .set("Sec-Fetch-Mode", "no-cors")
                .set("Sec-Fetch-Site", "cross-site")
                .expect(403);
            expect(codes).to.equal(0);
        });

        it("rejects a navigation from a web page, but not one typed in the address bar", async function() {
            await request(host.app)
                .get("/")
                .set("Sec-Fetch-Mode", "navigate")
                .set("Sec-Fetch-Site", "cross-site")
                .expect(403);
            await request(host.app)
                .get("/")
                .set("Sec-Fetch-Mode", "navigate")
                .set("Sec-Fetch-Site", "none")
                .expect(200);
        });

        it("serves a cors-mode request from an extension", function() {
            return request(host.app)
                .get("/")
                .set("Origin", "chrome-extension://abcdefghijklmnop")
                .set("Sec-Fetch-Mode", "cors")
                .set("Sec-Fetch-Site", "cross-site")
                .expect(200);
        });

        it("does not start pairing for a rejected request", async function() {
            let codes = 0;
            host.emitter.on("codeReady", () => (codes += 1));
            await request(host.app).get("/connect").set("Origin", "https://evil.example.com").expect(403);
            await request(host.app).get("/connect").set("Host", "evil.example.com").expect(403);
            expect(codes).to.equal(0);
            await request(host.app).get("/connect").expect(200);
            expect(codes).to.equal(1);
        });
    });

    describe("generated secrets", function() {
        let randomBefore;

        beforeEach(function() {
            randomBefore = Math.random;
            Math.random = () => {
                throw new Error("Math.random must not be used for secrets");
            };
        });

        afterEach(function() {
            Math.random = randomBefore;
        });

        it("generates a cipher key of 24 to 32 characters from the key alphabet", function() {
            for (let i = 0; i < 500; i += 1) {
                const key = generateCipherKey();
                expect(key.length).to.be.within(24, 32);
                for (const char of key) {
                    expect(CIPHER_KEY_CHARACTERS).to.include(char);
                }
            }
        });

        it("generates both ends of the cipher key length range", function() {
            const lengths = new Set();
            for (let i = 0; i < 2000; i += 1) {
                lengths.add(generateCipherKey().length);
            }
            expect(lengths.has(24)).to.equal(true);
            expect(lengths.has(32)).to.equal(true);
            expect(Math.max(...lengths)).to.equal(32);
            expect(Math.min(...lengths)).to.equal(24);
        });

        it("generates a connect code of 6 characters from the code alphabet", function() {
            for (let i = 0; i < 500; i += 1) {
                const code = generateConnectCode();
                expect(code).to.have.lengthOf(6);
                for (const char of code) {
                    expect(CODE_CHARACTERS).to.include(char);
                }
            }
        });

        it("does not repeat codes", function() {
            const codes = new Set();
            for (let i = 0; i < 1000; i += 1) {
                codes.add(generateConnectCode());
            }
            expect(codes.size).to.be.above(995);
        });
    });
});
