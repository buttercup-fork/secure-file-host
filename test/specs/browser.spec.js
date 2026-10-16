// A real browser loading a page from another site. Skipped when Playwright and its browsers are not
// installed (it is not a dependency of this package); run with NODE_PATH pointing at a node_modules
// that has `playwright`, for example the desktop app's.
const http = require("http");
const net = require("net");
const { createHost } = require("../../source/host.js");

let playwright = null;
try {
    playwright = require("playwright");
} catch (err) {
    // not installed
}

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

function pageScript(target) {
    return `
        fetch("${target}/connect", { mode: "no-cors" }).catch(() => {});
        const img = new Image(); img.src = "${target}/connect";
        const s = document.createElement("script"); s.src = "${target}/connect"; document.head.appendChild(s);
        const frame = document.createElement("iframe"); frame.src = "${target}/connect"; document.body.appendChild(frame);
        fetch("${target}/connect/AAAAAA", { mode: "no-cors" }).catch(() => {});
        fetch("${target}/connect", { method: "POST", mode: "no-cors", headers: { "Content-Type": "text/plain" }, body: "x" }).catch(() => {});
        fetch("${target}/connect").catch(() => {});
    `;
}

describe("web page in a real browser", function() {
    if (!playwright) {
        it("needs Playwright (skipped)", function() {
            this.skip();
        });
        return;
    }

    this.timeout(60000);

    for (const name of ["chromium", "firefox"]) {
        it(`${name}: a page on another site cannot start or disturb pairing`, async function() {
            const hostPort = await getFreePort();
            const pagePort = await getFreePort();
            const host = createHost(hostPort, "testing");
            await new Promise(resolve => host.server.on("listening", resolve));
            let codes = 0;
            host.emitter.on("codeReady", () => (codes += 1));
            let failures = 0;
            host.emitter.on("connectionFailed", () => (failures += 1));
            const pageServer = http
                .createServer((req, res) => {
                    res.setHeader("Content-Type", "text/html");
                    res.end(`<html><body><script>${pageScript(`http://127.0.0.1:${hostPort}`)}</script></body></html>`);
                })
                .listen(pagePort, "127.0.0.1");
            let browser;
            try {
                browser = await playwright[name].launch();
                const page = await browser.newPage();
                await page.goto(`http://localhost:${pagePort}/`);
                await new Promise(resolve => setTimeout(resolve, 2000));
            } finally {
                if (browser) {
                    await browser.close();
                }
                pageServer.close();
                host.stop();
            }
            expect(codes, "pairing was started by a web page").to.equal(0);
            expect(failures, "pairing was blocked by a web page").to.equal(0);
        });
    }
});
