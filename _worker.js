/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run "npm run dev" in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run "npm run deploy" to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

import { connect } from 'cloudflare:sockets';

let subPath = 'subInfo';
let subPathLow;
let readyHosts = [atob('c3BlZWQuY2xvd' + 'WRmbGFyZS5jb20=')];
let enableSocks = false;
let enableHttp = false;
let proxyIP = '';
let parsedSocks5Address = {};
let DNS64Server = '';

let go2Socks5s = [
    '*tapecontent.net',
    '*cloudatacdn.com',
    '*ttvnw.net',
    '*.loadshare.org'
];

let BotToken;
let ChatID;
let FileName = atob('ZWRnZXR1' + 'bm5lbA==');
let RproxyIP = 'false';
const expire = 4102329599
let addresses = [];
const httpPorts = ["8080", "8880", "2052", "2082", "2086", "2095"];
let httpsPorts = ["2053", "2083", "2087", "2096", "8443"];
let addressesapi = [];
let addressesnotls = [];
let addressesnotlsapi = [];
let addressescsv = [];
let link = [];

let proxyhosts = [];
let proxyhostsURL = atob('aHR0cHM6Ly9yYXcuZ2l0aHVid' + 'XNlcmNvbnRlbnQuY29tL2NtbGl1L2Nt' + 'bGl1L21haW4vUHJveHlIT1NU');
let noTLS = 'false';
let socks5s;
let subProtocol = 'https';
let path = '/?ed=2560';
let subConverter = atob('U1VCQVBJLkNN' + 'TGl1c3Nzcy5uZXQ=');
let subConfig = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNv' + 'bnRlbnQuY29tL0FDTDRTU1IvQUNMNFNTUi9tYXN0ZXIvQ2xhc2gvY29uZmlnL0FDTDRTU1JfT25saW5lX01pbmlfTXVsdGlNb2RlLmluaQ==');
let subEmoji = 'true';
let SCV = 'true';
let allowInsecure = '&allowInsecure=1';
let proxyIPPool = [];
let DLS = 8;
let remarkIndex = 1;
let socks5Address = '';

export default {
    async fetch(request, env, ctx) {

        const upgradeHeader = request.headers.get('Upgrade');
        const url = new URL(request.url);
        const UA = request.headers.get('User-Agent') || 'null';
        const userAgent = UA.toLowerCase();


        if (!upgradeHeader || upgradeHeader !== 'websocket') {

            BotToken = env.TGTOKEN || BotToken;
            ChatID = env.TGID || ChatID;
            socks5s = await 整理(socks5Address);

            const currentDate = new Date();
            currentDate.setHours(0, 0, 0, 0);
            const timestamp = Math.ceil(currentDate.getTime() / 1000);

            const mirrorUserIDMD5 = await 双重哈希(`${subPath}${timestamp}`);
            const mirrorUserID = [
                mirrorUserIDMD5.slice(0, 8),
                mirrorUserIDMD5.slice(8, 12),
                mirrorUserIDMD5.slice(12, 16),
                mirrorUserIDMD5.slice(16, 20),
                mirrorUserIDMD5.slice(20)
            ].join('-');
            let sub = env.SUB || '';
            const mirrorHostName = `${mirrorUserIDMD5.slice(6, 9)}.${mirrorUserIDMD5.slice(13, 19)}`;

            const reqPath = url.pathname.toLowerCase();
            if (reqPath == '/') {
                if (env.URL302) return Response.redirect(env.URL302, 302);
                else return new Response('Hello World!');
            } else if (url.pathname == `/${subPath}`) {
                await sendMessage(`#获取订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${UA}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);
                const epConfig = await genConf(subPath, request.headers.get('Host'), sub, UA, RproxyIP, url, mirrorUserID, mirrorHostName, env);
                const now = Date.now();
                const today = new Date(now);
                today.setHours(0, 0, 0, 0);
                const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
                let pagesSum = UD;
                let workersSum = UD;
                let total = 24 * 1099511627776;
                if (userAgent && userAgent.includes('mozilla')) {
                    return new Response(epConfig, {
                        status: 200,
                        headers: {
                            "Content-Type": "text/html;charset=utf-8",
                            "Profile-Update-Interval": "6",
                            "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                            "Cache-Control": "no-store",
                        }
                    });
                } else {
                    return new Response(epConfig, {
                        status: 200,
                        headers: {
                            "Content-Disposition": `attachment; filename=${FileName}; filename*=utf-8''${encodeURIComponent(FileName)}`,
                            "Profile-Update-Interval": "6",
                            "Profile-web-page-url": request.url.includes('?') ? request.url.split('?')[0] : request.url,
                            "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                        }
                    });
                }
            } else {
                return new Response('Hello World! Path: ' + reqPath);
            }
        } else {
            return await epOverWSHandler(request);
        }

    }
};

async function epOverWSHandler(request) {

    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);

    webSocket.accept();

    let address = '';

    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);

    let remoteSocketWapper = {
        value: null,
    };
    let udpStreamWrite = null;
    let isDns = false;

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (isDns && udpStreamWrite) {
                return udpStreamWrite(chunk);
            }
            if (remoteSocketWapper.value) {
                const writer = remoteSocketWapper.value.writable.getWriter()
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            const {
                hasError,
                message,
                addressType,
                portRemote = 443,
                addressRemote = '',
                rawDataIndex,
                epVersion = new Uint8Array([0, 0]),
                isUDP,
            } = processEpHeader(chunk, subPath);

            address = addressRemote;
            if (hasError) {
                throw new Error(message);
            }
            if (isUDP) {
                if (portRemote === 53) {
                    isDns = true;
                } else {
                    throw new Error('UDP PX is only for DNS 53 port');
                }
            }
            const epResponseHeader = new Uint8Array([epVersion[0], 0]);
            const rawClientData = chunk.slice(rawDataIndex);

            if (isDns) {
                const { write } = await handleUDPOutBound(webSocket, epResponseHeader);
                udpStreamWrite = write;
                udpStreamWrite(rawClientData);
                return;
            }
            if (!readyHosts.includes(addressRemote)) {
                handleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, epResponseHeader);
            } else {
                throw new Error(`Black list TCP outbound ${addressRemote}:${portRemote}`);
            }
        },
        close() {

        },
        abort(reason) {

        },
    })).catch((err) => {

    });

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader) {
    let readableStreamCancel = false;

    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener('message', (event) => {
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                controller.enqueue(message);
            });

            webSocketServer.addEventListener('close', () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            });

            webSocketServer.addEventListener('error', (err) => {
                controller.error(err);
            });

            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },

        pull(controller) { },

        cancel(reason) {
            if (readableStreamCancel) {
                return;
            }
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });

    return stream;
}

function processEpHeader(epBuffer, subPath) {
    if (epBuffer.byteLength < 24) {
        return {
            hasError: true,
            message: 'invalid data',
        };
    }

    const version = new Uint8Array(epBuffer.slice(0, 1));

    let isValidUser = false;
    let isUDP = false;

    function issubPathValid(subPath, subPathLow, buffer) {
        const subPathArray = new Uint8Array(buffer.slice(1, 17));
        const subPathString = strify(subPathArray);
        return subPathString === subPath || subPathString === subPathLow;
    }

    isValidUser = issubPathValid(subPath, subPathLow, epBuffer);

    if (!isValidUser) {
        return {
            hasError: true,
            message: `invalid user ${(new Uint8Array(epBuffer.slice(1, 17)))}`,
        };
    }

    const optLength = new Uint8Array(epBuffer.slice(17, 18))[0];
    const command = new Uint8Array(
        epBuffer.slice(18 + optLength, 18 + optLength + 1)
    )[0];

    if (command === 1) {

    } else if (command === 2) {
        isUDP = true;
    } else {
        return {
            hasError: true,
            message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
        };
    }

    const portIndex = 18 + optLength + 1;
    const portBuffer = epBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(
        epBuffer.slice(addressIndex, addressIndex + 1)
    );

    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = '';

    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(
                epBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            ).join('.');
            break;
        case 2:
            addressLength = new Uint8Array(
                epBuffer.slice(addressValueIndex, addressValueIndex + 1)
            )[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(
                epBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            break;
        case 3:
            addressLength = 16;
            const dataView = new DataView(
                epBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(':');
            break;
        default:
            return {
                hasError: true,
                message: `invild addressType is ${addressType}`,
            };
    }

    if (!addressValue) {
        return {
            hasError: true,
            message: `addressValue is empty, addressType is ${addressType}`,
        };
    }

    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        epVersion: version,
        isUDP,
    };
}

async function handleUDPOutBound(webSocket, epResponseHeader) {

    let isEpHeaderSent = false;
    const transformStream = new TransformStream({
        start(controller) {

        },
        transform(chunk, controller) {
            for (let index = 0; index < chunk.byteLength;) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(
                    chunk.slice(index + 2, index + 2 + udpPakcetLength)
                );
                index = index + 2 + udpPakcetLength;
                controller.enqueue(udpData);
            }
        },
        flush(controller) {
        }
    });

    transformStream.readable.pipeTo(new WritableStream({
        async write(chunk) {
            const resp = await fetch('https://1.1.1.1/dns-query',
                {
                    method: 'POST',
                    headers: {
                        'content-type': 'application/dns-message',
                    },
                    body: chunk,
                })
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
            if (webSocket.readyState === WS_READY_STATE_OPEN) {
                if (isEpHeaderSent) {
                    webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                } else {
                    webSocket.send(await new Blob([epResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                    isEpHeaderSent = true;
                }
            }
        }
    })).catch((error) => { });

    const writer = transformStream.writable.getWriter();

    return {
        write(chunk) {
            writer.write(chunk);
        }
    };
}

async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, epResponseHeader) {
    async function useSocks5Pattern(address) {
        if (go2Socks5s.includes(atob('YWxsIGlu')) || go2Socks5s.includes(atob('Kg=='))) return true;
        return go2Socks5s.some(pattern => {
            let regexPattern = pattern.replace(/\*/g, '.*');
            let regex = new RegExp(`^${regexPattern}$`, 'i');
            return regex.test(address);
        });
    }

    async function connectAndWrite(address, port, socks = false, http = false) {
        const tcpSocket = socks
            ? (http ? await httpConnect(address, port) : await sosConnect(addressType, address, port))
            : connect({ hostname: address, port: port });

        remoteSocket.value = tcpSocket;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    async function nat64() {
        if (!useSocks) {
            const nat64Proxyip = `[${await resolveToIPv6(addressRemote)}]`;
            tcpSocket = await connectAndWrite(nat64Proxyip, 443);
        }
        tcpSocket.closed.catch(error => { }).finally(() => {
            safeCloseWebSocket(webSocket);
        })
        remoteSocketToWS(tcpSocket, webSocket, epResponseHeader, null);
    }

    async function retry() {
        if (enableSocks) {
            tcpSocket = await connectAndWrite(addressRemote, portRemote, true, enableHttp);
        } else {
            if (!proxyIP || proxyIP == '') {
                proxyIP = atob('UFJPWFlJUC50c' + 'DEuMDkwMjI3Lnh5eg==');
            } else if (proxyIP.includes(']:')) {
                portRemote = proxyIP.split(']:')[1] || portRemote;
                proxyIP = proxyIP.split(']:')[0] + "]" || proxyIP;
            } else if (proxyIP.split(':').length === 2) {
                portRemote = proxyIP.split(':')[1] || portRemote;
                proxyIP = proxyIP.split(':')[0] || proxyIP;
            }
            if (proxyIP.includes('.tp')) portRemote = proxyIP.split('.tp')[1].split('.')[0] || portRemote;
            tcpSocket = await connectAndWrite(proxyIP.toLowerCase() || addressRemote, portRemote);
        }
        remoteSocketToWS(tcpSocket, webSocket, epResponseHeader, nat64);
    }

    let useSocks = false;
    if (go2Socks5s.length > 0 && enableSocks) useSocks = await useSocks5Pattern(addressRemote);
    let tcpSocket = await connectAndWrite(addressRemote, portRemote, useSocks, enableHttp);

    remoteSocketToWS(tcpSocket, webSocket, epResponseHeader, retry);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) { }
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) {
        return { earlyData: undefined, error: null };
    }
    try {
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: undefined, error };
    }
}

function strify(arr, offset = 0) {
    const uuid = unStrify(arr, offset);
    if (!checkUUID(uuid)) {
        throw TypeError(`gen UUID not correct ${uuid}`);
    }
    return uuid;
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
    byteToHex.push((i + 256).toString(16).slice(1));
}

function unStrify(arr, offset = 0) {
    return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" +
        byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" +
        byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" +
        byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" +
        byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] +
        byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function checkUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

async function httpConnect(addressRemote, portRemote) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const sock = await connect({
        hostname: hostname,
        port: port
    });

    let connectRequest = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\n`;
    connectRequest += `Host: ${addressRemote}:${portRemote}\r\n`;

    if (username && password) {
        const authString = `${username}:${password}`;
        const base64Auth = btoa(authString);
        connectRequest += `Proxy-Authorization: Basic ${base64Auth}\r\n`;
    }

    connectRequest += `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n`;
    connectRequest += `Proxy-Connection: Keep-Alive\r\n`;
    connectRequest += `Connection: Keep-Alive\r\n`;
    connectRequest += `\r\n`;

    try {
        const writer = sock.writable.getWriter();
        await writer.write(new TextEncoder().encode(connectRequest));
        writer.releaseLock();
    } catch (err) {
        throw new Error(`send HTTP CONNECT request failed: ${err.message}`);
    }

    const reader = sock.readable.getReader();
    let respText = '';
    let connected = false;
    let responseBuffer = new Uint8Array(0);

    try {
        while (true) {
            const { value, done } = await reader.read();
            if (done) {
                throw new Error('HTTP PX breadk');
            }

            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;

            respText = new TextDecoder().decode(responseBuffer);

            if (respText.includes('\r\n\r\n')) {
                const headersEndPos = respText.indexOf('\r\n\r\n') + 4;
                const headers = respText.substring(0, headersEndPos);

                if (headers.startsWith('HTTP/1.1 200') || headers.startsWith('HTTP/1.0 200')) {
                    connected = true;

                    if (headersEndPos < responseBuffer.length) {
                        const remainingData = responseBuffer.slice(headersEndPos);
                        const dataStream = new ReadableStream({
                            start(controller) {
                                controller.enqueue(remainingData);
                            }
                        });

                        const { readable, writable } = new TransformStream();
                        dataStream.pipeTo(writable).catch(err => { });

                        sock.readable = readable;
                    }
                } else {
                    const errorMsg = `HTTP PX connect failed: ${headers.split('\r\n')[0]}`;
                    throw new Error(errorMsg);
                }
                break;
            }
        }
    } catch (err) {
        reader.releaseLock();
        throw new Error(`handle HTTP PX response failed: ${err.message}`);
    }

    reader.releaseLock();

    if (!connected) {
        throw new Error('HTTP PX failed');
    }
    return sock;
}

async function sosConnect(addressType, addressRemote, portRemote) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const socket = connect({
        hostname,
        port,
    });

    const socksGreeting = new Uint8Array([5, 2, 0, 2]);
    const writer = socket.writable.getWriter();

    await writer.write(socksGreeting);
    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();
    let res = (await reader.read()).value;

    if (res[0] !== 0x05) {
        return;
    }
    if (res[1] === 0xff) {
        return;
    }

    if (res[1] === 0x02) {
        if (!username || !password) {
            return;
        }

        const authRequest = new Uint8Array([
            1,
            username.length,
            ...encoder.encode(username),
            password.length,
            ...encoder.encode(password)
        ]);
        await writer.write(authRequest);
        res = (await reader.read()).value;
        if (res[0] !== 0x01 || res[1] !== 0x00) {

            return;
        }
    }

    let DSTADDR;
    switch (addressType) {
        case 1:
            DSTADDR = new Uint8Array(
                [1, ...addressRemote.split('.').map(Number)]
            );
            break;
        case 2:
            DSTADDR = new Uint8Array(
                [3, addressRemote.length, ...encoder.encode(addressRemote)]
            );
            break;
        case 3:
            DSTADDR = new Uint8Array(
                [4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
            );
            break;
        default:
            return;
    }
    const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
    await writer.write(socksRequest);


    res = (await reader.read()).value;
    if (res[1] === 0x00) {

    } else {

        return;
    }
    writer.releaseLock();
    reader.releaseLock();
    return socket;
}

async function resolveToIPv6(target) {
    const defaultAddress = atob('cHJveHlpcC5jb' + 'WxpdXNzc3MubmV0');
    if (!DNS64Server) {
        try {
            const response = await fetch(atob('aHR0cHM6Ly8xLjE' + 'uMS4xL2Rucy1xdWVyeT9uYW1lPW5hdDY0Lm' + 'NtbGl1c3Nzcy5uZXQmdHlwZT1UWFQ='), {
                headers: { 'Accept': 'application/dns-json' }
            });

            if (!response.ok) return defaultAddress;
            const data = await response.json();
            const txtRecords = (data.Answer || []).filter(record => record.type === 16).map(record => record.data);

            if (txtRecords.length === 0) return defaultAddress;
            let txtData = txtRecords[0];
            if (txtData.startsWith('"') && txtData.endsWith('"')) txtData = txtData.slice(1, -1);
            const prefixes = txtData.replace(/\\010/g, '\n').split('\n').filter(prefix => prefix.trim());
            if (prefixes.length === 0) return defaultAddress;
            DNS64Server = prefixes[Math.floor(Math.random() * prefixes.length)];
        } catch (error) {
            return defaultAddress;
        }
    }

    function isIPv4(str) {
        const parts = str.split('.');
        return parts.length === 4 && parts.every(part => {
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255 && part === num.toString();
        });
    }

    function isIPv6(str) {
        return str.includes(':') && /^[0-9a-fA-F:]+$/.test(str);
    }

    async function fetchIPv4(domain) {
        const url = `https://1.1.1.1/dns-query?name=${domain}&type=A`;
        const response = await fetch(url, {
            headers: { 'Accept': 'application/dns-json' }
        });

        if (!response.ok) throw new Error('DNS查询失败');

        const data = await response.json();
        const ipv4s = (data.Answer || [])
            .filter(record => record.type === 1)
            .map(record => record.data);

        if (ipv4s.length === 0) throw new Error('not found IPv4');
        return ipv4s[Math.floor(Math.random() * ipv4s.length)];
    }

    async function queryNAT64(domain) {
        const socket = connect({
            hostname: isIPv6(DNS64Server) ? `[${DNS64Server}]` : DNS64Server,
            port: 53
        });

        const writer = socket.writable.getWriter();
        const reader = socket.readable.getReader();

        try {
            const query = buildDNSQuery(domain);
            const queryWithLength = new Uint8Array(query.length + 2);
            queryWithLength[0] = query.length >> 8;
            queryWithLength[1] = query.length & 0xFF;
            queryWithLength.set(query, 2);
            await writer.write(queryWithLength);

            const response = await readDNSResponse(reader);
            const ipv6s = parseIPv6(response);

            return ipv6s.length > 0 ? ipv6s[0] : '未找到IPv6地址';
        } finally {
            await writer.close();
            await reader.cancel();
        }
    }

    function buildDNSQuery(domain) {
        const buffer = new ArrayBuffer(512);
        const view = new DataView(buffer);
        let offset = 0;

        view.setUint16(offset, Math.floor(Math.random() * 65536)); offset += 2;
        view.setUint16(offset, 0x0100); offset += 2;
        view.setUint16(offset, 1); offset += 2;
        view.setUint16(offset, 0); offset += 6;

        for (const label of domain.split('.')) {
            view.setUint8(offset++, label.length);
            for (let i = 0; i < label.length; i++) {
                view.setUint8(offset++, label.charCodeAt(i));
            }
        }
        view.setUint8(offset++, 0);

        view.setUint16(offset, 28); offset += 2;
        view.setUint16(offset, 1); offset += 2;

        return new Uint8Array(buffer, 0, offset);
    }

    async function readDNSResponse(reader) {
        const chunks = [];
        let totalLength = 0;
        let expectedLength = null;

        while (true) {
            const { value, done } = await reader.read();
            if (done) break;

            chunks.push(value);
            totalLength += value.length;

            if (expectedLength === null && totalLength >= 2) {
                expectedLength = (chunks[0][0] << 8) | chunks[0][1];
            }

            if (expectedLength !== null && totalLength >= expectedLength + 2) {
                break;
            }
        }

        const fullResponse = new Uint8Array(totalLength);
        let offset = 0;
        for (const chunk of chunks) {
            fullResponse.set(chunk, offset);
            offset += chunk.length;
        }

        return fullResponse.slice(2);
    }

    function parseIPv6(response) {
        const view = new DataView(response.buffer);
        let offset = 12;

        while (view.getUint8(offset) !== 0) {
            offset += view.getUint8(offset) + 1;
        }
        offset += 5;

        const answers = [];
        const answerCount = view.getUint16(6);

        for (let i = 0; i < answerCount; i++) {
            if ((view.getUint8(offset) & 0xC0) === 0xC0) {
                offset += 2;
            } else {
                while (view.getUint8(offset) !== 0) {
                    offset += view.getUint8(offset) + 1;
                }
                offset++;
            }

            const type = view.getUint16(offset); offset += 2;
            offset += 6;
            const dataLength = view.getUint16(offset); offset += 2;

            if (type === 28 && dataLength === 16) {
                const parts = [];
                for (let j = 0; j < 8; j++) {
                    parts.push(view.getUint16(offset + j * 2).toString(16));
                }
                answers.push(parts.join(':'));
            }
            offset += dataLength;
        }

        return answers;
    }

    function convertToNAT64IPv6(ipv4Address) {
        const parts = ipv4Address.split('.');
        if (parts.length !== 4) {
            throw new Error('invalid IPv4');
        }

        const hex = parts.map(part => {
            const num = parseInt(part, 10);
            if (num < 0 || num > 255) {
                throw new Error('invalid IPv4 range');
            }
            return num.toString(16).padStart(2, '0');
        });

        return DNS64Server.split('/96')[0] + hex[0] + hex[1] + ":" + hex[2] + hex[3];
    }

    try {
        if (isIPv6(target)) return target;
        const ipv4 = isIPv4(target) ? target : await fetchIPv4(target);
        const nat64 = DNS64Server.endsWith('/96') ? convertToNAT64IPv6(ipv4) : await queryNAT64(ipv4 + atob('LmlwLjA5MD' + 'IyNy54eXo='));
        return isIPv6(nat64) ? nat64 : defaultAddress;
    } catch (error) {
        return defaultAddress;
    }
}

async function remoteSocketToWS(remoteSocket, webSocket, epResponseHeader, retry) {
    let remoteChunkCount = 0;
    let chunks = [];
    /** @type {ArrayBuffer | null} */
    let 维列斯Header = epResponseHeader;
    let hasIncomingData = false;

    await remoteSocket.readable
        .pipeTo(
            new WritableStream({
                start() {

                },
                async write(chunk, controller) {
                    hasIncomingData = true;


                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {

                    }

                    if (维列斯Header) {
                        webSocket.send(await new Blob([维列斯Header, chunk]).arrayBuffer());
                        维列斯Header = null;
                    } else {

                        webSocket.send(chunk);
                    }
                },
                close() {

                },
                abort(reason) {

                },
            })
        )
        .catch((error) => {

            safeCloseWebSocket(webSocket);
        });

    if (hasIncomingData === false && retry) {

        retry();
    }
}

async function sendMessage(type, ip, add_data = "") {
    if (!BotToken || !ChatID) return;

    try {
        let msg = "";
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
        if (response.ok) {
            const ipInfo = await response.json();
            msg = `${type}\nIP: ${ip}\n国家: ${ipInfo.country}\n<tg-spoiler>城市: ${ipInfo.city}\n组织: ${ipInfo.org}\nASN: ${ipInfo.as}\n${add_data}`;
        } else {
            msg = `${type}\nIP: ${ip}\n<tg-spoiler>${add_data}`;
        }

        const url = `https://api.telegram.org/bot${BotToken}/sendMessage?chat_id=${ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
        return fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;',
                'Accept-Encoding': 'gzip, deflate, br',
                'User-Agent': 'Mozilla/5.0 Chrome/90.0.4430.72'
            }
        });
    } catch (error) { }
}

let subParams = ['sub', 'b64', 'sb'];

const shaFun = atob('ZG14b' + 'GMzTT0=');

async function genConf(userID, hostName, sub, UA, RproxyIP, _url, mirrorUserID, mirrorHostName, env) {
    if (sub) {
        const match = sub.match(/^(?:https?:\/\/)?([^\/]+)/);
        if (match) {
            sub = match[1];
        }
        const subs = await 整理(sub);
        if (subs.length > 1) sub = subs[0];
    } else {
        if (env.KV) {
            await 迁移地址列表(env);
            const 优选地址列表 = await env.KV.get('ADD.txt');
            if (优选地址列表) {
                const 优选地址数组 = await 整理(优选地址列表);
                const 分类地址 = {
                    接口地址: new Set(),
                    链接地址: new Set(),
                    优选地址: new Set()
                };

                for (const 元素 of 优选地址数组) {
                    if (元素.startsWith('https://')) {
                        分类地址.接口地址.add(元素);
                    } else if (元素.includes('://')) {
                        分类地址.链接地址.add(元素);
                    } else {
                        分类地址.优选地址.add(元素);
                    }
                }

                addressesapi = [...分类地址.接口地址];
                link = [...分类地址.链接地址];
                addresses = [...分类地址.优选地址];
            }
        }

        if ((addresses.length + addressesapi.length + addressesnotls.length + addressesnotlsapi.length + addressescsv.length) == 0) {
            let cfips = ['104.16.0.0/13', '162.159.152.0/23',
                '172.64.146.0/24',
                '172.64.229.0/24',
                '104.16.0.0/16',
                '104.17.0.0/16',
                '104.18.0.0/16',
                '104.19.0.0/16',
                '104.20.0.0/16',
                '104.21.0.0/16',
                '104.22.0.0/16',
                '104.24.0.0/16',
                '104.25.0.0/16',
                '104.26.0.0/16',
                '104.27.0.0/16',
                '172.66.0.0/16',
                '172.67.0.0/16'];

            // 生成符合给定 CIDR 范围的随机 IP 地址
            function generateRandomIPFromCIDR(cidr) {
                const [base, mask] = cidr.split('/');
                const baseIP = base.split('.').map(Number);
                const subnetMask = 32 - parseInt(mask, 10);
                const maxHosts = Math.pow(2, subnetMask) - 1;
                const randomHost = Math.floor(Math.random() * maxHosts);

                const randomIP = baseIP.map((octet, index) => {
                    if (index < 2) return octet;
                    if (index === 2) return (octet & (255 << (subnetMask - 8))) + ((randomHost >> 8) & 255);
                    return (octet & (255 << subnetMask)) + (randomHost & 255);
                });

                return randomIP.join('.');
            }
            addresses = addresses.concat('127.0.0.1:1234#CFnat');
            let counter = 1;
            if (hostName.includes("worker") || hostName.includes("notls")) {
                const randomPorts = httpPorts.concat('80');
                addressesnotls = addressesnotls.concat(
                    cfips.map(cidr => generateRandomIPFromCIDR(cidr) + ':' + randomPorts[Math.floor(Math.random() * randomPorts.length)] + '#CF随机节点' + String(counter++).padStart(2, '0'))
                );
            } else {
                const randomPorts = httpsPorts.concat('443');
                addresses = addresses.concat(
                    cfips.map(cidr => generateRandomIPFromCIDR(cidr) + ':' + randomPorts[Math.floor(Math.random() * randomPorts.length)] + '#CF随机节点' + String(counter++).padStart(2, '0'))
                );
            }
        }
    }

    const userAgent = UA.toLowerCase();

    let proxyhost = "";
    if (hostName.includes(".workers.dev")) {
        if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
            try {
                const response = await fetch(proxyhostsURL);

                if (!response.ok) {
                    return;
                }

                const text = await response.text();
                const lines = text.split('\n');
                const nonEmptyLines = lines.filter(line => line.trim() !== '');

                proxyhosts = proxyhosts.concat(nonEmptyLines);
            } catch (error) { }
        }
        if (proxyhosts.length != 0) proxyhost = proxyhosts[Math.floor(Math.random() * proxyhosts.length)] + "/";
    }

    if (userAgent.includes('mozilla') && !subParams.some(_searchParams => _url.searchParams.has(_searchParams))) {
        const newSocks5s = socks5s.map(socks5Address => {
            if (socks5Address.includes('@')) return socks5Address.split('@')[1];
            else if (socks5Address.includes('//')) return socks5Address.split('//')[1];
            else return socks5Address;
        });

        let socks5List = '';
        if (go2Socks5s.length > 0 && enableSocks) {
            socks5List = `${(enableHttp ? "HTTP" : "Socks5") + decodeURIComponent('%EF%BC%88%E7%99%BD%E5%90%8D%E5%8D%95%EF%BC%89%3A%20')}`;
            if (go2Socks5s.includes(atob('YWxsIGlu')) || go2Socks5s.includes(atob('Kg=='))) socks5List += `${decodeURIComponent('%E6%89%80%E6%9C%89%E6%B5%81%E9%87%8F')}<br>`;
            else socks5List += `<br>&nbsp;&nbsp;${go2Socks5s.join('<br>&nbsp;&nbsp;')}<br>`;
        }
        return `<div></div>`;
    } else {
        if (typeof fetch != 'function') {
            return 'Error: fetch is not available in this environment.';
        }

        let newAddressesapi = [];
        let newAddressescsv = [];
        let newAddressesnotlsapi = [];
        let newAddressesnotlscsv = [];

        if (hostName.includes(".workers.dev")) {
            noTLS = 'true';
            mirrorHostName = `${mirrorHostName}.workers.dev`;
            newAddressesnotlsapi = await 整理优选列表(addressesnotlsapi);
            newAddressesnotlscsv = await 整理测速结果('FALSE');
        } else if (hostName.includes(".pages.dev")) {
            mirrorHostName = `${mirrorHostName}.pages.dev`;
        } else if (hostName.includes("worker") || hostName.includes("notls") || noTLS == 'true') {
            noTLS = 'true';
            mirrorHostName = `notls${mirrorHostName}.net`;
            newAddressesnotlsapi = await 整理优选列表(addressesnotlsapi);
            newAddressesnotlscsv = await 整理测速结果('FALSE');
        } else {
            mirrorHostName = `${mirrorHostName}.xyz`
        }
        let url = `${subProtocol}://${sub}/sub?host=${mirrorHostName}&uuid=${mirrorUserID + atob('JmVkZ2V0dW5uZWw9Y2' + '1saXUmcHJveHlpcD0=') + RproxyIP}&path=${encodeURIComponent(path)}`;
        let isBase64 = true;

        if (!sub || sub == "") {
            if (hostName.includes('workers.dev')) {
                if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
                    try {
                        const response = await fetch(proxyhostsURL);
                        if (!response.ok) {
                            return;
                        }

                        const text = await response.text();
                        const lines = text.split('\n');
                        const nonEmptyLines = lines.filter(line => line.trim() !== '');

                        proxyhosts = proxyhosts.concat(nonEmptyLines);
                    } catch (error) { }
                }
                proxyhosts = [...new Set(proxyhosts)];
            }

            newAddressesapi = await 整理优选列表(addressesapi);
            newAddressescsv = await 整理测速结果('TRUE');
            url = `https://${hostName}/${mirrorUserID + _url.search}`;
            if (hostName.includes("worker") || hostName.includes("notls") || noTLS == 'true') {
                if (_url.search) url += '&notls';
                else url += '?notls';
            }
        }

        if (userAgent.includes(('CF-Workers-SUB').toLowerCase()) || _url.searchParams.has('b64') || _url.searchParams.has('base64') || userAgent.includes('subconverter')) {
            isBase64 = true;
        } else if ((userAgent.includes('clash') && !userAgent.includes('nekobox')) || (_url.searchParams.has('clash'))) {
            url = `${subProtocol}://${subConverter}/sub?target=clash&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}&fdn=false&sort=false&new_name=true`;
            isBase64 = false;
        } else if (userAgent.includes('sing-box') || userAgent.includes('singbox') || _url.searchParams.has('singbox') || _url.searchParams.has('sb')) {
            url = `${subProtocol}://${subConverter}/sub?target=singbox&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}&fdn=false&sort=false&new_name=true`;
            isBase64 = false;
        } else if (userAgent.includes('loon') || _url.searchParams.has('loon')) {
            url = `${subProtocol}://${subConverter}/sub?target=loon&url=${encodeURIComponent(url)}&insert=false&config=${encodeURIComponent(subConfig)}&emoji=${subEmoji}&list=false&tfo=false&scv=${SCV}&fdn=false&sort=false&new_name=true`;
            isBase64 = false;
        }

        try {
            let content;
            if ((!sub || sub == "") && isBase64 == true) {
                content = await 生成本地订阅(mirrorHostName, mirrorUserID, noTLS, newAddressesapi, newAddressescsv, newAddressesnotlsapi, newAddressesnotlscsv);
            } else {
                const response = await fetch(url, {
                    headers: {
                        'User-Agent': 'v2r' + 'ayN' + atob('L2VkZ2V0dW5uZWwgKGh0' + 'dHBzOi8vZ2l0aHViLmNvbS9jbWxpdS9lZGdldHVubmVsKQ==')
                    }
                });
                content = await response.text();
            }

            if (_url.pathname == `/${mirrorUserID}`) return content;

            return 恢复模糊信息(content, userID, hostName, mirrorUserID, mirrorHostName, isBase64);

        } catch (error) {
            return `Error fetching content: ${error.message}`;
        }
    }
}

async function 双重哈希(文本) {
    const 编码器 = new TextEncoder();

    const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
    const 第一次哈希数组 = Array.from(new Uint8Array(第一次哈希));
    const 第一次十六进制 = 第一次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

    const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
    const 第二次哈希数组 = Array.from(new Uint8Array(第二次哈希));
    const 第二次十六进制 = 第二次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

    return 第二次十六进制.toLowerCase();
}

async function 整理(内容) {
    var 替换后的内容 = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');

    if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
    if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);

    const 地址数组 = 替换后的内容.split(',');
    return 地址数组;
}

async function 迁移地址列表(env, txt = 'ADD.txt') {
    const 旧数据 = await env.KV.get(`/${txt}`);
    const 新数据 = await env.KV.get(txt);

    if (旧数据 && !新数据) {
        await env.KV.put(txt, 旧数据);
        await env.KV.delete(`/${txt}`);
        return true;
    }
    return false;
}

async function 整理优选列表(api) {
    if (!api || api.length === 0) return [];

    let newapi = "";


    const controller = new AbortController();

    const timeout = setTimeout(() => {
        controller.abort();
    }, 2000);

    try {
        const responses = await Promise.allSettled(api.map(apiUrl => fetch(apiUrl, {
            method: 'get',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;',
                'User-Agent': atob('Q0YtV29ya2Vycy1lZ' + 'GdldHVubmVsL2NtbGl1')
            },
            signal: controller.signal
        }).then(response => response.ok ? response.text() : Promise.reject())));

        for (const [index, response] of responses.entries()) {
            if (response.status === 'fulfilled') {
                const content = await response.value;

                const lines = content.split(/\r?\n/);
                let 节点备注 = '';
                let 测速端口 = '443';

                if (lines[0].split(',').length > 3) {
                    const idMatch = api[index].match(/id=([^&]*)/);
                    if (idMatch) 节点备注 = idMatch[1];

                    const portMatch = api[index].match(/port=([^&]*)/);
                    if (portMatch) 测速端口 = portMatch[1];

                    for (let i = 1; i < lines.length; i++) {
                        const columns = lines[i].split(',')[0];
                        if (columns) {
                            newapi += `${columns}:${测速端口}${节点备注 ? `#${节点备注}` : ''}\n`;
                            if (api[index].includes('proxyip=true')) proxyIPPool.push(`${columns}:${测速端口}`);
                        }
                    }
                } else {
                    if (api[index].includes('proxyip=true')) {
                        proxyIPPool = proxyIPPool.concat((await 整理(content)).map(item => {
                            const baseItem = item.split('#')[0] || item;
                            if (baseItem.includes(':')) {
                                const port = baseItem.split(':')[1];
                                if (!httpsPorts.includes(port)) {
                                    return baseItem;
                                }
                            } else {
                                return `${baseItem}:443`;
                            }
                            return null;
                        }).filter(Boolean));
                    }
                    newapi += content + '\n';
                }
            }
        }
    } catch (error) { } finally {
        clearTimeout(timeout);
    }
    const newAddressesapi = await 整理(newapi);
    return newAddressesapi;
}

async function 整理测速结果(tls) {
    if (!addressescsv || addressescsv.length === 0) {
        return [];
    }

    let newAddressescsv = [];

    for (const csvUrl of addressescsv) {
        try {
            const response = await fetch(csvUrl);

            if (!response.ok) {
                continue;
            }

            const text = await response.text();
            let lines;
            if (text.includes('\r\n')) {
                lines = text.split('\r\n');
            } else {
                lines = text.split('\n');
            }

            const header = lines[0].split(',');
            const tlsIndex = header.indexOf('TLS');

            const ipAddressIndex = 0;
            const portIndex = 1;
            const dataCenterIndex = tlsIndex + remarkIndex;

            if (tlsIndex === -1) {
                continue;
            }

            for (let i = 1; i < lines.length; i++) {
                const columns = lines[i].split(',');
                const speedIndex = columns.length - 1;
                if (columns[tlsIndex].toUpperCase() === tls && parseFloat(columns[speedIndex]) > DLS) {
                    const ipAddress = columns[ipAddressIndex];
                    const port = columns[portIndex];
                    const dataCenter = columns[dataCenterIndex];

                    const formattedAddress = `${ipAddress}:${port}#${dataCenter}`;
                    newAddressescsv.push(formattedAddress);
                    if (csvUrl.includes('proxyip=true') && columns[tlsIndex].toUpperCase() == 'true' && !httpsPorts.includes(port)) {
                        proxyIPPool.push(`${ipAddress}:${port}`);
                    }
                }
            }
        } catch (error) {
            continue;
        }
    }

    return newAddressescsv;
}

function 生成本地订阅(host, UUID, noTLS, newAddressesapi, newAddressescsv, newAddressesnotlsapi, newAddressesnotlscsv) {
    const regex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[.*\]):?(\d+)?#?(.*)?$/;
    addresses = addresses.concat(newAddressesapi);
    addresses = addresses.concat(newAddressescsv);
    let notlsresponseBody;
    if (noTLS == 'true') {
        addressesnotls = addressesnotls.concat(newAddressesnotlsapi);
        addressesnotls = addressesnotls.concat(newAddressesnotlscsv);
        const uniqueAddressesnotls = [...new Set(addressesnotls)];

        notlsresponseBody = uniqueAddressesnotls.map(address => {
            let port = "-1";
            let addressid = address;

            const match = addressid.match(regex);
            if (!match) {
                if (address.includes(':') && address.includes('#')) {
                    const parts = address.split(':');
                    address = parts[0];
                    const subParts = parts[1].split('#');
                    port = subParts[0];
                    addressid = subParts[1];
                } else if (address.includes(':')) {
                    const parts = address.split(':');
                    address = parts[0];
                    port = parts[1];
                } else if (address.includes('#')) {
                    const parts = address.split('#');
                    address = parts[0];
                    addressid = parts[1];
                }

                if (addressid.includes(':')) {
                    addressid = addressid.split(':')[0];
                }
            } else {
                address = match[1];
                port = match[2] || port;
                addressid = match[3] || address;
            }

            if (!isValidIPv4(address) && port == "-1") {
                for (let httpPort of httpPorts) {
                    if (address.includes(httpPort)) {
                        port = httpPort;
                        break;
                    }
                }
            }
            if (port == "-1") port = "80";

            let 模糊域名 = host;
            let 最终路径 = path;
            let 节点备注 = '';
            const 协议类型 = atob(shaFun);

            const ctx = `${协议类型}://${UUID}@${address}:${port + atob('P2VuY3J5cHRpb249bm' + '9uZSZzZWN1cml0eT0mdHlwZT13cyZob3N0PQ==') + 模糊域名}&path=${encodeURIComponent(最终路径)}#${encodeURIComponent(addressid + 节点备注)}`;

            return ctx;

        }).join('\n');

    }

    const uniqueAddresses = [...new Set(addresses)];

    const responseBody = uniqueAddresses.map(address => {
        let port = "-1";
        let addressid = address;

        const match = addressid.match(regex);
        if (!match) {
            if (address.includes(':') && address.includes('#')) {
                const parts = address.split(':');
                address = parts[0];
                const subParts = parts[1].split('#');
                port = subParts[0];
                addressid = subParts[1];
            } else if (address.includes(':')) {
                const parts = address.split(':');
                address = parts[0];
                port = parts[1];
            } else if (address.includes('#')) {
                const parts = address.split('#');
                address = parts[0];
                addressid = parts[1];
            }

            if (addressid.includes(':')) {
                addressid = addressid.split(':')[0];
            }
        } else {
            address = match[1];
            port = match[2] || port;
            addressid = match[3] || address;
        }

        if (!isValidIPv4(address) && port == "-1") {
            for (let httpsPort of httpsPorts) {
                if (address.includes(httpsPort)) {
                    port = httpsPort;
                    break;
                }
            }
        }
        if (port == "-1") port = "443";

        let 模糊域名 = host;
        let 最终路径 = path;
        let 节点备注 = '';
        const matchingProxyIP = proxyIPPool.find(proxyIP => proxyIP.includes(address));
        if (matchingProxyIP) 最终路径 = `/proxyip=${matchingProxyIP}`;
        const 协议类型 = atob(shaFun);
        const ctx = `${协议类型}://${UUID}@${address}:${port + atob('P2VuY3J5cHRpb249bm9uZSZ' + 'zZWN1cml0eT10bHMmc25pPQ==') + 模糊域名}&fp=random&type=ws&host=${模糊域名}&path=${encodeURIComponent(最终路径) + allowInsecure}&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}#${encodeURIComponent(addressid + 节点备注)}`;

        return ctx;
    }).join('\n');

    let base64Response = responseBody;
    if (noTLS == 'true') base64Response += `\n${notlsresponseBody}`;
    if (link.length > 0) base64Response += '\n' + link.join('\n');
    return btoa(base64Response);
}

function 恢复模糊信息(content, userID, hostName, mirrorUserID, mirrorHostName, isBase64) {
    if (isBase64) content = atob(content);

    content = content.replace(new RegExp(mirrorUserID, 'g'), userID)
        .replace(new RegExp(mirrorHostName, 'g'), hostName);

    if (isBase64) content = btoa(content);

    return content;
}

function isValidIPv4(address) {
    const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(address);
}