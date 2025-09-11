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
let readyHosts = [atob('c3BlZWQuY2xvd'+'WRmbGFyZS5jb20=')];
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

export default {
    async fetch(request, env, ctx) {

        const upgradeHeader = request.headers.get('Upgrade');
        const url = new URL(request.url);


        if (!upgradeHeader || upgradeHeader !== 'websocket') {

            const reqPath = url.pathname.toLowerCase();
            if (reqPath == '/') {
                if (env.URL302) return Response.redirect(env.URL302, 302);
                // else if (env.URL) return await 代理URL(env.URL, url);
                else return new Response('Hello World!');
            } else if (reqPath != '/') {
                return new Response('Hello World! Path: ' + reqPath);
            } else {
                if (env.URL302) return Response.redirect(env.URL302, 302);
                else return new Response('should not be here');
            }
        }else {
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

        pull(controller) {},

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
        transform(chunk, controller) {for (let index = 0; index < chunk.byteLength;) {
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
    })).catch((error) => {});

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
        tcpSocket.closed.catch(error => {}).finally(() => {
            safeCloseWebSocket(webSocket);
        })
        remoteSocketToWS(tcpSocket, webSocket, epResponseHeader, null);
    }

    async function retry() {
        if (enableSocks) {
            tcpSocket = await connectAndWrite(addressRemote, portRemote, true, enableHttp);
        } else {
            if (!proxyIP || proxyIP == '') {
                proxyIP = atob('UFJPWFlJUC50c'+'DEuMDkwMjI3Lnh5eg==');
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
    } catch (error) {}
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
                        dataStream.pipeTo(writable).catch(err => {});

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
    const defaultAddress = atob('cHJveHlpcC5jb'+'WxpdXNzc3MubmV0');
    if (!DNS64Server) {
        try {
            const response = await fetch(atob('aHR0cHM6Ly8xLjE'+'uMS4xL2Rucy1xdWVyeT9uYW1lPW5hdDY0Lm'+'NtbGl1c3Nzcy5uZXQmdHlwZT1UWFQ='), {
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
        const nat64 = DNS64Server.endsWith('/96') ? convertToNAT64IPv6(ipv4) : await queryNAT64(ipv4 + atob('LmlwLjA5MDIyNy54eXo='));
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