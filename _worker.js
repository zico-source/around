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

let userID = 'ziccolon';
let proxyIP = '';
let DNS64Server = '';
//let sub = '';
let subConverter = atob('U1VCQVBJLkNNTGl1c3Nzcy5uZXQ=');
let subConfig = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0FDTDRTU1IvQUNMNFNTUi9tYXN0ZXIvQ2xhc2gvY29uZmlnL0FDTDRTU1JfT25saW5lX01pbmlfTXVsdGlNb2RlLmluaQ==');
let subProtocol = 'https';
let subEmoji = 'true';
let socks5Address = '';
let parsedSocks5Address = {};
let enableSocks = false;
let enableHttp = false;
let noTLS = 'false';
const expire = 4102329600;//2099-12-31
let proxyIPs;
let socks5s;
let go2Socks5s = [
    '*ttvnw.net',
    '*tapecontent.net',
    '*cloudatacdn.com',
    '*.loadshare.org',
];
let addresses = [];
let addressesapi = [];
let addressesnotls = [];
let addressesnotlsapi = [];
let addressescsv = [];
let DLS = 8;
let remarkIndex = 1;//CSV备注所在列偏移量
let FileName = atob('ZWRnZXR1bm5lbA==');
let BotToken;
let ChatID;
let proxyhosts = [];
let proxyhostsURL = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2NtbGl1L2NtbGl1L21haW4vUHJveHlIT1NU');
let RproxyIP = 'false';
const httpPorts = ["8080", "8880", "2052", "2082", "2086", "2095"];
let httpsPorts = ["2053", "2083", "2087", "2096", "8443"];
let 有效时间 = 7;
let 更新时间 = 3;
let userIDLow;
let userIDTime = "";
let proxyIPPool = [];
let path = '/?ed=2560';
let 动态UUID = userID;
let link = [];
let banHosts = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
let SCV = 'true';
let allowInsecure = '&allowInsecure=1';
export default {
    async fetch(request, env, ctx) {
        try {
            const UA = request.headers.get('User-Agent') || 'null';
            const userAgent = UA.toLowerCase();
            userID = 'subInfo';
            if (env.KEY || env.TOKEN || (userID && !isValidUUID(userID))) {
                动态UUID = env.KEY || env.TOKEN || userID;
                有效时间 = Number(env.TIME) || 有效时间;
                更新时间 = Number(env.UPTIME) || 更新时间;
                const userIDs = await 生成动态UUID(动态UUID);
                userID = userIDs[0];
                userIDLow = userIDs[1];
            } else 动态UUID = userID;

            if (!userID) {
                return new Response('', {
                    status: 202,
                    headers: {
                        "Content-Type": "text/plain;charset=UTF-8",
                    }
                });
            }
            const currentDate = new Date();
            currentDate.setHours(0, 0, 0, 0);
            const timestamp = Math.ceil(currentDate.getTime() / 1000);
            const mirrorUserIDMD5 = await 双重哈希(`${userID}${timestamp}`);
            const mirrorUserID = [
                mirrorUserIDMD5.slice(0, 8),
                mirrorUserIDMD5.slice(8, 12),
                mirrorUserIDMD5.slice(12, 16),
                mirrorUserIDMD5.slice(16, 20),
                mirrorUserIDMD5.slice(20)
            ].join('-');

            const mirrorHostName = `${mirrorUserIDMD5.slice(6, 9)}.${mirrorUserIDMD5.slice(13, 19)}`;

            proxyIP = env.PROXYIP || env.proxyip || proxyIP;
            proxyIPs = await 整理(proxyIP);
            proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
            DNS64Server = env.DNS64 || env.NAT64 || DNS64Server;
            socks5Address = env.HTTP || env.SOCKS5 || socks5Address;
            socks5s = await 整理(socks5Address);
            socks5Address = socks5s[Math.floor(Math.random() * socks5s.length)];
            enableHttp = env.HTTP ? true : socks5Address.toLowerCase().includes('http://');
            socks5Address = socks5Address.split('//')[1] || socks5Address;
            if (env.GO2SOCKS5) go2Socks5s = await 整理(env.GO2SOCKS5);
            if (env.CFPORTS) httpsPorts = await 整理(env.CFPORTS);
            if (env.BAN) banHosts = await 整理(env.BAN);
            if (socks5Address) {
                try {
                    parsedSocks5Address = socks5AddressParser(socks5Address);
                    RproxyIP = env.RPROXYIP || 'false';
                    enableSocks = true;
                } catch (err) {
                    let e = err;
                    console.log(e.toString());
                    RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
                    enableSocks = false;
                }
            } else {
                RproxyIP = env.RPROXYIP || !proxyIP ? 'true' : 'false';
            }

            const upgradeHeader = request.headers.get('Upgrade');
            const url = new URL(request.url);
            if (!upgradeHeader || upgradeHeader !== 'websocket') {
                if (env.ADD) addresses = await 整理(env.ADD);
                if (env.ADDAPI) addressesapi = await 整理(env.ADDAPI);
                if (env.ADDNOTLS) addressesnotls = await 整理(env.ADDNOTLS);
                if (env.ADDNOTLSAPI) addressesnotlsapi = await 整理(env.ADDNOTLSAPI);
                if (env.ADDCSV) addressescsv = await 整理(env.ADDCSV);
                DLS = Number(env.DLS) || DLS;
                remarkIndex = Number(env.CSVREMARK) || remarkIndex;
                BotToken = env.TGTOKEN || BotToken;
                ChatID = env.TGID || ChatID;
                FileName = env.SUBNAME || FileName;
                subEmoji = env.SUBEMOJI || env.EMOJI || subEmoji;
                if (subEmoji == '0') subEmoji = 'false';
                if (env.LINK) link = await 整理(env.LINK);
                let sub = env.SUB || '';
                subConverter = env.SUBAPI || subConverter;
                if (subConverter.includes("http://")) {
                    subConverter = subConverter.split("//")[1];
                    subProtocol = 'http';
                } else {
                    subConverter = subConverter.split("//")[1] || subConverter;
                }
                subConfig = env.SUBCONFIG || subConfig;
                if (url.searchParams.has('sub') && url.searchParams.get('sub') !== '') sub = url.searchParams.get('sub').toLowerCase();
                if (url.searchParams.has('notls')) noTLS = 'true';

                if (url.searchParams.has('proxyip')) {
                    path = `/proxyip=${url.searchParams.get('proxyip')}`;
                    RproxyIP = 'false';
                } else if (url.searchParams.has('socks5')) {
                    path = `/?socks5=${url.searchParams.get('socks5')}`;
                    RproxyIP = 'false';
                } else if (url.searchParams.has('socks')) {
                    path = `/?socks5=${url.searchParams.get('socks')}`;
                    RproxyIP = 'false';
                }

                SCV = env.SCV || SCV;
                if (!SCV || SCV == '0' || SCV == 'false') allowInsecure = '';
                else SCV = 'true';
                const 路径 = url.pathname.toLowerCase();
                if (路径 == '/') {
                    if (env.URL302) return Response.redirect(env.URL302, 302);
                    else if (env.URL) return await 代理URL(env.URL, url);
                    else return new Response('Hello World!', {
                        status: 200,
                        headers: {
                            'Content-Type': 'text/html; charset=UTF-8',
                        },
                    });
                } else if (路径 == `/${mirrorUserID}`) {
                    const mirrorConfig = await 生成配置信息(userID, request.headers.get('Host'), sub, 'CF-Workers-SUB', RproxyIP, url, mirrorUserID, mirrorHostName, env);
                    return new Response(`${mirrorConfig}`, { status: 200 });
                } else if (url.pathname == `/${动态UUID}` || 路径 == `/${userID}`) {
                    await sendMessage(`#获取订阅 ${FileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${UA}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);
                    const 维列斯Config = await 生成配置信息(userID, request.headers.get('Host'), sub, UA, RproxyIP, url, mirrorUserID, mirrorHostName, env);
                    const now = Date.now();
                    //const timestamp = Math.floor(now / 1000);
                    const today = new Date(now);
                    today.setHours(0, 0, 0, 0);
                    const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
                    let pagesSum = UD;
                    let workersSum = UD;
                    let total = 24 * 1099511627776;
                    if (userAgent && userAgent.includes('mozilla')) {
                        return new Response(维列斯Config, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/html;charset=utf-8",
                                "Profile-Update-Interval": "6",
                                "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                                "Cache-Control": "no-store",
                            }
                        });
                    } else {
                        return new Response(维列斯Config, {
                            status: 200,
                            headers: {
                                "Content-Disposition": `attachment; filename=${FileName}; filename*=utf-8''${encodeURIComponent(FileName)}`,
                                //"Content-Type": "text/plain;charset=utf-8",
                                "Profile-Update-Interval": "6",
                                "Profile-web-page-url": request.url.includes('?') ? request.url.split('?')[0] : request.url,
                                "Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
                            }
                        });
                    }
                } else {
                    if (env.URL302) return Response.redirect(env.URL302, 302);
                    else if (env.URL) return await 代理URL(env.URL, url);
                    else return new Response('', {
                    status: 202,
                    headers: {
                        "Content-Type": "text/plain;charset=UTF-8",
                    }
                });
                }
            } else {
                socks5Address = url.searchParams.get('socks5') || socks5Address;
                if (new RegExp('/socks5=', 'i').test(url.pathname)) socks5Address = url.pathname.split('5=')[1];
                else if (new RegExp('/socks://', 'i').test(url.pathname) || new RegExp('/socks5://', 'i').test(url.pathname) || new RegExp('/http://', 'i').test(url.pathname)) {
                    enableHttp = url.pathname.includes('http://');
                    socks5Address = url.pathname.split('://')[1].split('#')[0];
                    if (socks5Address.includes('@')) {
                        const lastAtIndex = socks5Address.lastIndexOf('@');
                        let userPassword = socks5Address.substring(0, lastAtIndex).replaceAll('%3D', '=');
                        const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
                        if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
                        socks5Address = `${userPassword}@${socks5Address.substring(lastAtIndex + 1)}`;
                    }
                    go2Socks5s = ['all in'];//开启全局SOCKS5
                }

                if (socks5Address) {
                    try {
                        parsedSocks5Address = socks5AddressParser(socks5Address);
                        enableSocks = true;
                    } catch (err) {
                        let e = err;
                        console.log(e.toString());
                        enableSocks = false;
                    }
                } else {
                    enableSocks = false;
                }

                if (url.searchParams.has('proxyip')) {
                    proxyIP = url.searchParams.get('proxyip');
                    enableSocks = false;
                } else if (new RegExp('/proxyip=', 'i').test(url.pathname)) {
                    proxyIP = url.pathname.toLowerCase().split('/proxyip=')[1];
                    enableSocks = false;
                } else if (new RegExp('/proxyip.', 'i').test(url.pathname)) {
                    proxyIP = `proxyip.${url.pathname.toLowerCase().split("/proxyip.")[1]}`;
                    enableSocks = false;
                } else if (new RegExp('/pyip=', 'i').test(url.pathname)) {
                    proxyIP = url.pathname.toLowerCase().split('/pyip=')[1];
                    enableSocks = false;
                }

                return await 维列斯OverWSHandler(request);
            }
        } catch (err) {
            let e = err;
            return new Response(e.toString());
        }
    },
};

async function 维列斯OverWSHandler(request) {

    // @ts-ignore
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);

    // 接受 WebSocket 连接
    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    // 日志函数，用于记录连接信息
    const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
    };
    // 获取早期数据头部，可能包含了一些初始化数据
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

    // 创建一个可读的 WebSocket 流，用于接收客户端数据
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    // 用于存储远程 Socket 的包装器
    let remoteSocketWapper = {
        value: null,
    };
    // 标记是否为 DNS 查询
    let udpStreamWrite = null;
    let isDns = false;

    // WebSocket 数据流向远程服务器的管道
    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (isDns && udpStreamWrite) {
                // 如果是 DNS 查询，调用 DNS 处理函数
                //return await handleDNSQuery(chunk, webSocket, null, log);
                return udpStreamWrite(chunk);
            }
            if (remoteSocketWapper.value) {
                // 如果已有远程 Socket，直接写入数据
                const writer = remoteSocketWapper.value.writable.getWriter()
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            // 处理 维列斯 协议头部
            const {
                hasError,
                message,
                addressType,
                portRemote = 443,
                addressRemote = '',
                rawDataIndex,
                维列斯Version = new Uint8Array([0, 0]),
                isUDP,
            } = process维列斯Header(chunk, userID);
            // 设置地址和端口信息，用于日志
            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp ' : 'tcp '} `;
            if (hasError) {
                // 如果有错误，抛出异常
                throw new Error(message);
                return;
            }
            // 如果是 UDP 且端口不是 DNS 端口（53），则关闭连接
            if (isUDP) {
                if (portRemote === 53) {
                    isDns = true;
                } else {
                    throw new Error('UDP 代理仅对 DNS（53 端口）启用');
                    return;
                }
            }
            // 构建 维列斯 响应头部
            const 维列斯ResponseHeader = new Uint8Array([维列斯Version[0], 0]);
            // 获取实际的客户端数据
            const rawClientData = chunk.slice(rawDataIndex);

            if (isDns) {
                // 如果是 DNS 查询，调用 DNS 处理函数
                //return handleDNSQuery(rawClientData, webSocket, 维列斯ResponseHeader, log);
                const { write } = await handleUDPOutBound(webSocket, 维列斯ResponseHeader, log);
                udpStreamWrite = write;
                udpStreamWrite(rawClientData);
                return;
            }
            // 处理 TCP 出站连接
            if (!banHosts.includes(addressRemote)) {
                log(`处理 TCP 出站连接 ${addressRemote}:${portRemote}`);
                handleTCPOutBound(remoteSocketWapper, addressType, addressRemote, portRemote, rawClientData, webSocket, 维列斯ResponseHeader, log);
            } else {
                throw new Error(`黑名单关闭 TCP 出站连接 ${addressRemote}:${portRemote}`);
            }
        },
        close() {
            log(`readableWebSocketStream 已关闭`);
        },
        abort(reason) {
            log(`readableWebSocketStream 已中止`, JSON.stringify(reason));
        },
    })).catch((err) => {
        log('readableWebSocketStream 管道错误', err);
    });

    // 返回一个 WebSocket 升级的响应
    return new Response(null, {
        status: 101,
        // @ts-ignore
        webSocket: client,
    });
}

async function handleTCPOutBound(remoteSocket, addressType, addressRemote, portRemote, rawClientData, webSocket, 维列斯ResponseHeader, log,) {
    async function useSocks5Pattern(address) {
        if (go2Socks5s.includes(atob('YWxsIGlu')) || go2Socks5s.includes(atob('Kg=='))) return true;
        return go2Socks5s.some(pattern => {
            let regexPattern = pattern.replace(/\*/g, '.*');
            let regex = new RegExp(`^${regexPattern}$`, 'i');
            return regex.test(address);
        });
    }

    async function connectAndWrite(address, port, socks = false, http = false) {
        log(`connected to ${address}:${port}`);
        //if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LmlwLjA5MDIyNy54eXo=')}`;
        // 先确定连接方式，再创建连接
        const tcpSocket = socks
            ? (http ? await httpConnect(address, port, log) : await socks5Connect(addressType, address, port, log))
            : connect({ hostname: address, port: port });

        remoteSocket.value = tcpSocket;
        //log(`connected to ${address}:${port}`);
        const writer = tcpSocket.writable.getWriter();
        // 首次写入，通常是 TLS 客户端 Hello 消息
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    async function nat64() {
        if (!useSocks) {
            const nat64Proxyip = `[${await resolveToIPv6(addressRemote)}]`;
            log(`NAT64 代理连接到 ${nat64Proxyip}:443`);
            tcpSocket = await connectAndWrite(nat64Proxyip, 443);
        }
        tcpSocket.closed.catch(error => {
            console.log('retry tcpSocket closed error', error);
        }).finally(() => {
            safeCloseWebSocket(webSocket);
        })
        remoteSocketToWS(tcpSocket, webSocket, 维列斯ResponseHeader, null, log);
    }

    /**
     * 重试函数：当 Cloudflare 的 TCP Socket 没有传入数据时，我们尝试重定向 IP
     * 这可能是因为某些网络问题导致的连接失败
     */
    async function retry() {
        if (enableSocks) {
            // 如果启用了 SOCKS5，通过 SOCKS5 代理重试连接
            tcpSocket = await connectAndWrite(addressRemote, portRemote, true, enableHttp);
        } else {
            // 否则，尝试使用预设的代理 IP（如果有）或原始地址重试连接
            if (!proxyIP || proxyIP == '') {
                proxyIP = atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg==');
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
        /* 无论重试是否成功，都要关闭 WebSocket（可能是为了重新建立连接）
        tcpSocket.closed.catch(error => {
            console.log('retry tcpSocket closed error', error);
        }).finally(() => {
            safeCloseWebSocket(webSocket);
        })
        */
        // 建立从远程 Socket 到 WebSocket 的数据流
        remoteSocketToWS(tcpSocket, webSocket, 维列斯ResponseHeader, nat64, log);
    }

    let useSocks = false;
    if (go2Socks5s.length > 0 && enableSocks) useSocks = await useSocks5Pattern(addressRemote);
    // 首次尝试连接远程服务器
    let tcpSocket = await connectAndWrite(addressRemote, portRemote, useSocks, enableHttp);

    // 当远程 Socket 就绪时，将其传递给 WebSocket
    // 建立从远程服务器到 WebSocket 的数据流，用于将远程服务器的响应发送回客户端
    // 如果连接失败或无数据，retry 函数将被调用进行重试
    remoteSocketToWS(tcpSocket, webSocket, 维列斯ResponseHeader, retry, log);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    // 标记可读流是否已被取消
    let readableStreamCancel = false;

    // 创建一个新的可读流
    const stream = new ReadableStream({
        // 当流开始时的初始化函数
        start(controller) {
            // 监听 WebSocket 的消息事件
            webSocketServer.addEventListener('message', (event) => {
                // 如果流已被取消，不再处理新消息
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                // 将消息加入流的队列中
                controller.enqueue(message);
            });

            // 监听 WebSocket 的关闭事件
            // 注意：这个事件意味着客户端关闭了客户端 -> 服务器的流
            // 但是，服务器 -> 客户端的流仍然打开，直到在服务器端调用 close()
            // WebSocket 协议要求在每个方向上都要发送单独的关闭消息，以完全关闭 Socket
            webSocketServer.addEventListener('close', () => {
                // 客户端发送了关闭信号，需要关闭服务器端
                safeCloseWebSocket(webSocketServer);
                // 如果流未被取消，则关闭控制器
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            });

            // 监听 WebSocket 的错误事件
            webSocketServer.addEventListener('error', (err) => {
                log('WebSocket 服务器发生错误');
                // 将错误传递给控制器
                controller.error(err);
            });

            // 处理 WebSocket 0-RTT（零往返时间）的早期数据
            // 0-RTT 允许在完全建立连接之前发送数据，提高了效率
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                // 如果解码早期数据时出错，将错误传递给控制器
                controller.error(error);
            } else if (earlyData) {
                // 如果有早期数据，将其加入流的队列中
                controller.enqueue(earlyData);
            }
        },

        // 当使用者从流中拉取数据时调用
        pull(controller) {
            // 这里可以实现反压机制
            // 如果 WebSocket 可以在流满时停止读取，我们就可以实现反压
            // 参考：https://streams.spec.whatwg.org/#example-rs-push-backpressure
        },

        // 当流被取消时调用
        cancel(reason) {
            // 流被取消的几种情况：
            // 1. 当管道的 WritableStream 有错误时，这个取消函数会被调用，所以在这里处理 WebSocket 服务器的关闭
            // 2. 如果 ReadableStream 被取消，所有 controller.close/enqueue 都需要跳过
            // 3. 但是经过测试，即使 ReadableStream 被取消，controller.error 仍然有效
            if (readableStreamCancel) {
                return;
            }
            log(`可读流被取消，原因是 ${reason}`);
            readableStreamCancel = true;
            // 安全地关闭 WebSocket
            safeCloseWebSocket(webSocketServer);
        }
    });

    return stream;
}

// https://xtls.github.io/development/protocols/维列斯.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 * 解析 维列斯 协议的头部数据
 * @param { ArrayBuffer} 维列斯Buffer 维列斯 协议的原始头部数据
 * @param {string} userID 用于验证的用户 ID
 * @returns {Object} 解析结果，包括是否有错误、错误信息、远程地址信息等
 */
function process维列斯Header(维列斯Buffer, userID) {
    // 检查数据长度是否足够（至少需要 24 字节）
    if (维列斯Buffer.byteLength < 24) {
        return {
            hasError: true,
            message: 'invalid data',
        };
    }

    // 解析 维列斯 协议版本（第一个字节）
    const version = new Uint8Array(维列斯Buffer.slice(0, 1));

    let isValidUser = false;
    let isUDP = false;

    // 验证用户 ID（接下来的 16 个字节）
    function isUserIDValid(userID, userIDLow, buffer) {
        const userIDArray = new Uint8Array(buffer.slice(1, 17));
        const userIDString = stringify(userIDArray);
        return userIDString === userID || userIDString === userIDLow;
    }

    // 使用函数验证
    isValidUser = isUserIDValid(userID, userIDLow, 维列斯Buffer);

    // 如果用户 ID 无效，返回错误
    if (!isValidUser) {
        return {
            hasError: true,
            message: `invalid user ${(new Uint8Array(维列斯Buffer.slice(1, 17)))}`,
        };
    }

    // 获取附加选项的长度（第 17 个字节）
    const optLength = new Uint8Array(维列斯Buffer.slice(17, 18))[0];
    // 暂时跳过附加选项

    // 解析命令（紧跟在选项之后的 1 个字节）
    // 0x01: TCP, 0x02: UDP, 0x03: MUX（多路复用）
    const command = new Uint8Array(
        维列斯Buffer.slice(18 + optLength, 18 + optLength + 1)
    )[0];

    // 0x01 TCP
    // 0x02 UDP
    // 0x03 MUX
    if (command === 1) {
        // TCP 命令，不需特殊处理
    } else if (command === 2) {
        // UDP 命令
        isUDP = true;
    } else {
        // 不支持的命令
        return {
            hasError: true,
            message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
        };
    }

    // 解析远程端口（大端序，2 字节）
    const portIndex = 18 + optLength + 1;
    const portBuffer = 维列斯Buffer.slice(portIndex, portIndex + 2);
    // port is big-Endian in raw data etc 80 == 0x005d
    const portRemote = new DataView(portBuffer).getUint16(0);

    // 解析地址类型和地址
    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(
        维列斯Buffer.slice(addressIndex, addressIndex + 1)
    );

    // 地址类型：1-IPv4(4字节), 2-域名(可变长), 3-IPv6(16字节)
    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = '';

    switch (addressType) {
        case 1:
            // IPv4 地址
            addressLength = 4;
            // 将 4 个字节转为点分十进制格式
            addressValue = new Uint8Array(
                维列斯Buffer.slice(addressValueIndex, addressValueIndex + addressLength)
            ).join('.');
            break;
        case 2:
            // 域名
            // 第一个字节是域名长度
            addressLength = new Uint8Array(
                维列斯Buffer.slice(addressValueIndex, addressValueIndex + 1)
            )[0];
            addressValueIndex += 1;
            // 解码域名
            addressValue = new TextDecoder().decode(
                维列斯Buffer.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            break;
        case 3:
            // IPv6 地址
            addressLength = 16;
            const dataView = new DataView(
                维列斯Buffer.slice(addressValueIndex, addressValueIndex + addressLength)
            );
            // 每 2 字节构成 IPv6 地址的一部分
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(':');
            // seems no need add [] for ipv6
            break;
        default:
            // 无效的地址类型
            return {
                hasError: true,
                message: `invild addressType is ${addressType}`,
            };
    }

    // 确保地址不为空
    if (!addressValue) {
        return {
            hasError: true,
            message: `addressValue is empty, addressType is ${addressType}`,
        };
    }

    // 返回解析结果
    return {
        hasError: false,
        addressRemote: addressValue,  // 解析后的远程地址
        addressType,				 // 地址类型
        portRemote,				 // 远程端口
        rawDataIndex: addressValueIndex + addressLength,  // 原始数据的实际起始位置
        维列斯Version: version,	  // 维列斯 协议版本
        isUDP,					 // 是否是 UDP 请求
    };
}

async function remoteSocketToWS(remoteSocket, webSocket, 维列斯ResponseHeader, retry, log) {
    // 将数据从远程服务器转发到 WebSocket
    let remoteChunkCount = 0;
    let chunks = [];
    /** @type {ArrayBuffer | null} */
    let 维列斯Header = 维列斯ResponseHeader;
    let hasIncomingData = false; // 检查远程 Socket 是否有传入数据

    // 使用管道将远程 Socket 的可读流连接到一个可写流
    await remoteSocket.readable
        .pipeTo(
            new WritableStream({
                start() {
                    // 初始化时不需要任何操作
                },
                /**
                 * 处理每个数据块
                 * @param {Uint8Array} chunk 数据块
                 * @param {*} controller 控制器
                 */
                async write(chunk, controller) {
                    hasIncomingData = true; // 标记已收到数据
                    // remoteChunkCount++; // 用于流量控制，现在似乎不需要了

                    // 检查 WebSocket 是否处于开放状态
                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        controller.error(
                            'webSocket.readyState is not open, maybe close'
                        );
                    }

                    if (维列斯Header) {
                        // 如果有 维列斯 响应头部，将其与第一个数据块一起发送
                        webSocket.send(await new Blob([维列斯Header, chunk]).arrayBuffer());
                        维列斯Header = null; // 清空头部，之后不再发送
                    } else {
                        // 直接发送数据块
                        // 以前这里有流量控制代码，限制大量数据的发送速率
                        // 但现在 Cloudflare 似乎已经修复了这个问题
                        // if (remoteChunkCount > 20000) {
                        // 	// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M
                        // 	await delay(1);
                        // }
                        webSocket.send(chunk);
                    }
                },
                close() {
                    // 当远程连接的可读流关闭时
                    log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
                    // 不需要主动关闭 WebSocket，因为这可能导致 HTTP ERR_CONTENT_LENGTH_MISMATCH 问题
                    // 客户端无论如何都会发送关闭事件
                    // safeCloseWebSocket(webSocket);
                },
                abort(reason) {
                    // 当远程连接的可读流中断时
                    console.error(`remoteConnection!.readable abort`, reason);
                },
            })
        )
        .catch((error) => {
            // 捕获并记录任何异常
            console.error(
                `remoteSocketToWS has exception `,
                error.stack || error
            );
            // 发生错误时安全地关闭 WebSocket
            safeCloseWebSocket(webSocket);
        });

    // 处理 Cloudflare 连接 Socket 的特殊错误情况
    // 1. Socket.closed 将有错误
    // 2. Socket.readable 将关闭，但没有任何数据
    if (hasIncomingData === false && retry) {
        log(`retry`);
        retry(); // 调用重试函数，尝试重新建立连接
    }
}

/**
 * 将 Base64 编码的字符串转换为 ArrayBuffer
 * 
 * @param {string} base64Str Base64 编码的输入字符串
 * @returns {{ earlyData: ArrayBuffer | undefined, error: Error | null }} 返回解码后的 ArrayBuffer 或错误
 */
function base64ToArrayBuffer(base64Str) {
    // 如果输入为空，直接返回空结果
    if (!base64Str) {
        return { earlyData: undefined, error: null };
    }
    try {
        // Go 语言使用了 URL 安全的 Base64 变体（RFC 4648）
        // 这种变体使用 '-' 和 '_' 来代替标准 Base64 中的 '+' 和 '/'
        // JavaScript 的 atob 函数不直接支持这种变体，所以我们需要先转换
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');

        // 使用 atob 函数解码 Base64 字符串
        // atob 将 Base64 编码的 ASCII 字符串转换为原始的二进制字符串
        const decode = atob(base64Str);

        // 将二进制字符串转换为 Uint8Array
        // 这是通过遍历字符串中的每个字符并获取其 Unicode 编码值（0-255）来完成的
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));

        // 返回 Uint8Array 的底层 ArrayBuffer
        // 这是实际的二进制数据，可以用于网络传输或其他二进制操作
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        // 如果在任何步骤中出现错误（如非法 Base64 字符），则返回错误
        return { earlyData: undefined, error };
    }
}

/**
 * 这不是真正的 UUID 验证，而是一个简化的版本
 * @param {string} uuid 要验证的 UUID 字符串
 * @returns {boolean} 如果字符串匹配 UUID 格式则返回 true，否则返回 false
 */
function isValidUUID(uuid) {
    // 定义一个正则表达式来匹配 UUID 格式
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

    // 使用正则表达式测试 UUID 字符串
    return uuidRegex.test(uuid);
}

// WebSocket 的两个重要状态常量
const WS_READY_STATE_OPEN = 1;	 // WebSocket 处于开放状态，可以发送和接收消息
const WS_READY_STATE_CLOSING = 2;  // WebSocket 正在关闭过程中

function safeCloseWebSocket(socket) {
    try {
        // 只有在 WebSocket 处于开放或正在关闭状态时才调用 close()
        // 这避免了在已关闭或连接中的 WebSocket 上调用 close()
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        // 记录任何可能发生的错误，虽然按照规范不应该有错误
        console.error('safeCloseWebSocket error', error);
    }
}

// 预计算 0-255 每个字节的十六进制表示
const byteToHex = [];
for (let i = 0; i < 256; ++i) {
    // (i + 256).toString(16) 确保总是得到两位数的十六进制
    // .slice(1) 删除前导的 "1"，只保留两位十六进制数
    byteToHex.push((i + 256).toString(16).slice(1));
}

/**
 * 快速地将字节数组转换为 UUID 字符串，不进行有效性检查
 * 这是一个底层函数，直接操作字节，不做任何验证
 * @param {Uint8Array} arr 包含 UUID 字节的数组
 * @param {number} offset 数组中 UUID 开始的位置，默认为 0
 * @returns {string} UUID 字符串
 */
function unsafeStringify(arr, offset = 0) {
    // 直接从查找表中获取每个字节的十六进制表示，并拼接成 UUID 格式
    // 8-4-4-4-12 的分组是通过精心放置的连字符 "-" 实现的
    // toLowerCase() 确保整个 UUID 是小写的
    return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" +
        byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" +
        byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" +
        byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" +
        byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] +
        byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

/**
 * 将字节数组转换为 UUID 字符串，并验证其有效性
 * 这是一个安全的函数，它确保返回的 UUID 格式正确
 * @param {Uint8Array} arr 包含 UUID 字节的数组
 * @param {number} offset 数组中 UUID 开始的位置，默认为 0
 * @returns {string} 有效的 UUID 字符串
 * @throws {TypeError} 如果生成的 UUID 字符串无效
 */
function stringify(arr, offset = 0) {
    // 使用不安全的函数快速生成 UUID 字符串
    const uuid = unsafeStringify(arr, offset);
    // 验证生成的 UUID 是否有效
    if (!isValidUUID(uuid)) {
        // 原：throw TypeError("Stringified UUID is invalid");
        throw TypeError(`生成的 UUID 不符合规范 ${uuid}`);
        //uuid = userID;
    }
    return uuid;
}

async function handleUDPOutBound(webSocket, 维列斯ResponseHeader, log) {

    let is维列斯HeaderSent = false;
    const transformStream = new TransformStream({
        start(controller) {

        },
        transform(chunk, controller) {
            // udp message 2 byte is the the length of udp data
            // TODO: this should have bug, beacsue maybe udp chunk can be in two websocket message
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

    // only handle dns udp for now
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
            // console.log([...new Uint8Array(dnsQueryResult)].map((x) => x.toString(16)));
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
            if (webSocket.readyState === WS_READY_STATE_OPEN) {
                log(`doh success and dns message length is ${udpSize}`);
                if (is维列斯HeaderSent) {
                    webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                } else {
                    webSocket.send(await new Blob([维列斯ResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                    is维列斯HeaderSent = true;
                }
            }
        }
    })).catch((error) => {
        log('dns udp has error' + error)
    });

    const writer = transformStream.writable.getWriter();

    return {
        /**
         * 
         * @param {Uint8Array} chunk 
         */
        write(chunk) {
            writer.write(chunk);
        }
    };
}

/**
 * 处理 DNS 查询的函数
 * @param {ArrayBuffer} udpChunk - 客户端发送的 DNS 查询数据
 * @param {ArrayBuffer} 维列斯ResponseHeader - 维列斯 协议的响应头部数据
 * @param {(string)=> void} log - 日志记录函数
 */
async function handleDNSQuery(udpChunk, webSocket, 维列斯ResponseHeader, log) {
    // 无论客户端发送到哪个 DNS 服务器，我们总是使用硬编码的服务器
    // 因为有些 DNS 服务器不支持 DNS over TCP
    try {
        // 选用 Google 的 DNS 服务器（注：后续可能会改为 Cloudflare 的 1.1.1.1）
        const dnsServer = '8.8.4.4'; // 在 Cloudflare 修复连接自身 IP 的 bug 后，将改为 1.1.1.1
        const dnsPort = 53; // DNS 服务的标准端口

        let 维列斯Header = 维列斯ResponseHeader; // 保存 维列斯 响应头部，用于后续发送

        // 与指定的 DNS 服务器建立 TCP 连接
        const tcpSocket = connect({
            hostname: dnsServer,
            port: dnsPort,
        });

        log(`连接到 ${dnsServer}:${dnsPort}`); // 记录连接信息
        const writer = tcpSocket.writable.getWriter();
        await writer.write(udpChunk); // 将客户端的 DNS 查询数据发送给 DNS 服务器
        writer.releaseLock(); // 释放写入器，允许其他部分使用

        // 将从 DNS 服务器接收到的响应数据通过 WebSocket 发送回客户端
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                if (webSocket.readyState === WS_READY_STATE_OPEN) {
                    if (维列斯Header) {
                        // 如果有 维列斯 头部，则将其与 DNS 响应数据合并后发送
                        webSocket.send(await new Blob([维列斯Header, chunk]).arrayBuffer());
                        维列斯Header = null; // 头部只发送一次，之后置为 null
                    } else {
                        // 否则直接发送 DNS 响应数据
                        webSocket.send(chunk);
                    }
                }
            },
            close() {
                log(`DNS 服务器(${dnsServer}) TCP 连接已关闭`); // 记录连接关闭信息
            },
            abort(reason) {
                console.error(`DNS 服务器(${dnsServer}) TCP 连接异常中断`, reason); // 记录异常中断原因
            },
        }));
    } catch (error) {
        // 捕获并记录任何可能发生的错误
        console.error(
            `handleDNSQuery 函数发生异常，错误信息: ${error.message}`
        );
    }
}

async function socks5Connect(addressType, addressRemote, portRemote, log) {
    const { username, password, hostname, port } = parsedSocks5Address;
    // 连接到 SOCKS5 代理服务器
    const socket = connect({
        hostname, // SOCKS5 服务器的主机名
        port,	// SOCKS5 服务器的端口
    });

    const socksGreeting = new Uint8Array([5, 2, 0, 2]);
    // 5: SOCKS5 版本号, 2: 支持的认证方法数, 0和2: 两种认证方法（无认证和用户名/密码）

    const writer = socket.writable.getWriter();

    await writer.write(socksGreeting);
    log('已发送 SOCKS5 问候消息');

    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();
    let res = (await reader.read()).value;

    if (res[0] !== 0x05) {
        log(`SOCKS5 服务器版本错误: 收到 ${res[0]}，期望是 5`);
        return;
    }
    if (res[1] === 0xff) {
        log("服务器不接受任何认证方法");
        return;
    }

    // 如果返回 0x0502，表示需要用户名/密码认证
    if (res[1] === 0x02) {
        log("SOCKS5 服务器需要认证");
        if (!username || !password) {
            log("请提供用户名和密码");
            return;
        }
    
        const authRequest = new Uint8Array([
            1,				   // 认证子协议版本
            username.length,	// 用户名长度
            ...encoder.encode(username), // 用户名
            password.length,	// 密码长度
            ...encoder.encode(password)  // 密码
        ]);
        await writer.write(authRequest);
        res = (await reader.read()).value;
        // 期望返回 0x0100 表示认证成功
        if (res[0] !== 0x01 || res[1] !== 0x00) {
            log("SOCKS5 服务器认证失败");
            return;
        }
    }

    let DSTADDR;	// DSTADDR = ATYP + DST.ADDR
    switch (addressType) {
        case 1: // IPv4
            DSTADDR = new Uint8Array(
                [1, ...addressRemote.split('.').map(Number)]
            );
            break;
        case 2: // 域名
            DSTADDR = new Uint8Array(
                [3, addressRemote.length, ...encoder.encode(addressRemote)]
            );
            break;
        case 3: // IPv6
            DSTADDR = new Uint8Array(
                [4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
            );
            break;
        default:
            log(`无效的地址类型: ${addressType}`);
            return;
    }
    const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
    // 5: SOCKS5版本, 1: 表示CONNECT请求, 0: 保留字段
    // ...DSTADDR: 目标地址, portRemote >> 8 和 & 0xff: 将端口转为网络字节序
    await writer.write(socksRequest);
    log('已发送 SOCKS5 请求');

    res = (await reader.read()).value;
    if (res[1] === 0x00) {
        log("SOCKS5 连接已建立");
    } else {
        log("SOCKS5 连接建立失败");
        return;
    }
    writer.releaseLock();
    reader.releaseLock();
    return socket;
}


async function httpConnect(addressRemote, portRemote, log) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const sock = await connect({
        hostname: hostname,
        port: port
    });

    // 构建HTTP CONNECT请求
    let connectRequest = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\n`;
    connectRequest += `Host: ${addressRemote}:${portRemote}\r\n`;

    // 添加代理认证（如果需要）
    if (username && password) {
        const authString = `${username}:${password}`;
        const base64Auth = btoa(authString);
        connectRequest += `Proxy-Authorization: Basic ${base64Auth}\r\n`;
    }

    connectRequest += `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n`;
    connectRequest += `Proxy-Connection: Keep-Alive\r\n`;
    connectRequest += `Connection: Keep-Alive\r\n`; // 添加标准 Connection 头
    connectRequest += `\r\n`;

    log(`正在连接到 ${addressRemote}:${portRemote} 通过代理 ${hostname}:${port}`);

    try {
        // 发送连接请求
        const writer = sock.writable.getWriter();
        await writer.write(new TextEncoder().encode(connectRequest));
        writer.releaseLock();
    } catch (err) {
        console.error('发送HTTP CONNECT请求失败:', err);
        throw new Error(`发送HTTP CONNECT请求失败: ${err.message}`);
    }

    // 读取HTTP响应
    const reader = sock.readable.getReader();
    let respText = '';
    let connected = false;
    let responseBuffer = new Uint8Array(0);

    try {
        while (true) {
            const { value, done } = await reader.read();
            if (done) {
                console.error('HTTP代理连接中断');
                throw new Error('HTTP代理连接中断');
            }

            // 合并接收到的数据
            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;

            // 将收到的数据转换为文本
            respText = new TextDecoder().decode(responseBuffer);

            // 检查是否收到完整的HTTP响应头
            if (respText.includes('\r\n\r\n')) {
                // 分离HTTP头和可能的数据部分
                const headersEndPos = respText.indexOf('\r\n\r\n') + 4;
                const headers = respText.substring(0, headersEndPos);

                log(`收到HTTP代理响应: ${headers.split('\r\n')[0]}`);

                // 检查响应状态
                if (headers.startsWith('HTTP/1.1 200') || headers.startsWith('HTTP/1.0 200')) {
                    connected = true;

                    // 如果响应头之后还有数据，我们需要保存这些数据以便后续处理
                    if (headersEndPos < responseBuffer.length) {
                        const remainingData = responseBuffer.slice(headersEndPos);
                        // 创建一个缓冲区来存储这些数据，以便稍后使用
                        const dataStream = new ReadableStream({
                            start(controller) {
                                controller.enqueue(remainingData);
                            }
                        });

                        // 创建一个新的TransformStream来处理额外数据
                        const { readable, writable } = new TransformStream();
                        dataStream.pipeTo(writable).catch(err => console.error('处理剩余数据错误:', err));

                        // 替换原始readable流
                        // @ts-ignore
                        sock.readable = readable;
                    }
                } else {
                    const errorMsg = `HTTP代理连接失败: ${headers.split('\r\n')[0]}`;
                    console.error(errorMsg);
                    throw new Error(errorMsg);
                }
                break;
            }
        }
    } catch (err) {
        reader.releaseLock();
        throw new Error(`处理HTTP代理响应失败: ${err.message}`);
    }

    reader.releaseLock();

    if (!connected) {
        throw new Error('HTTP代理连接失败: 未收到成功响应');
    }

    log(`HTTP代理连接成功: ${addressRemote}:${portRemote}`);
    return sock;
}

function socks5AddressParser(address) {
    // 使用 "@" 分割地址，分为认证部分和服务器地址部分
    const lastAtIndex = address.lastIndexOf("@");
    let [latter, former] = lastAtIndex === -1 ? [address, undefined] : [address.substring(lastAtIndex + 1), address.substring(0, lastAtIndex)];
    let username, password, hostname, port;

    // 如果存在 former 部分，说明提供了认证信息
    if (former) {
        const formers = former.split(":");
        if (formers.length !== 2) {
            throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');
        }
        [username, password] = formers;
    }

    // 解析服务器地址部分
    const latters = latter.split(":");
    // 检查是否是IPv6地址带端口格式 [xxx]:port
    if (latters.length > 2 && latter.includes("]:")) {
        // IPv6地址带端口格式：[2001:db8::1]:8080
        port = Number(latter.split("]:")[1].replace(/[^\d]/g, ''));
        hostname = latter.split("]:")[0] + "]"; // 正确提取hostname部分
    } else if (latters.length === 2) {
        // IPv4地址带端口或域名带端口
        port = Number(latters.pop().replace(/[^\d]/g, ''));
        hostname = latters.join(":");
    } else {
        port = 80;
        hostname = latter;
    }

    if (isNaN(port)) {
        throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
    }

    // 处理 IPv6 地址的特殊情况
    // IPv6 地址包含多个冒号，所以必须用方括号括起来，如 [2001:db8::1]
    const regex = /^\[.*\]$/;
    if (hostname.includes(":") && !regex.test(hostname)) {
        throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');
    }

    //if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(hostname)) hostname = `${atob('d3d3Lg==')}${hostname}${atob('LmlwLjA5MDIyNy54eXo=')}`;
    // 返回解析后的结果
    return {
        username,  // 用户名，如果没有则为 undefined
        password,  // 密码，如果没有则为 undefined
        hostname,  // 主机名，可以是域名、IPv4 或 IPv6 地址
        port,	 // 端口号，已转换为数字类型
    }
}

function 恢复模糊信息(content, userID, hostName, mirrorUserID, mirrorHostName, isBase64) {
    if (isBase64) content = atob(content);  // 如果内容是Base64编码的，先解码

    content = content.replace(new RegExp(mirrorUserID, 'g'), userID)
        .replace(new RegExp(mirrorHostName, 'g'), hostName);

    if (isBase64) content = btoa(content);  // 如果原内容是Base64编码的，处理完后再次编码

    return content;
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

async function 代理URL(代理网址, 目标网址) {
    const 网址列表 = await 整理(代理网址);
    const 完整网址 = 网址列表[Math.floor(Math.random() * 网址列表.length)];

    // 解析目标 URL
    let 解析后的网址 = new URL(完整网址);
    console.log(解析后的网址);
    // 提取并可能修改 URL 组件
    let 协议 = 解析后的网址.protocol.slice(0, -1) || 'https';
    let 主机名 = 解析后的网址.hostname;
    let 路径名 = 解析后的网址.pathname;
    let 查询参数 = 解析后的网址.search;

    // 处理路径名
    if (路径名.charAt(路径名.length - 1) == '/') {
        路径名 = 路径名.slice(0, -1);
    }
    路径名 += 目标网址.pathname;

    // 构建新的 URL
    let 新网址 = `${协议}://${主机名}${路径名}${查询参数}`;

    // 反向代理请求
    let 响应 = await fetch(新网址);

    // 创建新的响应
    let 新响应 = new Response(响应.body, {
        status: 响应.status,
        statusText: 响应.statusText,
        headers: 响应.headers
    });

    // 添加自定义头部，包含 URL 信息
    //新响应.headers.set('X-Proxied-By', 'Cloudflare Worker');
    //新响应.headers.set('X-Original-URL', 完整网址);
    新响应.headers.set('X-New-URL', 新网址);

    return 新响应;
}

const 啥啥啥_写的这是啥啊 = atob('ZG14bGMzTT0=');
function 配置信息(UUID, 域名地址) {
    const 协议类型 = atob(啥啥啥_写的这是啥啊);

    const 别名 = FileName;
    let 地址 = 域名地址;
    let 端口 = 443;

    const 用户ID = UUID;
    const 加密方式 = 'none';

    const 传输层协议 = 'ws';
    const 模糊域名 = 域名地址;
    const 路径 = path;

    let 传输层安全 = ['tls', true];
    const SNI = 域名地址;
    const 指纹 = 'randomized';

    if (域名地址.includes('.workers.dev')) {
        地址 = atob('dmlzYS5jb20uaGs=');
        端口 = 80;
        传输层安全 = ['', false];
    }

    const 威图瑞 = `${协议类型}://${用户ID}@${地址}:${端口}\u003f\u0065\u006e\u0063\u0072\u0079` + 'p' + `${atob('dGlvbj0=') + 加密方式}\u0026\u0073\u0065\u0063\u0075\u0072\u0069\u0074\u0079\u003d${传输层安全[0]}&sni=${SNI}&fp=${指纹}&type=${传输层协议}&host=${模糊域名}&path=${encodeURIComponent(路径) + allowInsecure}&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}#${encodeURIComponent(别名)}`;
    const 猫猫猫 = `- {name: ${FileName}, server: ${地址}, port: ${端口}, type: ${协议类型}, uuid: ${用户ID}, tls: ${传输层安全[1]}, alpn: [h3], udp: false, sni: ${SNI}, tfo: false, skip-cert-verify: ${SCV}, servername: ${模糊域名}, client-fingerprint: ${指纹}, network: ${传输层协议}, ws-opts: {path: "${路径}", headers: {${模糊域名}}}}`;
    return [威图瑞, 猫猫猫];
}

let subParams = ['sub', 'base64', 'b64', 'clash', 'singbox', 'sb'];
const cmad = decodeURIComponent(atob('dGVsZWdyYW0lMjAlRTQlQkElQTQlRTYlQjUlODElRTclQkUlQTQlMjAlRTYlOEElODAlRTYlOUMlQUYlRTUlQTQlQTclRTQlQkQlQUMlN0UlRTUlOUMlQTglRTclQkElQkYlRTUlOEYlOTElRTclODklOEMhJTNDYnIlM0UKJTNDYSUyMGhyZWYlM0QlMjdodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlMjclM0VodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlM0MlMkZhJTNFJTNDYnIlM0UKLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tJTNDYnIlM0UKZ2l0aHViJTIwJUU5JUExJUI5JUU3JTlCJUFFJUU1JTlDJUIwJUU1JTlEJTgwJTIwU3RhciFTdGFyIVN0YXIhISElM0NiciUzRQolM0NhJTIwaHJlZiUzRCUyN2h0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUyNyUzRWh0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZWRnZXR1bm5lbCUzQyUyRmElM0UlM0NiciUzRQotLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0lM0NiciUzRQolMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjMlMjM='));
/**
 * @param {string} userID
 * @param {string | null} hostName
 * @param {string} sub
 * @param {string} UA
 * @returns {Promise<string>}
 */
async function 生成配置信息(userID, hostName, sub, UA, RproxyIP, _url, mirrorUserID, mirrorHostName, env) {
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
            // 定义 Cloudflare IP 范围的 CIDR 列表
            let cfips = ['104.16.0.0/13','162.159.152.0/23',
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

    const uuid = (_url.pathname == `/${动态UUID}`) ? 动态UUID : userID;
    const userAgent = UA.toLowerCase();
    const Config = 配置信息(userID, hostName);
    const v2ray = Config[0];
    const clash = Config[1];
    let proxyhost = "";
    if (hostName.includes(".workers.dev")) {
        if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
            try {
                const response = await fetch(proxyhostsURL);

                if (!response.ok) {
                    console.error('获取地址时出错:', response.status, response.statusText);
                    return; // 如果有错误，直接返回
                }

                const text = await response.text();
                const lines = text.split('\n');
                // 过滤掉空行或只包含空白字符的行
                const nonEmptyLines = lines.filter(line => line.trim() !== '');

                proxyhosts = proxyhosts.concat(nonEmptyLines);
            } catch (error) {
                //console.error('获取地址时出错:', error);
            }
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

        const 动态UUID信息 = (uuid != userID) ? `TOKEN: ${uuid}<br>UUIDNow: ${userID}<br>UUIDLow: ${userIDLow}<br>${userIDTime}TIME（动态UUID有效时间）: ${有效时间} 天<br>UPTIME（动态UUID更新时间）: ${更新时间} 时（北京时间）<br><br>` : `${userIDTime}`;
        const 节点配置页 = `################################################################<br>`;
        return `<div style="font-size:13px;">${节点配置页}</div>`;
    } else {
        if (typeof fetch != 'function') {
            return 'Error: fetch is not available in this environment.';
        }

        let newAddressesapi = [];
        let newAddressescsv = [];
        let newAddressesnotlsapi = [];
        let newAddressesnotlscsv = [];

        // 如果是使用默认域名，则改成一个workers的域名，订阅器会加上代理
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
        console.log(`镜子HOST: ${mirrorHostName}`);
        let url = `${subProtocol}://${sub}/sub?host=${mirrorHostName}&uuid=${mirrorUserID + atob('JmVkZ2V0dW5uZWw9Y21saXUmcHJveHlpcD0=') + RproxyIP}&path=${encodeURIComponent(path)}`;
        let isBase64 = true;

        if (!sub || sub == "") {
            if (hostName.includes('workers.dev')) {
                if (proxyhostsURL && (!proxyhosts || proxyhosts.length == 0)) {
                    try {
                        const response = await fetch(proxyhostsURL);

                        if (!response.ok) {
                            console.error('获取地址时出错:', response.status, response.statusText);
                            return; // 如果有错误，直接返回
                        }

                        const text = await response.text();
                        const lines = text.split('\n');
                        // 过滤掉空行或只包含空白字符的行
                        const nonEmptyLines = lines.filter(line => line.trim() !== '');

                        proxyhosts = proxyhosts.concat(nonEmptyLines);
                    } catch (error) {
                        console.error('获取地址时出错:', error);
                    }
                }
                // 使用Set对象去重
                proxyhosts = [...new Set(proxyhosts)];
            }

            newAddressesapi = await 整理优选列表(addressesapi);
            newAddressescsv = await 整理测速结果('TRUE');
            url = `https://${hostName}/${mirrorUserID + _url.search}`;
            if (hostName.includes("worker") || hostName.includes("notls") || noTLS == 'true') {
                if (_url.search) url += '&notls';
                else url += '?notls';
            }
            console.log(`镜子订阅: ${url}`);
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
                        'User-Agent': 'v2rayN' + atob('L2VkZ2V0dW5uZWwgKGh0dHBzOi8vZ2l0aHViLmNvbS9jbWxpdS9lZGdldHVubmVsKQ==')
                    }
                });
                content = await response.text();
            }

            if (_url.pathname == `/${mirrorUserID}`) return content;

            return 恢复模糊信息(content, userID, hostName, mirrorUserID, mirrorHostName, isBase64);

        } catch (error) {
            console.error('Error fetching content:', error);
            return `Error fetching content: ${error.message}`;
        }
    }
}

async function 整理优选列表(api) {
    if (!api || api.length === 0) return [];

    let newapi = "";

    // 创建一个AbortController对象，用于控制fetch请求的取消
    const controller = new AbortController();

    const timeout = setTimeout(() => {
        controller.abort(); // 取消所有请求
    }, 2000); // 2秒后触发

    try {
        // 使用Promise.allSettled等待所有API请求完成，无论成功或失败
        // 对api数组进行遍历，对每个API地址发起fetch请求
        const responses = await Promise.allSettled(api.map(apiUrl => fetch(apiUrl, {
            method: 'get',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;',
                'User-Agent': atob('Q0YtV29ya2Vycy1lZGdldHVubmVsL2NtbGl1')
            },
            signal: controller.signal // 将AbortController的信号量添加到fetch请求中，以便于需要时可以取消请求
        }).then(response => response.ok ? response.text() : Promise.reject())));

        // 遍历所有响应
        for (const [index, response] of responses.entries()) {
            // 检查响应状态是否为'fulfilled'，即请求成功完成
            if (response.status === 'fulfilled') {
                // 获取响应的内容
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
                    // 验证当前apiUrl是否带有'proxyip=true'
                    if (api[index].includes('proxyip=true')) {
                        // 如果URL带有'proxyip=true'，则将内容添加到proxyIPPool
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
                            return null; // 不符合条件时返回 null
                        }).filter(Boolean)); // 过滤掉 null 值
                    }
                    // 将内容添加到newapi中
                    newapi += content + '\n';
                }
            }
        }
    } catch (error) {
        console.error(error);
    } finally {
        // 无论成功或失败，最后都清除设置的超时定时器
        clearTimeout(timeout);
    }

    const newAddressesapi = await 整理(newapi);

    // 返回处理后的结果
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
                console.error('获取CSV地址时出错:', response.status, response.statusText);
                continue;
            }

            const text = await response.text();// 使用正确的字符编码解析文本内容
            let lines;
            if (text.includes('\r\n')) {
                lines = text.split('\r\n');
            } else {
                lines = text.split('\n');
            }

            // 检查CSV头部是否包含必需字段
            const header = lines[0].split(',');
            const tlsIndex = header.indexOf('TLS');

            const ipAddressIndex = 0;// IP地址在 CSV 头部的位置
            const portIndex = 1;// 端口在 CSV 头部的位置
            const dataCenterIndex = tlsIndex + remarkIndex; // 数据中心是 TLS 的后一个字段

            if (tlsIndex === -1) {
                console.error('CSV文件缺少必需的字段');
                continue;
            }

            // 从第二行开始遍历CSV行
            for (let i = 1; i < lines.length; i++) {
                const columns = lines[i].split(',');
                const speedIndex = columns.length - 1; // 最后一个字段
                // 检查TLS是否为"TRUE"且速度大于DLS
                if (columns[tlsIndex].toUpperCase() === tls && parseFloat(columns[speedIndex]) > DLS) {
                    const ipAddress = columns[ipAddressIndex];
                    const port = columns[portIndex];
                    const dataCenter = columns[dataCenterIndex];

                    const formattedAddress = `${ipAddress}:${port}#${dataCenter}`;
                    newAddressescsv.push(formattedAddress);
                    if (csvUrl.includes('proxyip=true') && columns[tlsIndex].toUpperCase() == 'true' && !httpsPorts.includes(port)) {
                        // 如果URL带有'proxyip=true'，则将内容添加到proxyIPPool
                        proxyIPPool.push(`${ipAddress}:${port}`);
                    }
                }
            }
        } catch (error) {
            console.error('获取CSV地址时出错:', error);
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
            const 协议类型 = atob(啥啥啥_写的这是啥啊);

            const ctx = `${协议类型}://${UUID}@${address}:${port + atob('P2VuY3J5cHRpb249bm9uZSZzZWN1cml0eT0mdHlwZT13cyZob3N0PQ==') + 模糊域名}&path=${encodeURIComponent(最终路径)}#${encodeURIComponent(addressid + 节点备注)}`;

            return ctx;

        }).join('\n');

    }

    // 使用Set对象去重
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
        /*
        if (proxyhosts.length > 0 && (模糊域名.includes('.workers.dev'))) {
            最终路径 = `/${模糊域名}${最终路径}`;
            模糊域名 = proxyhosts[Math.floor(Math.random() * proxyhosts.length)];
            节点备注 = ` 已启用临时域名中转服务，请尽快绑定自定义域！`;
        }
        */
        const 协议类型 = atob(啥啥啥_写的这是啥啊);
        const ctx = `${协议类型}://${UUID}@${address}:${port + atob('P2VuY3J5cHRpb249bm9uZSZzZWN1cml0eT10bHMmc25pPQ==') + 模糊域名}&fp=random&type=ws&host=${模糊域名}&path=${encodeURIComponent(最终路径) + allowInsecure}&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}#${encodeURIComponent(addressid + 节点备注)}`;

        return ctx;
    }).join('\n');

    let base64Response = responseBody; // 重新进行 Base64 编码
    if (noTLS == 'true') base64Response += `\n${notlsresponseBody}`;
    if (link.length > 0) base64Response += '\n' + link.join('\n');
    return btoa(base64Response);
}

async function 整理(内容) {
    // 将制表符、双引号、单引号和换行符都替换为逗号
    // 然后将连续的多个逗号替换为单个逗号
    var 替换后的内容 = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');

    // 删除开头和结尾的逗号（如果有的话）
    if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
    if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);

    // 使用逗号分割字符串，得到地址数组
    const 地址数组 = 替换后的内容.split(',');

    return 地址数组;
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
    } catch (error) {
        console.error('Error sending message:', error);
    }
}

function isValidIPv4(address) {
    const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(address);
}

function 生成动态UUID(密钥) {
    const 时区偏移 = 8; // 北京时间相对于UTC的时区偏移+8小时
    const 起始日期 = new Date(2007, 6, 7, 更新时间, 0, 0); // 固定起始日期为2007年7月7日的凌晨3点
    const 一周的毫秒数 = 1000 * 60 * 60 * 24 * 有效时间;

    function 获取当前周数() {
        const 现在 = new Date();
        const 调整后的现在 = new Date(现在.getTime() + 时区偏移 * 60 * 60 * 1000);
        const 时间差 = Number(调整后的现在) - Number(起始日期);
        return Math.ceil(时间差 / 一周的毫秒数);
    }

    function 生成UUID(基础字符串) {
        const 哈希缓冲区 = new TextEncoder().encode(基础字符串);
        return crypto.subtle.digest('SHA-256', 哈希缓冲区).then((哈希) => {
            const 哈希数组 = Array.from(new Uint8Array(哈希));
            const 十六进制哈希 = 哈希数组.map(b => b.toString(16).padStart(2, '0')).join('');
            return `${十六进制哈希.substr(0, 8)}-${十六进制哈希.substr(8, 4)}-4${十六进制哈希.substr(13, 3)}-${(parseInt(十六进制哈希.substr(16, 2), 16) & 0x3f | 0x80).toString(16)}${十六进制哈希.substr(18, 2)}-${十六进制哈希.substr(20, 12)}`;
        });
    }

    const 当前周数 = 获取当前周数(); // 获取当前周数
    const 结束时间 = new Date(起始日期.getTime() + 当前周数 * 一周的毫秒数);

    // 生成两个 UUID
    const 当前UUIDPromise = 生成UUID(密钥 + 当前周数);
    const 上一个UUIDPromise = 生成UUID(密钥 + (当前周数 - 1));

    // 格式化到期时间
    const 到期时间UTC = new Date(结束时间.getTime() - 时区偏移 * 60 * 60 * 1000); // UTC时间
    const 到期时间字符串 = `到期时间(UTC): ${到期时间UTC.toISOString().slice(0, 19).replace('T', ' ')} (UTC+8): ${结束时间.toISOString().slice(0, 19).replace('T', ' ')}\n`;

    return Promise.all([当前UUIDPromise, 上一个UUIDPromise, 到期时间字符串]);
}

async function 迁移地址列表(env, txt = 'ADD.txt') {
    const 旧数据 = await env.KV.get(`/${txt}`);
    const 新数据 = await env.KV.get(txt);

    if (旧数据 && !新数据) {
        // 写入新位置
        await env.KV.put(txt, 旧数据);
        // 删除旧数据
        await env.KV.delete(`/${txt}`);
        return true;
    }
    return false;
}

async function resolveToIPv6(target) {
    const defaultAddress = atob('cHJveHlpcC5jbWxpdXNzc3MubmV0');
    if (!DNS64Server) {
        try {
            const response = await fetch(atob('aHR0cHM6Ly8xLjEuMS4xL2Rucy1xdWVyeT9uYW1lPW5hdDY0LmNtbGl1c3Nzcy5uZXQmdHlwZT1UWFQ='), {
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
            console.error('DNS64Server查询失败:', error);
            return defaultAddress;
        }
    }

    // 检查是否为IPv4
    function isIPv4(str) {
        const parts = str.split('.');
        return parts.length === 4 && parts.every(part => {
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255 && part === num.toString();
        });
    }

    // 检查是否为IPv6
    function isIPv6(str) {
        return str.includes(':') && /^[0-9a-fA-F:]+$/.test(str);
    }

    // 获取域名的IPv4地址
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

        if (ipv4s.length === 0) throw new Error('未找到IPv4地址');
        return ipv4s[Math.floor(Math.random() * ipv4s.length)];
    }

    // 查询NAT64 IPv6地址
    async function queryNAT64(domain) {
        const socket = connect({
            hostname: isIPv6(DNS64Server) ? `[${DNS64Server}]` : DNS64Server,
            port: 53
        });

        const writer = socket.writable.getWriter();
        const reader = socket.readable.getReader();

        try {
            // 发送DNS查询
            const query = buildDNSQuery(domain);
            const queryWithLength = new Uint8Array(query.length + 2);
            queryWithLength[0] = query.length >> 8;
            queryWithLength[1] = query.length & 0xFF;
            queryWithLength.set(query, 2);
            await writer.write(queryWithLength);

            // 读取响应
            const response = await readDNSResponse(reader);
            const ipv6s = parseIPv6(response);

            return ipv6s.length > 0 ? ipv6s[0] : '未找到IPv6地址';
        } finally {
            await writer.close();
            await reader.cancel();
        }
    }

    // 构建DNS查询包
    function buildDNSQuery(domain) {
        const buffer = new ArrayBuffer(512);
        const view = new DataView(buffer);
        let offset = 0;

        // DNS头部
        view.setUint16(offset, Math.floor(Math.random() * 65536)); offset += 2; // ID
        view.setUint16(offset, 0x0100); offset += 2; // 标志
        view.setUint16(offset, 1); offset += 2; // 问题数
        view.setUint16(offset, 0); offset += 6; // 答案数/权威数/附加数

        // 域名编码
        for (const label of domain.split('.')) {
            view.setUint8(offset++, label.length);
            for (let i = 0; i < label.length; i++) {
                view.setUint8(offset++, label.charCodeAt(i));
            }
        }
        view.setUint8(offset++, 0); // 结束标记

        // 查询类型和类
        view.setUint16(offset, 28); offset += 2; // AAAA记录
        view.setUint16(offset, 1); offset += 2; // IN类

        return new Uint8Array(buffer, 0, offset);
    }

    // 读取DNS响应
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

        // 合并数据并跳过长度前缀
        const fullResponse = new Uint8Array(totalLength);
        let offset = 0;
        for (const chunk of chunks) {
            fullResponse.set(chunk, offset);
            offset += chunk.length;
        }

        return fullResponse.slice(2);
    }

    // 解析IPv6地址
    function parseIPv6(response) {
        const view = new DataView(response.buffer);
        let offset = 12; // 跳过DNS头部

        // 跳过问题部分
        while (view.getUint8(offset) !== 0) {
            offset += view.getUint8(offset) + 1;
        }
        offset += 5;

        const answers = [];
        const answerCount = view.getUint16(6); // 答案数量

        for (let i = 0; i < answerCount; i++) {
            // 跳过名称
            if ((view.getUint8(offset) & 0xC0) === 0xC0) {
                offset += 2;
            } else {
                while (view.getUint8(offset) !== 0) {
                    offset += view.getUint8(offset) + 1;
                }
                offset++;
            }

            const type = view.getUint16(offset); offset += 2;
            offset += 6; // 跳过类和TTL
            const dataLength = view.getUint16(offset); offset += 2;

            if (type === 28 && dataLength === 16) { // AAAA记录
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
            throw new Error('无效的IPv4地址');
        }

        // 将每个部分转换为16进制
        const hex = parts.map(part => {
            const num = parseInt(part, 10);
            if (num < 0 || num > 255) {
                throw new Error('无效的IPv4地址段');
            }
            return num.toString(16).padStart(2, '0');
        });

        // 构造NAT64
        return DNS64Server.split('/96')[0] + hex[0] + hex[1] + ":" + hex[2] + hex[3];
    }

    try {
        // 判断输入类型并处理
        if (isIPv6(target)) return target; // IPv6直接返回
        const ipv4 = isIPv4(target) ? target : await fetchIPv4(target);
        const nat64 = DNS64Server.endsWith('/96') ? convertToNAT64IPv6(ipv4) : await queryNAT64(ipv4 + atob('LmlwLjA5MDIyNy54eXo='));
        return isIPv6(nat64) ? nat64 : defaultAddress;
    } catch (error) {
        console.error('解析错误:', error);
        return defaultAddress;
    }
}