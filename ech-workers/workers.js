// 1. 在这里设置你的 UUID (建议使用 UUID 生成器生成一个复杂的)
// 你也可以在 Cloudflare 后台的环境变量中设置 'UUID'，代码会自动优先读取环境变量
const CLIENT_UUID = 'd342d11e-d424-4583-b36e-524ab1f0afa4';

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CF_FALLBACK_IPS = ['[2a00:1098:2b::1:6815:5881]'];

const encoder = new TextEncoder();
const BUFFER_SIZE = 64 * 1024;

import { connect } from 'cloudflare:sockets';

export default {
  async fetch(request, env, ctx) {
    try {
      // 优先从环境变量读取 UUID，如果没设置则使用代码顶部的常量
      const userID = (env.UUID || CLIENT_UUID).toLowerCase();
      
      const upgradeHeader = request.headers.get('Upgrade');
      const url = new URL(request.url);

      // --- 安全校验逻辑开始 ---
      
      // 1. 简单伪装：如果是根路径且不是 websocket 请求，返回正常网页内容
      // 这样别人访问你的域名，只是一张白纸或伪装页面，看不出是代理
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
        const urlPath = url.pathname;
        if (urlPath === '/' || urlPath === '/favicon.ico') {
          return new Response('Welcome to nginx!', { status: 200 }); // 伪装成 nginx 默认页
        }
        return new Response('Not Found', { status: 404 });
      }

      // 2. 核心校验：检查路径中是否包含 UUID 或者 Header 中是否包含 UUID
      // 客户端连接地址示例: wss://你的域名.com/d342d11e-d424-4583-b36e-524ab1f0afa4
      const pathIncludesUUID = url.pathname.toLowerCase().includes(userID);
      const headerIncludesUUID = request.headers.get('Sec-WebSocket-Protocol') === userID;

      if (!pathIncludesUUID && !headerIncludesUUID) {
        return new Response('Unauthorized', { status: 401 });
      }
      
      // --- 安全校验逻辑结束 ---

      const [client, server] = Object.values(new WebSocketPair());
      server.accept();
      
      handleSession(server).catch(() => safeCloseWebSocket(server));

      const responseInit = {
        status: 101,
        webSocket: client
      };
      
      // 如果客户端是通过 Header 传递的 UUID，需要回传该 Header 以完成握手
      if (headerIncludesUUID) {
        responseInit.headers = { 'Sec-WebSocket-Protocol': userID };
      }

      return new Response(null, responseInit);
      
    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  },
};

async function handleSession(webSocket) {
  let remoteSocket, remoteWriter, remoteReader;
  let isClosed = false;

  const cleanup = () => {
    if (isClosed) return;
    isClosed = true;
    
    try { remoteWriter?.releaseLock(); } catch {}
    try { remoteReader?.releaseLock(); } catch {}
    try { remoteSocket?.close(); } catch {}
    
    remoteWriter = remoteReader = remoteSocket = null;
    safeCloseWebSocket(webSocket);
  };

  const pumpRemoteToWebSocket = async () => {
    try {
      while (!isClosed && remoteReader) {
        const { done, value } = await remoteReader.read();
        
        if (done) break;
        if (webSocket.readyState !== WS_READY_STATE_OPEN) break;
        if (value?.byteLength > 0) webSocket.send(value);
      }
    } catch {}
    
    if (!isClosed) {
      try { webSocket.send('CLOSE'); } catch {}
      cleanup();
    }
  };

  const parseAddress = (addr) => {
    if (addr[0] === '[') {
      const end = addr.indexOf(']');
      return {
        host: addr.substring(1, end),
        port: parseInt(addr.substring(end + 2), 10)
      };
    }
    const sep = addr.lastIndexOf(':');
    return {
      host: addr.substring(0, sep),
      port: parseInt(addr.substring(sep + 1), 10)
    };
  };

  const isCFError = (err) => {
    const msg = err?.message?.toLowerCase() || '';
    return msg.includes('proxy request') || 
           msg.includes('cannot connect') || 
           msg.includes('cloudflare');
  };

  const connectToRemote = async (targetAddr, firstFrameData) => {
    const { host, port } = parseAddress(targetAddr);
    // 安全策略：禁止连接局域网 IP (防止 SSRF 攻击)
    if (host.startsWith('127.') || host.startsWith('192.168.') || host.startsWith('10.')) {
        throw new Error('Local network access denied');
    }

    const attempts = [null, ...CF_FALLBACK_IPS];

    for (let i = 0; i < attempts.length; i++) {
      try {
        remoteSocket = connect({
          hostname: attempts[i] || host,
          port
        });

        if (remoteSocket.opened) await remoteSocket.opened;

        remoteWriter = remoteSocket.writable.getWriter();
        remoteReader = remoteSocket.readable.getReader();

        if (firstFrameData) {
          await remoteWriter.write(encoder.encode(firstFrameData));
        }

        webSocket.send('CONNECTED');
        pumpRemoteToWebSocket();
        return;

      } catch (err) {
        try { remoteWriter?.releaseLock(); } catch {}
        try { remoteReader?.releaseLock(); } catch {}
        try { remoteSocket?.close(); } catch {}
        remoteWriter = remoteReader = remoteSocket = null;

        if (!isCFError(err) || i === attempts.length - 1) {
          throw err;
        }
      }
    }
  };

  webSocket.addEventListener('message', async (event) => {
    if (isClosed) return;

    try {
      const data = event.data;

      if (typeof data === 'string') {
        if (data.startsWith('CONNECT:')) {
          const sep = data.indexOf('|', 8);
          await connectToRemote(
            data.substring(8, sep),
            data.substring(sep + 1)
          );
        }
        else if (data.startsWith('DATA:')) {
          if (remoteWriter) {
            await remoteWriter.write(encoder.encode(data.substring(5)));
          }
        }
        else if (data === 'CLOSE') {
          cleanup();
        }
      }
      else if (data instanceof ArrayBuffer && remoteWriter) {
        await remoteWriter.write(new Uint8Array(data));
      }
    } catch (err) {
      try { webSocket.send('ERROR:' + err.message); } catch {}
      cleanup();
    }
  });

  webSocket.addEventListener('close', cleanup);
  webSocket.addEventListener('error', cleanup);
}

function safeCloseWebSocket(ws) {
  try {
    if (ws.readyState === WS_READY_STATE_OPEN || 
        ws.readyState === WS_READY_STATE_CLOSING) {
      ws.close(1000, 'Server closed');
    }
  } catch {}
}