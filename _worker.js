import { connect } from "cloudflare:sockets";

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
          "Access-Control-Max-Age": "86400",
        }
      });
    }

    const url = new URL(request.url);
    const path = url.pathname.toLowerCase();
    const corsHeaders = {
      "Content-Type": "application/json; charset=UTF-8",
      "Access-Control-Allow-Origin": "*"
    };

    // 1. /check 接口：请求官方 Debian 镜像站，动态提取并转码
    if (path === '/check') {
      const rawIp = url.searchParams.get('proxyip');
      if (!rawIp) {
        return new Response(JSON.stringify({ success: false, error: '缺少 proxyip 参数' }), { status: 400, headers: corsHeaders });
      }

      const checkResult = await CheckProxyIP(rawIp.trim());

      return new Response(JSON.stringify(checkResult, null, 2), {
        status: checkResult.success ? 200 : 502,
        headers: corsHeaders
      });
    }

    // 2. /resolve 接口：DoH 域名解析
    if (path === '/resolve') {
      const domain = url.searchParams.get('domain') || url.searchParams.get('name');
      if (!domain) {
        return new Response(JSON.stringify({ success: false, error: '缺少 domain 参数' }), { status: 400, headers: corsHeaders });
      }

      try {
        const ips = await resolveDomain(domain.trim());
        return new Response(JSON.stringify({ success: true, domain, ips }, null, 2), { status: 200, headers: corsHeaders });
      } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), { status: 500, headers: corsHeaders });
      }
    }

    // 3. /ip-info 或 根目录：直接展示访问者原生信息
    const visitorIP = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
    const cf = request.cf || {};
    const visitorCountry = countryCodeToIATA(cf.country || cf.colo);

    return new Response(JSON.stringify({
      status: "success",
      clientIP: visitorIP,
      country: visitorCountry,
      isp: cf.asOrganization || "Cloudflare, Inc.",
      as: cf.asn ? `AS${cf.asn} ${cf.asOrganization || ''}`.trim() : "AS13335 CLOUDFLARENET",
      timestamp: new Date().toISOString()
    }, null, 2), {
      status: 200,
      headers: corsHeaders
    });
  }
};

// --- 国家/地区二字码转主要机场三字代码 (IATA) 映射表（未知/UNK 统一兜底 USA） ---
function countryCodeToIATA(code) {
  if (!code || code.toUpperCase() === "UNK") return "USA";
  const upper = code.toUpperCase();

  const map = {
    "HK": "HKG", "TW": "TPE", "JP": "NRT", "KR": "ICN", "SG": "SIN",
    "CN": "PEK", "MO": "MFM", "MY": "KUL", "TH": "BKK", "VN": "SGN",
    "PH": "MNL", "ID": "CGK", "IN": "DEL", "AU": "SYD", "NZ": "AKL",
    "US": "USA", "CA": "YYZ", "MX": "MEX", "BR": "GRU", "AR": "EZE",
    "CL": "SCL", "GB": "LHR", "UK": "LHR", "DE": "FRA", "FR": "CDG",
    "NL": "AMS", "RU": "SVO", "IT": "FCO", "ES": "MAD", "CH": "ZRH",
    "SE": "ARN", "NO": "OSL", "PL": "WAW", "IE": "DUB", "TR": "IST",
    "UA": "KBP", "AE": "DXB", "ZA": "JNB", "EG": "CAI", "SA": "RUH",
    "IL": "TLV",
  };

  return map[upper] || (upper.length === 3 ? upper : "USA");
}

// --- DoH 域名解析 ---
async function resolveDomain(domain) {
  let cleanDomain = domain.includes(':') ? domain.split(':')[0] : domain;
  cleanDomain = cleanDomain.replace(/[\[\]]/g, '');

  const [ipv4Res, ipv6Res] = await Promise.all([
    fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(cleanDomain)}&type=A`, { headers: { 'Accept': 'application/dns-json' } }),
    fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(cleanDomain)}&type=AAAA`, { headers: { 'Accept': 'application/dns-json' } })
  ]);

  const [ipv4Data, ipv6Data] = await Promise.all([ipv4Res.json(), ipv6Res.json()]);
  const ips = [];

  if (ipv4Data.Answer) ips.push(...ipv4Data.Answer.filter(r => r.type === 1).map(r => r.data));
  if (ipv6Data.Answer) ips.push(...ipv6Data.Answer.filter(r => r.type === 28).map(r => `[${r.data}]`));

  if (ips.length === 0) throw new Error('未找到 A 或 AAAA 记录');
  return ips;
}

// --- ProxyIP 检测与官方镜像站地理信息提取 ---
async function CheckProxyIP(proxyIP) {
  let portRemote = 443;
  let targetHost = proxyIP;

  if (proxyIP.includes('[') && proxyIP.includes(']:')) {
    portRemote = parseInt(proxyIP.split(']:')[1]);
    targetHost = proxyIP.split(']:')[0] + ']';
  } else if (proxyIP.includes(':') && proxyIP.indexOf(':') === proxyIP.lastIndexOf(':')) {
    portRemote = parseInt(proxyIP.split(':')[1]);
    targetHost = proxyIP.split(':')[0];
  }

  try {
    const tcpSocket = connect({
      hostname: targetHost,
      port: portRemote,
    });

    // 请求官方 debian 镜像站页面
    const httpRequest =
      "GET /debian HTTP/1.1\r\n" +
      "Host: cloudflaremirrors.com\r\n" +
      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n" +
      "Connection: close\r\n\r\n";

    const writer = tcpSocket.writable.getWriter();
    await writer.write(new TextEncoder().encode(httpRequest));
    writer.releaseLock();

    const reader = tcpSocket.readable.getReader();
    let responseData = new Uint8Array(0);

    while (true) {
      const { value, done } = await Promise.race([
        reader.read(),
        new Promise(resolve => setTimeout(() => resolve({ done: true }), 5000))
      ]);

      if (done) break;
      if (value) {
        const newData = new Uint8Array(responseData.length + value.length);
        newData.set(responseData);
        newData.set(value, responseData.length);
        responseData = newData;

        const responseText = new TextDecoder().decode(responseData);
        if (responseText.includes("\r\n\r\n") &&
          (responseText.toLowerCase().includes("connection: close") || responseText.toLowerCase().includes("content-length"))) {
          break;
        }
      }
    }
    reader.releaseLock();
    await tcpSocket.close();

    const responseText = new TextDecoder().decode(responseData);
    const statusMatch = responseText.match(/^HTTP\/\d\.\d\s+(\d+)/i);
    const statusCode = statusMatch ? parseInt(statusMatch[1]) : null;

    const looksLikeCloudflare = responseText.toLowerCase().includes("cloudflare");
    const hasBody = responseData.length > 50;

    let country = "USA";

    if (looksLikeCloudflare) {
      // 1. 优先提取 Body 中的镜像站二级国家代码 (如 ftp.jp.debian.org -> jp)
      const mirrorMatch = responseText.match(/ftp\.([a-zA-Z]{2})\.debian\.org/i);
      if (mirrorMatch && mirrorMatch[1]) {
        country = countryCodeToIATA(mirrorMatch[1]);
      } else {
        // 2. 备用：从 CF-RAY 头提取三字机房代码 (如 86d1a938c8f12345-HKG -> HKG)[span_1](start_span)[span_1](end_span)
        const coloMatch = responseText.match(/cf-ray:\s*[a-zA-Z0-9]+-([a-zA-Z0-9]{3})/i);
        if (coloMatch && coloMatch[1]) {
          country = countryCodeToIATA(coloMatch[1]);
        }
      }
    }

    const isSuccessful = statusCode !== null && looksLikeCloudflare && hasBody;

    return {
      success: isSuccessful,
      proxyIP: targetHost,
      portRemote: portRemote,
      country: country,
      statusCode: statusCode || null,
      responseSize: responseData.length,
      isp: "Cloudflare, Inc.",
      as: "AS13335 CLOUDFLARENET",
      timestamp: new Date().toISOString(),
    };
  } catch (error) {
    return {
      success: false,
      proxyIP: targetHost,
      portRemote: portRemote,
      timestamp: new Date().toISOString(),
      error: error.message || error.toString()
    };
  }
}
