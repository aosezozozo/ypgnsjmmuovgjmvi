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

    if (path === '/check') {
      const rawIp = url.searchParams.get('proxyip');
      if (!rawIp) {
        return new Response(JSON.stringify({ success: false, error: '缺少 proxyip 参数' }), { 
          status: 400, 
          headers: corsHeaders 
        });
      }

      const checkResult = await CheckProxyIP(rawIp.trim());

      return new Response(JSON.stringify(checkResult, null, 2), {
        status: checkResult.success ? 200 : 502,
        headers: corsHeaders
      });
    }

    // 访客原生信息
    const visitorIP = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
    const cf = request.cf || {};
    const locInfo = matchLocation(cf.colo || cf.country);

    return new Response(JSON.stringify({
      status: "success",
      clientIP: visitorIP,
      dataCenter: locInfo.iata,
      country: locInfo.cca2,
      region: locInfo.region,
      city: locInfo.city,
      isp: cf.asOrganization || "Cloudflare, Inc.",
      as: cf.asn ? `AS${cf.asn} ${cf.asOrganization || ''}`.trim() : "AS13335 CLOUDFLARENET",
      timestamp: new Date().toISOString()
    }, null, 2), {
      status: 200,
      headers: corsHeaders
    });
  }
};

// --- 全球常用 Cloudflare 机房/机场代码地理字典 ---
const IATA_MAP = {
  // 亚太地区
  "HKG": { cca2: "HK", region: "Asia", city: "Hong Kong" },
  "MFM": { cca2: "MO", region: "Asia", city: "Macau" },
  "TPE": { cca2: "TW", region: "Asia", city: "Taipei" },
  "KHH": { cca2: "TW", region: "Asia", city: "Kaohsiung" },
  "NRT": { cca2: "JP", region: "Asia", city: "Tokyo" },
  "HND": { cca2: "JP", region: "Asia", city: "Tokyo" },
  "KIX": { cca2: "JP", region: "Asia", city: "Osaka" },
  "FUK": { cca2: "JP", region: "Asia", city: "Fukuoka" },
  "ICN": { cca2: "KR", region: "Asia", city: "Seoul" },
  "SIN": { cca2: "SG", region: "Asia", city: "Singapore" },
  "BKK": { cca2: "TH", region: "Asia", city: "Bangkok" },
  "KUL": { cca2: "MY", region: "Asia", city: "Kuala Lumpur" },
  "JHB": { cca2: "MY", region: "Asia", city: "Johor Bahru" },
  "SGN": { cca2: "VN", region: "Asia", city: "Ho Chi Minh City" },
  "HAN": { cca2: "VN", region: "Asia", city: "Hanoi" },
  "MNL": { cca2: "PH", region: "Asia", city: "Manila" },
  "CGK": { cca2: "ID", region: "Asia", city: "Jakarta" },
  "DEL": { cca2: "IN", region: "Asia", city: "New Delhi" },
  "BOM": { cca2: "IN", region: "Asia", city: "Mumbai" },
  "MAA": { cca2: "IN", region: "Asia", city: "Chennai" },
  "BLR": { cca2: "IN", region: "Asia", city: "Bangalore" },
  "HYD": { cca2: "IN", region: "Asia", city: "Hyderabad" },
  "SYD": { cca2: "AU", region: "Oceania", city: "Sydney" },
  "MEL": { cca2: "AU", region: "Oceania", city: "Melbourne" },
  "BNE": { cca2: "AU", region: "Oceania", city: "Brisbane" },
  "PER": { cca2: "AU", region: "Oceania", city: "Perth" },
  "AKL": { cca2: "NZ", region: "Oceania", city: "Auckland" },
  // 北美地区
  "SJC": { cca2: "US", region: "North America", city: "San Jose" },
  "LAX": { cca2: "US", region: "North America", city: "Los Angeles" },
  "SFO": { cca2: "US", region: "North America", city: "San Francisco" },
  "SEA": { cca2: "US", region: "North America", city: "Seattle" },
  "PDX": { cca2: "US", region: "North America", city: "Portland" },
  "ORD": { cca2: "US", region: "North America", city: "Chicago" },
  "DFW": { cca2: "US", region: "North America", city: "Dallas" },
  "IAD": { cca2: "US", region: "North America", city: "Ashburn" },
  "EWR": { cca2: "US", region: "North America", city: "Newark" },
  "JFK": { cca2: "US", region: "North America", city: "New York" },
  "ATL": { cca2: "US", region: "North America", city: "Atlanta" },
  "MIA": { cca2: "US", region: "North America", city: "Miami" },
  "DEN": { cca2: "US", region: "North America", city: "Denver" },
  "PHX": { cca2: "US", region: "North America", city: "Phoenix" },
  "YYZ": { cca2: "CA", region: "North America", city: "Toronto" },
  "YVR": { cca2: "CA", region: "North America", city: "Vancouver" },
  "YUL": { cca2: "CA", region: "North America", city: "Montreal" },
  // 欧洲地区
  "LHR": { cca2: "GB", region: "Europe", city: "London" },
  "MAN": { cca2: "GB", region: "Europe", city: "Manchester" },
  "FRA": { cca2: "DE", region: "Europe", city: "Frankfurt" },
  "MUC": { cca2: "DE", region: "Europe", city: "Munich" },
  "BER": { cca2: "DE", region: "Europe", city: "Berlin" },
  "CDG": { cca2: "FR", region: "Europe", city: "Paris" },
  "MRS": { cca2: "FR", region: "Europe", city: "Marseille" },
  "AMS": { cca2: "NL", region: "Europe", city: "Amsterdam" },
  "MAD": { cca2: "ES", region: "Europe", city: "Madrid" },
  "BCN": { cca2: "ES", region: "Europe", city: "Barcelona" },
  "MXP": { cca2: "IT", region: "Europe", city: "Milan" },
  "FCO": { cca2: "IT", region: "Europe", city: "Rome" },
  "ZRH": { cca2: "CH", region: "Europe", city: "Zurich" },
  "GVA": { cca2: "CH", region: "Europe", city: "Geneva" },
  "VIE": { cca2: "AT", region: "Europe", city: "Vienna" },
  "BRU": { cca2: "BE", region: "Europe", city: "Brussels" },
  "ARN": { cca2: "SE", region: "Europe", city: "Stockholm" },
  "OSL": { cca2: "NO", region: "Europe", city: "Oslo" },
  "CPH": { cca2: "DK", region: "Europe", city: "Copenhagen" },
  "HEL": { cca2: "FI", region: "Europe", city: "Helsinki" },
  "WAW": { cca2: "PL", region: "Europe", city: "Warsaw" },
  "PRG": { cca2: "CZ", region: "Europe", city: "Prague" },
  "BUD": { cca2: "HU", region: "Europe", city: "Budapest" },
  "IST": { cca2: "TR", region: "Europe", city: "Istanbul" },
  "ATH": { cca2: "GR", region: "Europe", city: "Athens" },
  // 中东与南美
  "DXB": { cca2: "AE", region: "Middle East", city: "Dubai" },
  "DOH": { cca2: "QA", region: "Middle East", city: "Doha" },
  "TLV": { cca2: "IL", region: "Middle East", city: "Tel Aviv" },
  "GRU": { cca2: "BR", region: "South America", city: "Sao Paulo" },
  "GIG": { cca2: "BR", region: "South America", city: "Rio de Janeiro" },
  "EZE": { cca2: "AR", region: "South America", city: "Buenos Aires" },
  "SCL": { cca2: "CL", region: "South America", city: "Santiago" },
  "BOG": { cca2: "CO", region: "South America", city: "Bogota" },
  "LIM": { cca2: "PE", region: "South America", city: "Lima" },
  "JNB": { cca2: "ZA", region: "Africa", city: "Johannesburg" },
  "CPT": { cca2: "ZA", region: "Africa", city: "Cape Town" }
};

// 二字码备用映射表
const COUNTRY_TO_IATA = {
  "JP": "NRT", "HK": "HKG", "TW": "TPE", "KR": "ICN", "SG": "SIN",
  "US": "SJC", "CA": "YYZ", "GB": "LHR", "UK": "LHR", "DE": "FRA",
  "FR": "CDG", "NL": "AMS", "AU": "SYD", "NZ": "AKL", "TH": "BKK",
  "MY": "KUL", "VN": "SGN", "PH": "MNL", "ID": "CGK", "IN": "DEL"
};

// 字典地理位置匹配函数
function matchLocation(code) {
  if (!code || code.toUpperCase() === "UNK") {
    return { iata: "UNK", cca2: "UNK", region: "Unknown", city: "Unknown" };
  }

  let upper = code.toUpperCase();

  // 如果提取到的是 2 位国家代码，转为主机场代码匹配
  if (upper.length === 2 && COUNTRY_TO_IATA[upper]) {
    upper = COUNTRY_TO_IATA[upper];
  }

  const loc = IATA_MAP[upper];
  if (loc) {
    return {
      iata: upper,
      cca2: loc.cca2,
      region: loc.region,
      city: loc.city
    };
  }

  return {
    iata: upper,
    cca2: upper.length === 2 ? upper : "UNK",
    region: "Unknown",
    city: "Unknown"
  };
}

// 核心检测与地理位置提取
async function CheckProxyIP(proxyIP) {
  let targetHost = proxyIP;
  let rawPort = 443;

  if (proxyIP.includes('[') && proxyIP.includes(']:')) {
    rawPort = parseInt(proxyIP.split(']:')[1]);
    targetHost = proxyIP.split(']:')[0] + ']';
  } else if (proxyIP.includes(':') && proxyIP.indexOf(':') === proxyIP.lastIndexOf(':')) {
    rawPort = parseInt(proxyIP.split(':')[1]);
    targetHost = proxyIP.split(':')[0];
  }

  const startTime = Date.now();

  try {
    // 直连 80 端口以极速提取 CF-RAY 机房代码（对齐 Go scanIPs 实现）
    const tcpSocket = connect({
      hostname: targetHost,
      port: 80
    });

    const hostHeader = targetHost.includes(':') ? `[${targetHost}]` : targetHost;
    const httpRequest =
      `GET / HTTP/1.1\r\n` +
      `Host: ${hostHeader}\r\n` +
      `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n` +
      `Connection: close\r\n\r\n`;

    const writer = tcpSocket.writable.getWriter();
    await writer.write(new TextEncoder().encode(httpRequest));
    writer.releaseLock();

    const reader = tcpSocket.readable.getReader();
    let responseText = "";

    try {
      while (true) {
        const { value, done } = await Promise.race([
          reader.read(),
          new Promise(resolve => setTimeout(() => resolve({ done: true }), 2500))
        ]);

        if (done) break;
        if (value) {
          responseText += new TextDecoder().decode(value, { stream: true });
          if (responseText.toLowerCase().includes("cf-ray:") || responseText.includes("\r\n\r\n")) {
            break;
          }
        }
      }
    } finally {
      try { reader.releaseLock(); } catch (_) {}
      try { await tcpSocket.close(); } catch (_) {}
    }

    const tcpDuration = Date.now() - startTime;

    // 1. 获取 HTTP 状态码
    const statusMatch = responseText.match(/^HTTP\/\d\.\d\s+(\d+)/i);
    const statusCode = statusMatch ? parseInt(statusMatch[1]) : null;

    // 2. 精准提取 3 位机房 IATA 代码
    let extractedIATA = "UNK";

    // 优先：从 CF-RAY 响应头提取 (例如 cf-ray: 86d1a938c8f12345-HKG)
    const rayHeaderMatch = responseText.match(/cf-ray:\s*[a-zA-Z0-9]+-([a-zA-Z0-9]{3})/i);
    if (rayHeaderMatch && rayHeaderMatch[1]) {
      extractedIATA = rayHeaderMatch[1].toUpperCase();
    } else {
      // 备选 1：从 HTML 响应体中的 Ray ID 提取
      const rayBodyMatch = responseText.match(/Ray ID:\s*<[^>]+>[a-zA-Z0-9]+-([a-zA-Z0-9]{3})/i);
      if (rayBodyMatch && rayBodyMatch[1]) {
        extractedIATA = rayBodyMatch[1].toUpperCase();
      } else {
        // 备选 2：从镜像站特征提取国家代码
        const debianMatch = responseText.match(/ftp\.([a-zA-Z]{2})\.debian\.org/i);
        if (debianMatch && debianMatch[1]) {
          extractedIATA = debianMatch[1].toUpperCase();
        }
      }
    }

    // 3. 匹配真实地理位置
    const locInfo = matchLocation(extractedIATA);

    // 连通性判定：TCP 请求有响应即代表 IP 是通的
    const isConnected = responseText.length > 0;

    return {
      success: isConnected,
      proxyIP: targetHost,
      portRemote: rawPort,
      dataCenter: locInfo.iata,
      country: locInfo.cca2,
      region: locInfo.region,
      city: locInfo.city,
      latency: `${tcpDuration} ms`,
      tcpDuration: tcpDuration,
      statusCode: statusCode,
      isp: "Cloudflare, Inc.",
      as: "AS13335 CLOUDFLARENET",
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    return {
      success: false,
      proxyIP: targetHost,
      portRemote: rawPort,
      dataCenter: "UNK",
      country: "UNK",
      region: "Unknown",
      city: "Unknown",
      latency: `${Date.now() - startTime} ms`,
      timestamp: new Date().toISOString(),
      error: error.message || error.toString()
    };
  }
}
