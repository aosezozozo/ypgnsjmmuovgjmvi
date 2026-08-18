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

    // 1. /check 接口：仅当检测通过时，才查询地理信息并以英文完整输出
    if (path === '/check') {
      const rawIp = url.searchParams.get('proxyip');
      if (!rawIp) {
        return new Response(JSON.stringify({ success: false, error: '缺少 proxyip 参数' }), { status: 400, headers: corsHeaders });
      }

      const checkResult = await CheckProxyIP(rawIp.trim());

      if (checkResult.success) {
        const geoInfo = await getIPGeo(checkResult.proxyIP);
        let iataCode = checkResult.colo;

        // 如果报文未提取到 CF-RAY 机场码，则使用国家代码进行映射
        if (!iataCode || iataCode === "UNK") {
          iataCode = countryCodeToIATA(geoInfo.countryCode);
        }

        checkResult.country = iataCode;
        checkResult.region = geoInfo.region || "";
        checkResult.city = geoInfo.city || "";
        checkResult.isp = geoInfo.isp || "";
        checkResult.as = geoInfo.as || "";
        delete checkResult.colo;
      }

      return new Response(JSON.stringify(checkResult, null, 2), {
        status: checkResult.success ? 200 : 502,
        headers: corsHeaders
      });
    }

    // 2. /resolve 接口：域名解析
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

    // 3. /ip-info 接口：指定查询 IP 归属地（全英文保留字段）
    if (path === '/ip-info') {
      const clientIP = url.searchParams.get('ip') || request.headers.get('CF-Connecting-IP') || '127.0.0.1';
      const geoInfo = await getIPGeo(clientIP);
      const iataCode = countryCodeToIATA(geoInfo.countryCode);

      return new Response(JSON.stringify({
        status: geoInfo.status,
        ip: geoInfo.ip,
        country: iataCode,
        region: geoInfo.region,
        city: geoInfo.city,
        isp: geoInfo.isp,
        as: geoInfo.as
      }, null, 2), { status: 200, headers: corsHeaders });
    }

    // 4. 根目录：直接展示当前访问者的 IP 与全套英文地理信息
    const visitorIP = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
    const visitorGeo = await getIPGeo(visitorIP);
    const visitorIATA = countryCodeToIATA(visitorGeo.countryCode);

    return new Response(JSON.stringify({
      status: "success",
      clientIP: visitorIP,
      country: visitorIATA,
      region: visitorGeo.region,
      city: visitorGeo.city,
      isp: visitorGeo.isp,
      as: visitorGeo.as,
      timestamp: new Date().toISOString()
    }, null, 2), {
      status: 200,
      headers: corsHeaders
    });
  }
};

// --- 国家/地区二字码转主要机场三字代码 (IATA) 映射表 ---
function countryCodeToIATA(code) {
  if (!code) return "UNK";
  const map = {
    "HK": "HKG", // 香港
    "TW": "TPE", // 台湾
    "JP": "NRT", // 日本
    "KR": "ICN", // 韩国
    "SG": "SIN", // 新加坡
    "US": "USA", // 美国
    "GB": "LHR", // 英国
    "DE": "FRA", // 德国
    "FR": "CDG", // 法国
    "NL": "AMS", // 荷兰
    "RU": "SVO", // 俄罗斯
    "CA": "YYZ", // 加拿大
    "AU": "SYD", // 澳大利亚
    "CN": "PEK", // 中国大陆
    "MO": "MFM", // 澳门
    "MY": "KUL", // 马来西亚
    "TH": "BKK", // 泰国
    "VN": "SGN", // 越南
    "PH": "MNL", // 菲律宾
    "IN": "DEL", // 印度
  };
  return map[code.toUpperCase()] || code.toUpperCase();
}

// --- 英文地理位置查询（自动清洗端口，多源兜底） ---
async function getIPGeo(ip) {
  let cleanIp = ip.trim();
  if (cleanIp.startsWith('[') && cleanIp.includes(']')) {
    cleanIp = cleanIp.substring(1, cleanIp.indexOf(']'));
  } else if (cleanIp.includes(':') && cleanIp.indexOf(':') === cleanIp.lastIndexOf(':')) {
    cleanIp = cleanIp.split(':')[0];
  }

  // 1. 优先请求 ipwho.is (英文原生返回)
  try {
    const res = await fetch(`https://ipwho.is/${encodeURIComponent(cleanIp)}`);
    const data = await res.json();
    if (data.success) {
      return {
        status: "success",
        ip: cleanIp,
        countryCode: data.country_code || "",
        region: data.region || "",
        city: data.city || "",
        isp: data.connection?.isp || "",
        as: `${data.connection?.asn ? 'AS' + data.connection.asn : ''} ${data.connection?.org || ''}`.trim()
      };
    }
  } catch (_) {}

  // 2. 备用请求 ip-api.com (英文原生返回)
  try {
    const res = await fetch(`http://ip-api.com/json/${encodeURIComponent(cleanIp)}`);
    const data = await res.json();
    if (data.status === "success") {
      return {
        status: "success",
        ip: cleanIp,
        countryCode: data.countryCode || "",
        region: data.regionName || "",
        city: data.city || "",
        isp: data.isp || "",
        as: data.as || ""
      };
    }
  } catch (_) {}

  return { status: "fail", ip: cleanIp, countryCode: "UNK", region: "", city: "", isp: "", as: "" };
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

// --- ProxyIP 检测 ---
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

    const httpRequest =
      "GET /cdn-cgi/trace HTTP/1.1\r\n" +
      "Host: speed.cloudflare.com\r\n" +
      "User-Agent: CheckProxyIP/API\r\n" +
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
    const isExpectedError = responseText.includes("plain HTTP request") || responseText.includes("400 Bad Request");
    const hasBody = responseData.length > 50;

    let colo = "UNK";
    if (looksLikeCloudflare) {
      const coloMatch = responseText.match(/cf-ray:\s*[a-zA-Z0-9]+-([a-zA-Z0-9]{3})/i);
      if (coloMatch && coloMatch[1]) {
        colo = coloMatch[1].toUpperCase();
      }
    }

    const isSuccessful = statusCode !== null && looksLikeCloudflare && isExpectedError && hasBody;

    return {
      success: isSuccessful,
      proxyIP: targetHost,
      portRemote: portRemote,
      colo: colo,
      statusCode: statusCode || null,
      responseSize: responseData.length,
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
