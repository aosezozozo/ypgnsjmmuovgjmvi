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

// --- 全球 237 个 Cloudflare 机房/机场代码地理字典 (全量补齐) ---
const IATA_MAP = {
  "TIA": { cca2: "AL", region: "Europe", city: "Tirana" },
  "ALG": { cca2: "DZ", region: "Africa", city: "Algiers" },
  "AAE": { cca2: "DZ", region: "Africa", city: "Annaba" },
  "CZL": { cca2: "DZ", region: "Africa", city: "Constantine" },
  "ORN": { cca2: "DZ", region: "Africa", city: "Oran" },
  "LAD": { cca2: "AO", region: "Africa", city: "Luanda" },
  "EZE": { cca2: "AR", region: "South America", city: "Buenos Aires" },
  "COR": { cca2: "AR", region: "South America", city: "Córdoba" },
  "NQN": { cca2: "AR", region: "South America", city: "Neuquen" },
  "EVN": { cca2: "AM", region: "Middle East", city: "Yerevan" },
  "ADL": { cca2: "AU", region: "Oceania", city: "Adelaide" },
  "BNE": { cca2: "AU", region: "Oceania", city: "Brisbane" },
  "CBR": { cca2: "AU", region: "Oceania", city: "Canberra" },
  "HBA": { cca2: "AU", region: "Oceania", city: "Hobart" },
  "MEL": { cca2: "AU", region: "Oceania", city: "Melbourne" },
  "PER": { cca2: "AU", region: "Oceania", city: "Perth" },
  "SYD": { cca2: "AU", region: "Oceania", city: "Sydney" },
  "VIE": { cca2: "AT", region: "Europe", city: "Vienna" },
  "LLK": { cca2: "AZ", region: "Middle East", city: "Astara" },
  "GYD": { cca2: "AZ", region: "Middle East", city: "Baku" },
  "BAH": { cca2: "BH", region: "Middle East", city: "Manama" },
  "CGP": { cca2: "BD", region: "Asia Pacific", city: "Chittagong" },
  "DAC": { cca2: "BD", region: "Asia Pacific", city: "Dhaka" },
  "BGI": { cca2: "BB", region: "North America", city: "Bridgetown" },
  "MSQ": { cca2: "BY", region: "Europe", city: "Minsk" },
  "BRU": { cca2: "BE", region: "Europe", city: "Brussels" },
  "PBH": { cca2: "BT", region: "Asia Pacific", city: "Thimphu" },
  "LPB": { cca2: "BO", region: "South America", city: "La Paz" },
  "GBE": { cca2: "BW", region: "Africa", city: "Gaborone" },
  "QWJ": { cca2: "BR", region: "South America", city: "Americana" },
  "ARU": { cca2: "BR", region: "South America", city: "Aracatuba" },
  "BEL": { cca2: "BR", region: "South America", city: "Belém" },
  "CNF": { cca2: "BR", region: "South America", city: "Belo Horizonte" },
  "BNU": { cca2: "BR", region: "South America", city: "Blumenau" },
  "BSB": { cca2: "BR", region: "South America", city: "Brasilia" },
  "CFC": { cca2: "BR", region: "South America", city: "Cacador" },
  "VCP": { cca2: "BR", region: "South America", city: "Campinas" },
  "CAW": { cca2: "BR", region: "South America", city: "Campos dos Goytacazes" },
  "XAP": { cca2: "BR", region: "South America", city: "Chapeco" },
  "CGB": { cca2: "BR", region: "South America", city: "Cuiaba" },
  "CWB": { cca2: "BR", region: "South America", city: "Curitiba" },
  "FLN": { cca2: "BR", region: "South America", city: "Florianopolis" },
  "FOR": { cca2: "BR", region: "South America", city: "Fortaleza" },
  "GYN": { cca2: "BR", region: "South America", city: "Goiania" },
  "JOI": { cca2: "BR", region: "South America", city: "Joinville" },
  "JDO": { cca2: "BR", region: "South America", city: "Juazeiro do Norte" },
  "MAO": { cca2: "BR", region: "South America", city: "Manaus" },
  "PMW": { cca2: "BR", region: "South America", city: "Palmas" },
  "POA": { cca2: "BR", region: "South America", city: "Porto Alegre" },
  "REC": { cca2: "BR", region: "South America", city: "Recife" },
  "RAO": { cca2: "BR", region: "South America", city: "Ribeirao Preto" },
  "GIG": { cca2: "BR", region: "South America", city: "Rio de Janeiro" },
  "SSA": { cca2: "BR", region: "South America", city: "Salvador" },
  "SJP": { cca2: "BR", region: "South America", city: "São José do Rio Preto" },
  "SJK": { cca2: "BR", region: "South America", city: "São José dos Campos" },
  "GRU": { cca2: "BR", region: "South America", city: "São Paulo" },
  "SOD": { cca2: "BR", region: "South America", city: "Sorocaba" },
  "NVT": { cca2: "BR", region: "South America", city: "Timbo" },
  "UDI": { cca2: "BR", region: "South America", city: "Uberlandia" },
  "VIX": { cca2: "BR", region: "South America", city: "Vitoria" },
  "BWN": { cca2: "BN", region: "Asia Pacific", city: "Bandar Seri Begawan" },
  "SOF": { cca2: "BG", region: "Europe", city: "Sofia" },
  "OUA": { cca2: "BF", region: "Africa", city: "Ouagadougou" },
  "PNH": { cca2: "KH", region: "Asia Pacific", city: "Phnom Penh" },
  "YYC": { cca2: "CA", region: "North America", city: "Calgary" },
  "YVR": { cca2: "CA", region: "North America", city: "Vancouver" },
  "YWG": { cca2: "CA", region: "North America", city: "Winnipeg" },
  "YHZ": { cca2: "CA", region: "North America", city: "Halifax" },
  "YOW": { cca2: "CA", region: "North America", city: "Ottawa" },
  "YYZ": { cca2: "CA", region: "North America", city: "Toronto" },
  "YUL": { cca2: "CA", region: "North America", city: "Montréal" },
  "YXE": { cca2: "CA", region: "North America", city: "Saskatoon" },
  "ARI": { cca2: "CL", region: "South America", city: "Arica" },
  "CCP": { cca2: "CL", region: "South America", city: "Concepción" },
  "SCL": { cca2: "CL", region: "South America", city: "Santiago" },
  "BAQ": { cca2: "CO", region: "South America", city: "Barranquilla" },
  "BOG": { cca2: "CO", region: "South America", city: "Bogota" },
  "CLO": { cca2: "CO", region: "South America", city: "Cali" },
  "MDE": { cca2: "CO", region: "South America", city: "Medellín" },
  "FIH": { cca2: "CD", region: "Africa", city: "Kinshasa" },
  "SJO": { cca2: "CR", region: "South America", city: "San José" },
  "ABJ": { cca2: "CI", region: "Africa", city: "Abidjan" },
  "ASK": { cca2: "CI", region: "Africa", city: "Yamoussoukro" },
  "ZAG": { cca2: "HR", region: "Europe", city: "Zagreb" },
  "LCA": { cca2: "CY", region: "Europe", city: "Nicosia" },
  "PRG": { cca2: "CZ", region: "Europe", city: "Prague" },
  "CPH": { cca2: "DK", region: "Europe", city: "Copenhagen" },
  "JIB": { cca2: "DJ", region: "Africa", city: "Djibouti" },
  "STI": { cca2: "DO", region: "North America", city: "Santiago de los Caballeros" },
  "SDQ": { cca2: "DO", region: "North America", city: "Santo Domingo" },
  "GYE": { cca2: "EC", region: "South America", city: "Guayaquil" },
  "UIO": { cca2: "EC", region: "South America", city: "Quito" },
  "CAI": { cca2: "EG", region: "Africa", city: "Cairo" },
  "TLL": { cca2: "EE", region: "Europe", city: "Tallinn" },
  "ADD": { cca2: "ET", region: "Africa", city: "Addis Ababa" },
  "SUV": { cca2: "FJ", region: "Oceania", city: "Suva" },
  "HEL": { cca2: "FI", region: "Europe", city: "Helsinki" },
  "BOD": { cca2: "FR", region: "Europe", city: "Bordeaux" },
  "LYS": { cca2: "FR", region: "Europe", city: "Lyon" },
  "MRS": { cca2: "FR", region: "Europe", city: "Marseille" },
  "CDG": { cca2: "FR", region: "Europe", city: "Paris" },
  "PPT": { cca2: "PF", region: "Oceania", city: "Tahiti" },
  "TBS": { cca2: "GE", region: "Europe", city: "Tbilisi" },
  "TXL": { cca2: "DE", region: "Europe", city: "Berlin" },
  "DUS": { cca2: "DE", region: "Europe", city: "Düsseldorf" },
  "FRA": { cca2: "DE", region: "Europe", city: "Frankfurt" },
  "HAM": { cca2: "DE", region: "Europe", city: "Hamburg" },
  "MUC": { cca2: "DE", region: "Europe", city: "Munich" },
  "STR": { cca2: "DE", region: "Europe", city: "Stuttgart" },
  "ACC": { cca2: "GH", region: "Africa", city: "Accra" },
  "ATH": { cca2: "GR", region: "Europe", city: "Athens" },
  "SKG": { cca2: "GR", region: "Europe", city: "Thessaloniki" },
  "GND": { cca2: "GD", region: "South America", city: "St. George's" },
  "GUM": { cca2: "GU", region: "Asia Pacific", city: "Hagatna" },
  "GUA": { cca2: "GT", region: "North America", city: "Guatemala City" },
  "GEO": { cca2: "GY", region: "South America", city: "Georgetown" },
  "SAP": { cca2: "HN", region: "South America", city: "San Pedro Sula" },
  "TGU": { cca2: "HN", region: "South America", city: "Tegucigalpa" },
  "HKG": { cca2: "HK", region: "Asia Pacific", city: "Hong Kong" },
  "BUD": { cca2: "HU", region: "Europe", city: "Budapest" },
  "KEF": { cca2: "IS", region: "Europe", city: "Reykjavík" },
  "AMD": { cca2: "IN", region: "Asia Pacific", city: "Ahmedabad" },
  "BLR": { cca2: "IN", region: "Asia Pacific", city: "Bangalore" },
  "IXC": { cca2: "IN", region: "Asia Pacific", city: "Chandigarh" },
  "MAA": { cca2: "IN", region: "Asia Pacific", city: "Chennai" },
  "HYD": { cca2: "IN", region: "Asia Pacific", city: "Hyderabad" },
  "CNN": { cca2: "IN", region: "Asia Pacific", city: "Kannur" },
  "KNU": { cca2: "IN", region: "Asia Pacific", city: "Kanpur" },
  "COK": { cca2: "IN", region: "Asia Pacific", city: "Kochi" },
  "CCU": { cca2: "IN", region: "Asia Pacific", city: "Kolkata" },
  "BOM": { cca2: "IN", region: "Asia Pacific", city: "Mumbai" },
  "NAG": { cca2: "IN", region: "Asia Pacific", city: "Nagpur" },
  "DEL": { cca2: "IN", region: "Asia Pacific", city: "New Delhi" },
  "PAT": { cca2: "IN", region: "Asia Pacific", city: "Patna" },
  "DPS": { cca2: "ID", region: "Asia Pacific", city: "Denpasar" },
  "CGK": { cca2: "ID", region: "Asia Pacific", city: "Jakarta" },
  "MLG": { cca2: "ID", region: "Asia Pacific", city: "Malang" },
  "JOG": { cca2: "ID", region: "Asia Pacific", city: "Yogyakarta" },
  "BGW": { cca2: "IQ", region: "Middle East", city: "Baghdad" },
  "BSR": { cca2: "IQ", region: "Middle East", city: "Basra" },
  "EBL": { cca2: "IQ", region: "Middle East", city: "Erbil" },
  "NJF": { cca2: "IQ", region: "Middle East", city: "Najaf" },
  "XNH": { cca2: "IQ", region: "Middle East", city: "Nasiriyah" },
  "ISU": { cca2: "IQ", region: "Middle East", city: "Sulaymaniyah" },
  "DUB": { cca2: "IE", region: "Europe", city: "Dublin" },
  "HFA": { cca2: "IL", region: "Middle East", city: "Haifa" },
  "TLV": { cca2: "IL", region: "Middle East", city: "Tel Aviv" },
  "MXP": { cca2: "IT", region: "Europe", city: "Milan" },
  "PMO": { cca2: "IT", region: "Europe", city: "Palermo" },
  "FCO": { cca2: "IT", region: "Europe", city: "Rome" },
  "KIN": { cca2: "JM", region: "North America", city: "Kingston" },
  "FUK": { cca2: "JP", region: "Asia Pacific", city: "Fukuoka" },
  "OKA": { cca2: "JP", region: "Asia Pacific", city: "Naha" },
  "KIX": { cca2: "JP", region: "Asia Pacific", city: "Osaka" },
  "NRT": { cca2: "JP", region: "Asia Pacific", city: "Tokyo" },
  "AMM": { cca2: "JO", region: "Middle East", city: "Amman" },
  "AKX": { cca2: "KZ", region: "Europe", city: "Aktobe" },
  "ALA": { cca2: "KZ", region: "Europe", city: "Almaty" },
  "NQZ": { cca2: "KZ", region: "Europe", city: "Astana" },
  "MBA": { cca2: "KE", region: "Africa", city: "Mombasa" },
  "NBO": { cca2: "KE", region: "Africa", city: "Nairobi" },
  "ICN": { cca2: "KR", region: "Asia Pacific", city: "Seoul" },
  "KWI": { cca2: "KW", region: "Middle East", city: "Kuwait City" },
  "FRU": { cca2: "KG", region: "Asia Pacific", city: "Bishkek" },
  "VTE": { cca2: "LA", region: "Asia Pacific", city: "Vientiane" },
  "RIX": { cca2: "LV", region: "Europe", city: "Riga" },
  "BEY": { cca2: "LB", region: "Middle East", city: "Beirut" },
  "VNO": { cca2: "LT", region: "Europe", city: "Vilnius" },
  "LUX": { cca2: "LU", region: "Europe", city: "Luxembourg City" },
  "MFM": { cca2: "MO", region: "Asia Pacific", city: "Macau" },
  "TNR": { cca2: "MG", region: "Africa", city: "Antananarivo" },
  "LLW": { cca2: "MW", region: "Africa", city: "Lilongwe" },
  "JHB": { cca2: "MY", region: "Asia Pacific", city: "Johor Bahru" },
  "KUL": { cca2: "MY", region: "Asia Pacific", city: "Kuala Lumpur" },
  "KCH": { cca2: "MY", region: "Asia Pacific", city: "Kuching" },
  "MLE": { cca2: "MV", region: "Asia Pacific", city: "Male" },
  "MLA": { cca2: "MT", region: "Europe", city: "Santa Venera" },
  "MRU": { cca2: "MU", region: "Africa", city: "Port Louis" },
  "GDL": { cca2: "MX", region: "North America", city: "Guadalajara" },
  "MEX": { cca2: "MX", region: "North America", city: "Mexico City" },
  "QRO": { cca2: "MX", region: "North America", city: "Queretaro" },
  "KIV": { cca2: "MD", region: "Europe", city: "Chișinău" },
  "ULN": { cca2: "MN", region: "Asia Pacific", city: "Ulaanbaatar" },
  "MPM": { cca2: "MZ", region: "Africa", city: "Maputo" },
  "WDH": { cca2: "NA", region: "Africa", city: "Windhoek" },
  "KTM": { cca2: "NP", region: "Asia Pacific", city: "Kathmandu" },
  "AMS": { cca2: "NL", region: "Europe", city: "Amsterdam" },
  "NOU": { cca2: "NC", region: "Oceania", city: "Noumea" },
  "AKL": { cca2: "NZ", region: "Oceania", city: "Auckland" },
  "CHC": { cca2: "NZ", region: "Oceania", city: "Christchurch" },
  "LOS": { cca2: "NG", region: "Africa", city: "Lagos" },
  "SKP": { cca2: "MK", region: "Europe", city: "Skopje" },
  "OSL": { cca2: "NO", region: "Europe", city: "Oslo" },
  "MCT": { cca2: "OM", region: "Middle East", city: "Muscat" },
  "ISB": { cca2: "PK", region: "Asia Pacific", city: "Islamabad" },
  "KHI": { cca2: "PK", region: "Asia Pacific", city: "Karachi" },
  "LHE": { cca2: "PK", region: "Asia Pacific", city: "Lahore" },
  "ZDM": { cca2: "PS", region: "Middle East", city: "Ramallah" },
  "PTY": { cca2: "PA", region: "South America", city: "Panama City" },
  "ASU": { cca2: "PY", region: "South America", city: "Asunción" },
  "LIM": { cca2: "PE", region: "South America", city: "Lima" },
  "CGY": { cca2: "PH", region: "Asia Pacific", city: "Cagayan de Oro" },
  "CEB": { cca2: "PH", region: "Asia Pacific", city: "Cebu" },
  "MNL": { cca2: "PH", region: "Asia Pacific", city: "Manila" },
  "CRK": { cca2: "PH", region: "Asia Pacific", city: "Tarlac City" },
  "WAW": { cca2: "PL", region: "Europe", city: "Warsaw" },
  "WRO": { cca2: "PL", region: "Europe", city: "Wroclaw" },
  "LIS": { cca2: "PT", region: "Europe", city: "Lisbon" },
  "SJU": { cca2: "PR", region: "North America", city: "San Juan" },
  "DOH": { cca2: "QA", region: "Middle East", city: "Doha" },
  "RUN": { cca2: "RE", region: "Africa", city: "Saint-Denis" },
  "OTP": { cca2: "RO", region: "Europe", city: "Bucharest" },
  "KJA": { cca2: "RU", region: "Asia Pacific", city: "Krasnoyarsk" },
  "DME": { cca2: "RU", region: "Europe", city: "Moscow" },
  "LED": { cca2: "RU", region: "Europe", city: "Saint Petersburg" },
  "KGL": { cca2: "RW", region: "Africa", city: "Kigali" },
  "DMM": { cca2: "SA", region: "Middle East", city: "Dammam" },
  "JED": { cca2: "SA", region: "Middle East", city: "Jeddah" },
  "RUH": { cca2: "SA", region: "Middle East", city: "Riyadh" },
  "DKR": { cca2: "SN", region: "Africa", city: "Dakar" },
  "BEG": { cca2: "RS", region: "Europe", city: "Belgrade" },
  "SIN": { cca2: "SG", region: "Asia Pacific", city: "Singapore" },
  "BTS": { cca2: "SK", region: "Europe", city: "Bratislava" },
  "CPT": { cca2: "ZA", region: "Africa", city: "Cape Town" },
  "DUR": { cca2: "ZA", region: "Africa", city: "Durban" },
  "JNB": { cca2: "ZA", region: "Africa", city: "Johannesburg" },
  "BCN": { cca2: "ES", region: "Europe", city: "Barcelona" },
  "MAD": { cca2: "ES", region: "Europe", city: "Madrid" },
  "CMB": { cca2: "LK", region: "Asia Pacific", city: "Colombo" },
  "PBM": { cca2: "SR", region: "South America", city: "Paramaribo" },
  "GOT": { cca2: "SE", region: "Europe", city: "Gothenburg" },
  "ARN": { cca2: "SE", region: "Europe", city: "Stockholm" },
  "GVA": { cca2: "CH", region: "Europe", city: "Geneva" },
  "ZRH": { cca2: "CH", region: "Europe", city: "Zurich" },
  "KHH": { cca2: "TW", region: "Asia Pacific", city: "Kaohsiung City" },
  "TPE": { cca2: "TW", region: "Asia Pacific", city: "Taipei" },
  "DAR": { cca2: "TZ", region: "Africa", city: "Dar es Salaam" },
  "BKK": { cca2: "TH", region: "Asia Pacific", city: "Bangkok" },
  "CNX": { cca2: "TH", region: "Asia Pacific", city: "Chiang Mai" },
  "URT": { cca2: "TH", region: "Asia Pacific", city: "Surat Thani" },
  "POS": { cca2: "TT", region: "South America", city: "Port of Spain" },
  "TUN": { cca2: "TN", region: "Africa", city: "Tunis" },
  "IST": { cca2: "TR", region: "Europe", city: "Istanbul" },
  "ADB": { cca2: "TR", region: "Europe", city: "Izmir" },
  "EBB": { cca2: "UG", region: "Africa", city: "Kampala" },
  "KBP": { cca2: "UA", region: "Europe", city: "Kyiv" },
  "DXB": { cca2: "AE", region: "Middle East", city: "Dubai" },
  "LHR": { cca2: "GB", region: "Europe", city: "London" },
  "MAN": { cca2: "GB", region: "Europe", city: "Manchester" },
  "ANC": { cca2: "US", region: "North America", city: "Anchorage" },
  "PHX": { cca2: "US", region: "North America", city: "Phoenix" },
  "LAX": { cca2: "US", region: "North America", city: "Los Angeles" },
  "SMF": { cca2: "US", region: "North America", city: "Sacramento" },
  "SAN": { cca2: "US", region: "North America", city: "San Diego" },
  "SFO": { cca2: "US", region: "North America", city: "San Francisco" },
  "SJC": { cca2: "US", region: "North America", city: "San Jose" },
  "DEN": { cca2: "US", region: "North America", city: "Denver" },
  "JAX": { cca2: "US", region: "North America", city: "Jacksonville" },
  "MIA": { cca2: "US", region: "North America", city: "Miami" },
  "TLH": { cca2: "US", region: "North America", city: "Tallahassee" },
  "TPA": { cca2: "US", region: "North America", city: "Tampa" },
  "ATL": { cca2: "US", region: "North America", city: "Atlanta" },
  "HNL": { cca2: "US", region: "North America", city: "Honolulu" },
  "ORD": { cca2: "US", region: "North America", city: "Chicago" },
  "IND": { cca2: "US", region: "North America", city: "Indianapolis" },
  "BGR": { cca2: "US", region: "North America", city: "Bangor" },
  "BOS": { cca2: "US", region: "North America", city: "Boston" },
  "DTW": { cca2: "US", region: "North America", city: "Detroit" },
  "MSP": { cca2: "US", region: "North America", city: "Minneapolis" },
  "MCI": { cca2: "US", region: "North America", city: "Kansas City" },
  "STL": { cca2: "US", region: "North America", city: "St. Louis" },
  "OMA": { cca2: "US", region: "North America", city: "Omaha" },
  "LAS": { cca2: "US", region: "North America", city: "Las Vegas" },
  "EWR": { cca2: "US", region: "North America", city: "Newark" },
  "ABQ": { cca2: "US", region: "North America", city: "Albuquerque" },
  "BUF": { cca2: "US", region: "North America", city: "Buffalo" },
  "CLT": { cca2: "US", region: "North America", city: "Charlotte" },
  "RDU": { cca2: "US", region: "North America", city: "Durham" },
  "CLE": { cca2: "US", region: "North America", city: "Cleveland" },
  "CMH": { cca2: "US", region: "North America", city: "Columbus" },
  "OKC": { cca2: "US", region: "North America", city: "Oklahoma City" },
  "PDX": { cca2: "US", region: "North America", city: "Portland" },
  "PHL": { cca2: "US", region: "North America", city: "Philadelphia" },
  "PIT": { cca2: "US", region: "North America", city: "Pittsburgh" },
  "FSD": { cca2: "US", region: "North America", city: "Sioux Falls" },
  "MEM": { cca2: "US", region: "North America", city: "Memphis" },
  "BNA": { cca2: "US", region: "North America", city: "Nashville" },
  "AUS": { cca2: "US", region: "North America", city: "Austin" },
  "DFW": { cca2: "US", region: "North America", city: "Dallas" },
  "IAH": { cca2: "US", region: "North America", city: "Houston" },
  "SAT": { cca2: "US", region: "North America", city: "San Antonio" },
  "SLC": { cca2: "US", region: "North America", city: "Salt Lake City" },
  "IAD": { cca2: "US", region: "North America", city: "Ashburn" },
  "ORF": { cca2: "US", region: "North America", city: "Norfolk" },
  "RIC": { cca2: "US", region: "North America", city: "Richmond" },
  "SEA": { cca2: "US", region: "North America", city: "Seattle" },
  "DAD": { cca2: "VN", region: "Asia Pacific", city: "Da Nang" },
  "HAN": { cca2: "VN", region: "Asia Pacific", city: "Hanoi" },
  "SGN": { cca2: "VN", region: "Asia Pacific", city: "Ho Chi Minh City" },
  "LUN": { cca2: "ZM", region: "Africa", city: "Lusaka" },
  "HRE": { cca2: "ZW", region: "Africa", city: "Harare" }
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
