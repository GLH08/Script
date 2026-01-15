/***
 * Surge 流媒体 & AI 服务检测脚本
 * 2026 美化版 - 修复排版与旗帜显示
 * 
 * 功能：
 * 1. 自动生成任意国家旗帜 Emoji
 * 2. 修复面板换行问题
 * 3. 增强 YouTube/Netflix 地区提取稳定性
 */

// ========== 配置区域 ==========
const BASE_URL_NF = 'https://www.netflix.com/title/';
const BASE_URL_YTB = "https://www.youtube.com/premium";
const BASE_URL_DISNEY = 'https://www.disneyplus.com';
const BASE_URL_GPT = 'https://chat.openai.com/';
const BASE_URL_GPT_TRACE = 'https://chat.openai.com/cdn-cgi/trace';
const BASE_URL_TIKTOK = 'https://www.tiktok.com/';
const BASE_URL_CLAUDE = 'https://claude.ai/login';
const BASE_URL_GEMINI = 'https://gemini.google.com';
const BASE_URL_COPILOT = 'https://copilot.microsoft.com/';
const BASE_URL_META = 'https://www.meta.ai/';
const BASE_URL_IP_API = 'https://api.ip.sb/geoip';

const FILM_ID = 81280792;
const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

// 模块参数获取
const TARGET_POLICY = $argument || "DIRECT";

// 结果容器
let result = {
  "ip": "检测中...",
  "loc": "", // IP地区
  "YouTube": "⌛️",
  "Netflix": "⌛️",
  "Disney": "⌛️",
  "TikTok": "⌛️",
  "ChatGPT": "⌛️",
  "Claude": "⌛️",
  "Gemini": "⌛️",
  "Copilot": "⌛️",
  "MetaAI": "⌛️"
};

// ========== 核心工具函数 ==========

/**
 * 自动将国家代码转换为 Emoji 旗帜
 * 算法：将字母转为 Unicode 区域指示符号
 */
function getFlag(code) {
  if (!code || code === 'null' || code === 'undefined') return "🏳️";
  if (code.toUpperCase() === 'GLOBAL') return "🌍";
  if (code.length !== 2) return `[${code}]`; // 非标准代码直接显示文字

  const offset = 127397;
  const flag = code.toUpperCase().replace(/./g, (char) =>
    String.fromCodePoint(char.charCodeAt(0) + offset)
  );
  return flag;
}

// 统一请求函数
function makeRequest(url, headers = {}, timeout = 5) {
  return new Promise((resolve, reject) => {
    let option = {
      url: url,
      headers: Object.assign({ 'User-Agent': UA }, headers),
      policy: TARGET_POLICY,
      timeout: timeout
    };
    
    $httpClient.get(option, function(error, response, data) {
      if (error) {
        reject(error);
      } else {
        resolve({ 
          status: response.status, 
          data: data, 
          headers: response.headers 
        });
      }
    });
  });
}

// ========== IP 信息 ==========
async function getIPInfo() {
  try {
    const { status, data } = await makeRequest(BASE_URL_IP_API, {}, 6);
    if (status === 200) {
      const info = JSON.parse(data);
      result["ip"] = info.ip || "IP未知";
      // 存储 IP 所在国家，用于后续兜底显示
      result["loc"] = info.country_code || "";
      if (result["loc"]) {
          result["ip"] += ` ${getFlag(result["loc"])}`;
      }
      if (info.organization) {
          result["ip"] += ` (${info.organization})`;
      }
    } else {
      result["ip"] = "IP获取失败";
    }
  } catch (e) {
    result["ip"] = "IP查询超时";
  }
}

// ========== 流媒体检测 ==========

// 1. TikTok
async function testTikTok() {
  try {
    const { status, data } = await makeRequest(BASE_URL_TIKTOK);
    if (status === 200) {
      let regionMatch = data.match(/"region":"([a-zA-Z]{2})"/i);
      if (regionMatch && regionMatch[1]) {
        result["TikTok"] = "✅ " + getFlag(regionMatch[1]);
      } else if (data.includes('region_restriction')) {
        result["TikTok"] = "🚫 风控";
      } else {
        result["TikTok"] = "✅ 未知";
      }
    } else {
      result["TikTok"] = "🚫 限制";
    }
  } catch (e) { result["TikTok"] = "🚦 超时"; }
}

// 2. YouTube
async function testYTB() {
  try {
    const { status, data } = await makeRequest(BASE_URL_YTB);
    if (status !== 200) {
      result["YouTube"] = "🚫 失败";
    } else if (data.indexOf('Premium is not available in your country') !== -1) {
      result["YouTube"] = "🚫 限制";
    } else {
      let region = '';
      let re = new RegExp('"GL":"(.*?)"', 'gm');
      let ret = re.exec(data);
      if (ret != null && ret.length === 2) {
        region = ret[1];
      } else if (data.indexOf('www.google.cn') !== -1) {
        region = 'CN';
      } else {
        // 兜底：如果正则没取到，尝试默认使用 IP 地区，或者标记为 US
        region = result["loc"] || "US";
      }
      result["YouTube"] = "✅ " + getFlag(region);
    }
  } catch (e) { result["YouTube"] = "🚦 超时"; }
}

// 3. Netflix
async function testNf(filmId) {
  try {
    const { status, headers, data } = await makeRequest(BASE_URL_NF + filmId);
    if (status === 404) {
      result["Netflix"] = "⚠️ 自制";
    } else if (status === 403) {
      result["Netflix"] = "🚫 限制";
    } else if (status === 200) {
      let region = '';
      try {
        let url = headers['X-Originating-URL'] || headers['x-originating-url'];
        if (url) region = url.split('/')[3].split('-')[0].replace('title', 'us');
      } catch (e) {}
      // 如果获取不到，默认给个 US 或者 IP 地区
      if (!region) region = result["loc"] || "US"; 
      result["Netflix"] = "✅ " + getFlag(region);
    } else {
      result["Netflix"] = "🚫 异常";
    }
  } catch (e) { result["Netflix"] = "🚦 超时"; }
}

// 4. Disney+
async function testDisneyPlus() {
  try {
    const { status, data } = await makeRequest(BASE_URL_DISNEY);
    if (status === 200 && data.indexOf('not available in your region') === -1) {
      let match = data.match(/Region: ([A-Za-z]{2})/);
      let region = match ? match[1] : "Global";
      result["Disney"] = "✅ " + getFlag(region);
    } else {
      result["Disney"] = "🚫 限制";
    }
  } catch (e) { result["Disney"] = "🚦 超时"; }
}

// ========== AI 检测 ==========

// 5. ChatGPT
async function testChatGPT() {
  try {
    const { status } = await makeRequest(BASE_URL_GPT, {}, 6);
    if (status === 403) {
      result["ChatGPT"] = "🚫 限制";
    } else {
      try {
        const { status: ts, data: td } = await makeRequest(BASE_URL_GPT_TRACE, {}, 5);
        if (ts === 200 && td.includes("loc=")) {
          let region = td.split("loc=")[1].split("\n")[0];
          result["ChatGPT"] = "✅ " + getFlag(region);
        } else {
          result["ChatGPT"] = "✅ 通用";
        }
      } catch (e) { result["ChatGPT"] = "✅ 通用"; }
    }
  } catch (e) { result["ChatGPT"] = "🚦 超时"; }
}

async function testClaude() {
  try {
    const { status } = await makeRequest(BASE_URL_CLAUDE);
    result["Claude"] = (status !== 403) ? "✅ 支持" : "🚫 限制";
  } catch (e) { result["Claude"] = "🚦 超时"; }
}

async function testGemini() {
  try {
    const { status } = await makeRequest(BASE_URL_GEMINI);
    result["Gemini"] = (status === 200 || status === 302) ? "✅ 支持" : "🚫 限制";
  } catch (e) { result["Gemini"] = "🚦 超时"; }
}

async function testCopilot() {
  try {
    const { status } = await makeRequest(BASE_URL_COPILOT);
    result["Copilot"] = (status === 200) ? "✅ 支持" : "🚫 限制";
  } catch (e) { result["Copilot"] = "🚦 超时"; }
}

async function testMetaAI() {
  try {
    const { status, data } = await makeRequest(BASE_URL_META);
    if (status === 200 && data.indexOf("not yet available") === -1) {
       result["MetaAI"] = "✅ 支持";
    } else if (status === 302) {
       result["MetaAI"] = "✅ 登录";
    } else {
       result["MetaAI"] = "🚫 限制";
    }
  } catch (e) { result["MetaAI"] = "🚦 超时"; }
}

// ========== 主程序 ==========
;(async () => {
  // 1. 获取IP
  await getIPInfo();
  
  // 2. 并行检测
  await Promise.allSettled([
    testDisneyPlus(),
    testNf(FILM_ID),
    testYTB(),
    testTikTok(),
    testChatGPT(),
    testClaude(),
    testGemini(),
    testCopilot(),
    testMetaAI()
  ]);

  // 3. 构造美化后的面板内容
  // 使用简短的分隔线，或者直接用空行分隔
  const separator = "──────────────"; 
  
  let content = 
    `📡 ${result["ip"]}\n` +
    `${separator}\n` +
    `YouTube: ${result["YouTube"]}   Disney+: ${result["Disney"]}\n` +
    `Netflix: ${result["Netflix"]}   TikTok:  ${result["TikTok"]}\n` +
    `${separator}\n` +
    `ChatGPT: ${result["ChatGPT"]}   Claude: ${result["Claude"]}\n` +
    `Gemini:  ${result["Gemini"]}   Copilot: ${result["Copilot"]}\n` +
    `Meta AI: ${result["MetaAI"]}\n` +
    `${separator}\n` +
    `🔧 策略: ${TARGET_POLICY}`;

  $done({
    title: '🚀 流媒体 & AI 检测',
    content: content,
    icon: 'play.tv.fill',
    'icon-color': '#FF2D55'
  });
})();
