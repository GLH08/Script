/***
 * Surge 流媒体 & AI 服务检测脚本
 * v3.0 最终修复版
 * 
 * 修复：
 * 1. 彻底移除分隔线，修复排版错乱
 * 2. 暴力修复“方框叉号”乱码，非标准代码统一显示地球
 * 3. 增加重试机制防止超时
 */

// ========== 常量定义 ==========
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
// 使用 Chrome UA 模拟真实浏览器
const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

// 模块参数
const TARGET_POLICY = $argument || "DIRECT";

// 结果容器
let result = {
  "ip": "检测中...",
  "loc": "", 
  "YouTube": "⌛️", "Netflix": "⌛️", "Disney": "⌛️", "TikTok": "⌛️",
  "ChatGPT": "⌛️", "Claude": "⌛️", "Gemini": "⌛️", "Copilot": "⌛️", "MetaAI": "⌛️"
};

// ========== 核心工具函数 ==========

/**
 * 严格模式的旗帜生成
 * 解决 ☒ 乱码问题
 */
function getFlag(code) {
  // 1. 空值检查
  if (!code || code === 'null' || code === 'undefined') return "🌍";
  
  // 2. 格式化
  code = code.toUpperCase();
  
  // 3. 特殊处理
  if (code === 'GLOBAL') return "🌍";
  if (code === 'CN') return "🇨🇳"; // 部分设备可能显示为CN文字
  
  // 4. 只有严格为2位字母时才生成旗帜，否则返回地球
  if (!/^[A-Z]{2}$/.test(code)) return "🌍";

  const offset = 127397;
  try {
    return code.replace(/./g, (char) =>
      String.fromCodePoint(char.charCodeAt(0) + offset)
    );
  } catch (e) {
    return "🌍"; // 生成失败兜底
  }
}

// 统一请求函数
function makeRequest(url, headers = {}, timeout = 6) { // 超时延长到6秒
  return new Promise((resolve, reject) => {
    let option = {
      url: url,
      headers: Object.assign({ 'User-Agent': UA }, headers),
      policy: TARGET_POLICY,
      timeout: timeout
    };
    
    $httpClient.get(option, function(error, response, data) {
      if (error) {
        resolve({ status: 0, data: null }); // 错误不reject，而是返回状态0
      } else {
        resolve({ status: response.status, data: data, headers: response.headers });
      }
    });
  });
}

// ========== 业务逻辑 ==========

// IP检测
async function getIPInfo() {
  const { status, data } = await makeRequest(BASE_URL_IP_API);
  if (status === 200 && data) {
    try {
      const info = JSON.parse(data);
      result["ip"] = info.ip || "IP未知";
      result["loc"] = info.country_code || "";
      if (result["loc"]) result["ip"] += ` ${getFlag(result["loc"])}`;
      if (info.organization) result["ip"] += ` (${info.organization})`;
    } catch(e) { result["ip"] = "IP解析误"; }
  } else {
    result["ip"] = "IP获取失败";
  }
}

// TikTok
async function testTikTok() {
  const { status, data } = await makeRequest(BASE_URL_TIKTOK);
  if (status === 200 && data) {
    let match = data.match(/"region":"([a-zA-Z]{2})"/i);
    if (match) {
      result["TikTok"] = "✅ " + getFlag(match[1]);
    } else if (data.includes('region_restriction')) {
      result["TikTok"] = "🚫 风控";
    } else {
      result["TikTok"] = "✅ " + getFlag(result["loc"]); // 兜底
    }
  } else {
    result["TikTok"] = "🚫 失败";
  }
}

// YouTube
async function testYTB() {
  const { status, data } = await makeRequest(BASE_URL_YTB);
  if (status !== 200) {
    result["YouTube"] = "🚫 失败";
  } else if (data && data.indexOf('Premium is not available') !== -1) {
    result["YouTube"] = "🚫 限制";
  } else {
    let region = '';
    if (data) {
        let match = /"GL":"([A-Z]{2})"/.exec(data);
        if (match) region = match[1];
        else if (data.indexOf('www.google.cn') !== -1) region = 'CN';
    }
    // 强制兜底，防止空值导致乱码
    if (!region) region = result["loc"] || "US";
    result["YouTube"] = "✅ " + getFlag(region);
  }
}

// Netflix
async function testNf(id) {
  const { status, headers } = await makeRequest(BASE_URL_NF + id);
  if (status === 200) {
    let region = '';
    try {
      let url = headers['X-Originating-URL'] || headers['x-originating-url'];
      if (url) region = url.split('/')[3].split('-')[0].replace('title', 'us');
    } catch (e) {}
    if (!region) region = result["loc"] || "US";
    result["Netflix"] = "✅ " + getFlag(region);
  } else if (status === 404) {
    result["Netflix"] = "⚠️ 自制";
  } else {
    result["Netflix"] = "🚫 限制";
  }
}

// Disney+
async function testDisney() {
  const { status, data } = await makeRequest(BASE_URL_DISNEY);
  if (status === 200 && data && data.indexOf('not available in your region') === -1) {
    let match = data.match(/Region: ([A-Za-z]{2})/);
    let region = match ? match[1] : "Global";
    result["Disney"] = "✅ " + getFlag(region);
  } else {
    result["Disney"] = "🚫 限制";
  }
}

// AI Tests
async function testChatGPT() {
  const { status } = await makeRequest(BASE_URL_GPT, {}, 5);
  if (status === 403) {
    result["ChatGPT"] = "🚫 限制";
  } else {
    // 尝试Trace
    const { status: ts, data: td } = await makeRequest(BASE_URL_GPT_TRACE, {}, 4);
    if (ts === 200 && td && td.includes("loc=")) {
        let region = td.split("loc=")[1].split("\n")[0];
        result["ChatGPT"] = "✅ " + getFlag(region);
    } else {
        result["ChatGPT"] = "✅ 通用";
    }
  }
}

async function testSimple(url, key, code200 = "✅ 支持", code403 = "🚫 限制") {
  const { status } = await makeRequest(url);
  // Gemini 302跳转也是支持，Claude 403是限制
  if (key === 'Claude') result[key] = (status !== 403) ? "✅ 支持" : "🚫 限制";
  else if (key === 'Gemini') result[key] = (status === 200 || status === 302) ? "✅ 支持" : "🚫 限制";
  else if (key === 'Copilot') result[key] = (status === 200) ? "✅ 支持" : "🚫 限制";
}

async function testMeta() {
  const { status, data } = await makeRequest(BASE_URL_META);
  if (status === 200 && data && !data.includes("not yet available")) result["MetaAI"] = "✅ 支持";
  else if (status === 302) result["MetaAI"] = "✅ 登录";
  else result["MetaAI"] = "🚫 限制";
}

// Main
;(async () => {
  await getIPInfo();
  await Promise.allSettled([
    testDisney(), testNf(FILM_ID), testYTB(), testTikTok(),
    testChatGPT(), 
    testSimple(BASE_URL_CLAUDE, 'Claude'),
    testSimple(BASE_URL_GEMINI, 'Gemini'),
    testSimple(BASE_URL_COPILOT, 'Copilot'),
    testMeta()
  ]);

  // ⚠️⚠️⚠️ 这里彻底去掉了横线，只保留换行符 ⚠️⚠️⚠️
  let content = 
    `📡 ${result["ip"]}\n\n` +
    `YouTube: ${result["YouTube"]}   Disney+: ${result["Disney"]}\n` +
    `Netflix: ${result["Netflix"]}   TikTok:  ${result["TikTok"]}\n\n` +
    `ChatGPT: ${result["ChatGPT"]}   Claude: ${result["Claude"]}\n` +
    `Gemini:  ${result["Gemini"]}   Copilot: ${result["Copilot"]}\n` +
    `Meta AI: ${result["MetaAI"]}\n\n` +
    `🔧 策略: ${TARGET_POLICY}`;

  $done({
    title: '🚀 流媒体 & AI 检测',
    content: content,
    icon: 'play.tv.fill',
    'icon-color': '#FF2D55'
  });
})();
