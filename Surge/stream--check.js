/***
 * Surge 流媒体 & AI 服务检测脚本
 * V4.1 双重验证精准版
 * 
 * 更新日志：
 * 1. Netflix 升级为双重验证：
 *    - 先测非自制剧 -> 404? -> 再测自制剧
 *    - 确保“仅自制剧”判断 100% 准确，排除假 404
 * 2. 保持 V4.0 的整齐排版
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

// ID 1: 非自制剧 (用于检测完整解锁)
const FILM_ID = 81280792;
// ID 2: 自制剧 (用于检测是否彻底封锁)
const ORIGINAL_ID = 80018499; 

const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const TARGET_POLICY = $argument || "DIRECT";

let result = {
  ip: "检测中...", loc: "",
  ytb: "检测中...", nf: "检测中...", disney: "检测中...", tiktok: "检测中...",
  chatgpt: "检测中...", claude: "检测中...", gemini: "检测中...", copilot: "检测中...", meta: "检测中..."
};

// ========== 工具函数 ==========

function getRegionStr(code) {
  if (!code || code === 'null' || code === 'undefined') return "未知";
  code = code.toUpperCase();
  if (code === 'GLOBAL') return "Global";
  let flag = "🏳️";
  if (/^[A-Z]{2}$/.test(code)) {
    const offset = 127397;
    try {
      flag = code.replace(/./g, (char) => String.fromCodePoint(char.charCodeAt(0) + offset));
    } catch (e) {}
  }
  return `${flag} ${code}`;
}

function makeRequest(url, headers = {}, timeout = 6) {
  return new Promise((resolve) => {
    let option = {
      url: url,
      headers: Object.assign({ 'User-Agent': UA }, headers),
      policy: TARGET_POLICY,
      timeout: timeout
    };
    $httpClient.get(option, (error, response, data) => {
      if (error) resolve({ status: 0, data: null });
      else resolve({ status: response.status, data: data, headers: response.headers });
    });
  });
}

// ========== 核心逻辑 ==========

async function checkIP() {
  const { status, data } = await makeRequest(BASE_URL_IP_API);
  if (status === 200 && data) {
    try {
      const info = JSON.parse(data);
      result.loc = info.country_code || "US";
      let org = info.organization || "";
      if (org.length > 20) org = org.substring(0, 20) + "...";
      result.ip = `${info.ip} ${getRegionStr(result.loc)} (${org})`;
    } catch (e) { result.ip = "IP 解析失败"; }
  } else { result.ip = "IP 获取失败"; }
}

async function checkYouTube() {
  const { status, data } = await makeRequest(BASE_URL_YTB);
  if (status !== 200) { result.ytb = "检测失败 🚫"; return; }
  if (data && data.includes('Premium is not available')) {
    result.ytb = "未支持 🚫";
  } else {
    let region = '';
    if (data) {
        let match = /"GL":"([A-Z]{2})"/.exec(data);
        if (match) region = match[1];
        else if (data.includes('www.google.cn')) region = 'CN';
    }
    if (!region) region = result.loc;
    result.ytb = `已解锁 ➟ ${getRegionStr(region)}`;
  }
}

// 🔥 Netflix 双重验证逻辑
async function checkNetflix() {
  // 第一次检测：非自制剧
  const { status, headers } = await makeRequest(BASE_URL_NF + FILM_ID);
  
  if (status === 200) {
    let region = 'US';
    try {
      let url = headers['X-Originating-URL'] || headers['x-originating-url'];
      if (url) region = url.split('/')[3].split('-')[0].replace('title', 'us');
    } catch (e) {}
    result.nf = `完整解锁 ➟ ${getRegionStr(region)}`;
  } else if (status === 403) {
    result.nf = "未支持 🚫";
  } else if (status === 404) {
    // ⚠️ 关键：第一次 404，进行第二次检测（自制剧）
    const { status: status2, headers: headers2 } = await makeRequest(BASE_URL_NF + ORIGINAL_ID);
    if (status2 === 200) {
      let region = 'US';
      try {
        let url = headers2['X-Originating-URL'] || headers2['x-originating-url'];
        if (url) region = url.split('/')[3].split('-')[0].replace('title', 'us');
      } catch (e) {}
      result.nf = `仅自制剧 ➟ ${getRegionStr(region)}`;
    } else {
      // 自制剧也看不了，那就是真挂了
      result.nf = "未支持 🚫";
    }
  } else {
    result.nf = "检测失败 🚫";
  }
}

async function checkDisney() {
  const { status, data } = await makeRequest(BASE_URL_DISNEY);
  if (status === 200 && data && !data.includes('not available in your region')) {
    let match = data.match(/Region: ([A-Za-z]{2})/);
    let region = match ? match[1] : "Global";
    result.disney = `已解锁 ➟ ${getRegionStr(region)}`;
  } else { result.disney = "未支持 🚫"; }
}

async function checkTikTok() {
  const { status, data } = await makeRequest(BASE_URL_TIKTOK);
  if (status === 200 && data) {
    let match = data.match(/"region":"([a-zA-Z]{2})"/i);
    if (match) result.tiktok = `已解锁 ➟ ${getRegionStr(match[1])}`;
    else if (data.includes('region_restriction')) result.tiktok = "未支持 (风控) 🚫";
    else result.tiktok = `已解锁 ➟ ${getRegionStr(result.loc)}`;
  } else { result.tiktok = "未支持 🚫"; }
}

async function checkChatGPT() {
  const { status } = await makeRequest(BASE_URL_GPT, {}, 5);
  if (status === 403) { result.chatgpt = "未支持 🚫"; } 
  else {
    const { status: ts, data: td } = await makeRequest(BASE_URL_GPT_TRACE, {}, 4);
    if (ts === 200 && td && td.includes("loc=")) {
        let region = td.split("loc=")[1].split("\n")[0];
        result.chatgpt = `已支持 ➟ ${getRegionStr(region)}`;
    } else { result.chatgpt = "已支持 (通用) 🎉"; }
  }
}

async function checkSimple(url, key) {
  const { status } = await makeRequest(url);
  // Claude 403是限制; Gemini 302/200是支持; Copilot 200是支持
  if (key === 'claude') result[key] = (status !== 403) ? "已支持 🎉" : "未支持 🚫";
  else if (key === 'gemini') result[key] = (status === 200 || status === 302) ? "已支持 🎉" : "未支持 🚫";
  else if (key === 'copilot') result[key] = (status === 200) ? "已支持 🎉" : "未支持 🚫";
}

async function checkMeta() {
  const { status, data } = await makeRequest(BASE_URL_META);
  if (status === 200 && data && !data.includes("not yet available")) result.meta = "已支持 🎉";
  else if (status === 302) result.meta = "已支持 (需登录) 🎉";
  else result.meta = "未支持 🚫";
}

// Main
;(async () => {
  await checkIP();
  await Promise.allSettled([
    checkYouTube(), checkNetflix(), checkDisney(), checkTikTok(),
    checkChatGPT(), checkSimple(BASE_URL_CLAUDE, 'claude'),
    checkSimple(BASE_URL_GEMINI, 'gemini'), checkSimple(BASE_URL_COPILOT, 'copilot'),
    checkMeta()
  ]);

  let content = 
    `📡 ${result.ip}\n` +
    `──────────────\n` +
    `YouTube: ${result.ytb}\n` +
    `Netflix: ${result.nf}\n` +
    `Disney+: ${result.disney}\n` +
    `TikTok:  ${result.tiktok}\n` +
    `──────────────\n` +
    `ChatGPT: ${result.chatgpt}\n` +
    `Claude:  ${result.claude}\n` +
    `Gemini:  ${result.gemini}\n` +
    `Copilot: ${result.copilot}\n` +
    `Meta AI: ${result.meta}\n` +
    `──────────────\n` +
    `🔧 策略: ${TARGET_POLICY}`;

  $done({ title: '🚀 流媒体 & AI 检测', content: content, icon: 'play.tv.fill', 'icon-color': '#FF2D55' });
})();
