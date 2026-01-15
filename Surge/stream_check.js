/***
 * Surge 流媒体 & AI 服务检测脚本
 * V5.1 YouTube 修复版
 * 
 * 核心修复：
 * 1. YouTube: 检测链接从 /premium 改为 首页 (www.youtube.com)
 *    解决 /premium 页面包含硬编码 "US" 导致英国/欧洲节点误判为美国的问题。
 * 2. 保持 V5 的智能 IP 锚定和双重验证逻辑。
 */

// ========== 配置区域 ==========
const BASE_URL_NF = 'https://www.netflix.com/title/';
// ⚠️ 变动：改为首页，准确度更高
const BASE_URL_YTB = "https://www.youtube.com/";
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
  if (!code || code === 'null' || code === 'undefined' || code === '') return "未知";
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
      result.loc = info.country_code || "Unknown";
      let org = info.organization || "";
      if (org.length > 20) org = org.substring(0, 20) + "...";
      result.ip = `${info.ip} ${getRegionStr(result.loc)} (${org})`;
    } catch (e) { 
      result.ip = "IP 解析失败"; 
      result.loc = "Unknown";
    }
  } else { 
    result.ip = "IP 获取失败"; 
    result.loc = "Unknown";
  }
}

// 🔥 YouTube 逻辑修复
async function checkYouTube() {
  const { status, data } = await makeRequest(BASE_URL_YTB);
  if (status !== 200) { result.ytb = "检测失败 🚫"; return; }
  
  // 首页如果包含这个关键词，通常是 Region 限制
  if (data && data.includes('www.google.cn')) {
    result.ytb = "未支持 🚫";
    return;
  }

  let region = '';
  if (data) {
      // 核心改动：匹配 ytcfg.set 中的 GL，这是最准确的
      // 格式通常为: "GL":"GB"
      let match = /['"]GL['"]\s*:\s*['"]([A-Z]{2})['"]/.exec(data);
      if (match) {
          region = match[1];
      } else {
          // 备用正则
          let match2 = /"countryCode":"([A-Z]{2})"/.exec(data);
          if (match2) region = match2[1];
      }
  }
  
  // 依然保留 IP 兜底，防止正则完全失效
  if (!region || region === '') region = result.loc;
  
  result.ytb = `已解锁 ➟ ${getRegionStr(region)}`;
}

async function checkNetflix() {
  const { status, headers } = await makeRequest(BASE_URL_NF + FILM_ID);
  
  if (status === 200) {
    let region = '';
    try {
      let url = headers['X-Originating-URL'] || headers['x-originating-url'];
      if (url) {
        let parts = url.split('/');
        let possibleRegion = parts[3].split('-')[0];
        if (possibleRegion !== 'title') region = possibleRegion;
      }
    } catch (e) {}
    if (!region) region = result.loc;
    result.nf = `完整解锁 ➟ ${getRegionStr(region)}`;
  } else if (status === 403) {
    result.nf = "未支持 🚫";
  } else if (status === 404) {
    const { status: status2 } = await makeRequest(BASE_URL_NF + ORIGINAL_ID);
    if (status2 === 200) {
      result.nf = `仅自制剧 ➟ ${getRegionStr(result.loc)}`;
    } else {
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
