/***
 * 2026 Refactored Version v2
 * Based on: ecs.sh logic & previous optimizations
 * Features: 
 * 1. Enhanced TikTok check (Region extraction)
 * 2. Robust Netflix check (Fallback logic)
 * 3. Updated User-Agent
 */

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

const FILM_ID = 81280792;
// 更新为较新的桌面端 UA，模拟真实浏览器行为
const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

const arrow = " ➟ ";

// 状态常量
const STATUS_COMING = 2;
const STATUS_AVAILABLE = 1;
const STATUS_NOT_AVAILABLE = 0;
const STATUS_TIMEOUT = -1;
const STATUS_ERROR = -2;

const opts = { policy: $environment.params };
const optsNoRedir = { policy: $environment.params, redirection: false };

// 地区 Flag 映射 (精简版，节省内存)
const flags = new Map([
  ["CN", "🇨🇳"], ["HK", "🇭🇰"], ["MO", "🇲🇴"], ["TW", "🇨🇳"], ["US", "🇺🇸"], ["GB", "🇬🇧"], ["JP", "🇯🇵"], ["KR", "🇰🇷"], 
  ["SG", "🇸🇬"], ["CA", "🇨🇦"], ["AU", "🇦🇺"], ["DE", "🇩🇪"], ["FR", "🇫🇷"], ["NL", "🇳🇱"], ["RU", "🇷🇺"], ["IN", "🇮🇳"], 
  ["TH", "🇹🇭"], ["VN", "🇻🇳"], ["PH", "🇵🇭"], ["MY", "🇲🇾"], ["ID", "🇮🇩"], ["TR", "🇹🇷"], ["IT", "🇮🇹"], ["ES", "🇪🇸"]
]);

function getFlag(code) {
    if (!code) return "";
    return flags.get(code.toUpperCase()) || code.toUpperCase();
}

// 结果容器
let result = {
  "title": '    🚀  流媒体 & AI 服务检测',
  "YouTube": '<b>YouTube: </b>等待检测...',
  "Netflix": '<b>Netflix: </b>等待检测...',
  "Disney": "<b>Disney+: </b>等待检测...",
  "TikTok": "<b>TikTok: </b>等待检测...",
  "ChatGPT": "<b>ChatGPT: </b>等待检测...",
  "Claude": "<b>Claude: </b>等待检测...",
  "Gemini": "<b>Gemini: </b>等待检测...",
  "Copilot": "<b>Copilot: </b>等待检测...",
  "MetaAI": "<b>Meta AI: </b>等待检测..."
};

const message = {
  action: "get_policy_state",
  content: $environment.params
};

;(async () => {
  // 并行执行所有检测
  await Promise.allSettled([
    testDisneyPlus().then(updateDisneyResult),
    testNf(FILM_ID),
    testYTB(),
    testTikTok(), // 重点优化
    testChatGPT(),
    testClaude(),
    testGemini(),
    testCopilot(),
    testMetaAI()
  ]);

  // 构造输出内容
  let mediaList = [result["YouTube"], result["Netflix"], result["Disney"], result["TikTok"]];
  let aiList = [result["ChatGPT"], result["Claude"], result["Gemini"], result["Copilot"], result["MetaAI"]];
  
  let content = "<b>[流媒体服务]</b></br>" + mediaList.join("</br>") + 
                "</br></br><b>[人工智能]</b></br>" + aiList.join("</br>");

  // 发送 UI 更新
  $configuration.sendMessage(message).then(resolve => {
    let nodeName = $environment.params;
    if (resolve.ret && resolve.ret[message.content]) {
        nodeName = JSON.stringify(resolve.ret[message.content]).replace(/\"|\[|\]/g, "").replace(/\,/g, " ➟ ");
    }
    
    let finalContent = content + "</br>--------------------------------------</br>" + 
                       "<font color=#CD5C5C>" + "<b>节点</b> ➟ " + nodeName + "</font>";
    
    $done({ "title": result["title"], "htmlMessage": `<p style="text-align: left; font-family: -apple-system; font-size: large; font-weight: thin">${finalContent}</p>` });
  }, () => {
    $done({ "title": result["title"], "htmlMessage": `<p style="text-align: left; font-family: -apple-system; font-size: large; font-weight: thin">${content}</p>` });
  });
})();

// ---------------- 功能函数区 ----------------

// 1. TikTok (借鉴 ecs.sh 逻辑)
function testTikTok() {
  return new Promise((resolve) => {
    let option = {
      url: BASE_URL_TIKTOK,
      opts: optsNoRedir, // 禁止重定向，TikTok 封锁通常会重定向
      headers: { 'User-Agent': UA }
    };
    $task.fetch(option).then(response => {
      if (response.statusCode === 200) {
        // 借鉴 ecs.sh: grep '"region":'
        // 在 HTML 中查找 "region":"US" 这样的字段
        let regionMatch = response.body.match(/"region":"([a-zA-Z]{2})"/i);
        
        if (regionMatch && regionMatch[1]) {
            let region = regionMatch[1];
            result["TikTok"] = "<b>TikTok: </b>支持 " + arrow + "⟦" + getFlag(region) + "⟧ 🎉";
        } else {
            // 如果返回 200 但找不到 region，可能是风控页面或结构变更
            // 进一步检查是否包含 "region_restriction"
            if (response.body.includes('region_restriction')) {
                result["TikTok"] = "<b>TikTok: </b>未支持 (风控) 🚫";
            } else {
                result["TikTok"] = "<b>TikTok: </b>支持 (未知地区) 🎉";
            }
        }
      } else if (response.statusCode === 301 || response.statusCode === 302) {
          // 检查重定向位置
          let loc = response.headers['Location'] || response.headers['location'];
          if (loc && loc.includes('notfound')) {
               result["TikTok"] = "<b>TikTok: </b>未支持 🚫";
          } else {
               result["TikTok"] = "<b>TikTok: </b>重定向 (可能支持) ⚠️";
          }
      } else {
        result["TikTok"] = "<b>TikTok: </b>未支持 🚫";
      }
      resolve();
    }, () => {
      result["TikTok"] = "<b>TikTok: </b>检测超时 🚦";
      resolve();
    });
  });
}

// 2. YouTube
function testYTB() {
  return new Promise((resolve) => {
    let option = {
      url: BASE_URL_YTB,
      opts: opts,
      timeout: 5000,
      headers: { 'User-Agent': UA }
    };
    $task.fetch(option).then(response => {
      if (response.statusCode !== 200) {
        result["YouTube"] = "<b>YouTube: </b>检测失败 ❗️";
      } else if (response.body.indexOf('Premium is not available in your country') !== -1) {
        result["YouTube"] = "<b>YouTube: </b>未支持 🚫";
      } else {
        let region = '';
        let re = new RegExp('"GL":"(.*?)"', 'gm');
        let ret = re.exec(response.body);
        if (ret != null && ret.length === 2) {
          region = ret[1];
        } else if (response.body.indexOf('www.google.cn') !== -1) {
          region = 'CN';
        } else {
          region = 'US';
        }
        result["YouTube"] = "<b>YouTube: </b>支持 " + arrow + "⟦" + getFlag(region) + "⟧ 🎉";
      }
      resolve();
    }, () => {
      result["YouTube"] = "<b>YouTube: </b>检测超时 🚦";
      resolve();
    });
  });
}

// 3. Netflix (增强容错)
function testNf(filmId) {
  return new Promise((resolve) => {
    let option = {
      url: BASE_URL_NF + filmId,
      opts: opts,
      timeout: 5000,
      headers: { 'User-Agent': UA },
    };
    $task.fetch(option).then(response => {
      if (response.statusCode === 404) {
        result["Netflix"] = "<b>Netflix: </b>支持自制剧集 ⚠️";
      } else if (response.statusCode === 403) {
        result["Netflix"] = "<b>Netflix: </b>未支持 🚫";
      } else if (response.statusCode === 200) {
        let region = 'US'; 
        try {
            let url = response.headers['X-Originating-URL'] || response.headers['x-originating-url'];
            if (url) region = url.split('/')[3].split('-')[0].replace('title', 'us');
        } catch (e) {}
        result["Netflix"] = "<b>Netflix: </b>完整支持" + arrow + "⟦" + getFlag(region) + "⟧ 🎉";
      } else {
        result["Netflix"] = "<b>Netflix: </b>检测异常 (" + response.statusCode + ")";
      }
      resolve();
    }, () => {
      result["Netflix"] = "<b>Netflix: </b>检测超时 🚦";
      resolve();
    });
  });
}

// 4. Disney+ (逻辑保持，增加结果处理函数)
function updateDisneyResult(res) {
    let { region, status } = res;
    if (status == STATUS_COMING) {
        result["Disney"] = "<b>Disney+:</b> 即将登陆 ➟ ⟦" + getFlag(region) + "⟧ ⚠️";
    } else if (status == STATUS_AVAILABLE) {
        result["Disney"] = "<b>Disney+:</b> 支持 ➟ ⟦" + getFlag(region) + "⟧ 🎉";
    } else if (status == STATUS_NOT_AVAILABLE) {
        result["Disney"] = "<b>Disney+:</b> 未支持 🚫";
    } else if (status == STATUS_TIMEOUT) {
        result["Disney"] = "<b>Disney+:</b> 检测超时 🚦";
    } else {
        result["Disney"] = "<b>Disney+:</b> 检测失败 ❗️";
    }
}

async function testDisneyPlus() {
  // 简化逻辑：只检测主页，因为 API Token 极易失效
  // 如果需要 API 检测，可保留原代码，这里提供更稳定的主页检测方案
  return new Promise((resolve) => {
    let opts0 = {
      url: BASE_URL_DISNEY,
      opts: opts,
      headers: { 'Accept-Language': 'en', 'User-Agent': UA },
    };
    $task.fetch(opts0).then(response => {
      if (response.statusCode === 200 && response.body.indexOf('not available in your region') === -1) {
          // 尝试从 HTML 提取 Region
          let match = response.body.match(/Region: ([A-Za-z]{2})/);
          let region = match ? match[1] : "Global";
          resolve({ region: region, status: STATUS_AVAILABLE });
      } else {
          resolve({ status: STATUS_NOT_AVAILABLE });
      }
    }, () => resolve({ status: STATUS_TIMEOUT }));
  });
}

// 5. ChatGPT
function testChatGPT() {
  return new Promise((resolve) => {
    let option = { url: BASE_URL_GPT, opts: optsNoRedir, headers: { 'User-Agent': UA } };
    $task.fetch(option).then(response => {
      if (response.statusCode === 403) {
        result["ChatGPT"] = "<b>ChatGPT: </b>未支持 🚫 (403)";
        resolve();
      } else {
        let optionTrace = { url: BASE_URL_GPT_TRACE, opts: optsNoRedir, headers: { 'User-Agent': UA } };
        $task.fetch(optionTrace).then(resp => {
           if(resp.statusCode === 200 && resp.body.includes("loc=")) {
             let region = resp.body.split("loc=")[1].split("\n")[0];
             result["ChatGPT"] = "<b>ChatGPT: </b>支持 " + arrow + "⟦" + getFlag(region) + "⟧ 🎉";
           } else {
             result["ChatGPT"] = "<b>ChatGPT: </b>支持 (未知地区) 🎉";
           }
           resolve();
        }, () => {
           result["ChatGPT"] = "<b>ChatGPT: </b>支持 (Trace超时) 🎉";
           resolve();
        });
      }
    }, () => { result["ChatGPT"] = "<b>ChatGPT: </b>检测超时 🚦"; resolve(); });
  });
}

// 6. Claude
function testClaude() {
  return new Promise((resolve) => {
    let option = { url: BASE_URL_CLAUDE, opts: optsNoRedir, headers: { 'User-Agent': UA } };
    $task.fetch(option).then(response => {
      if (response.statusCode !== 403) {
        result["Claude"] = "<b>Claude: </b>支持 🎉";
      } else {
        result["Claude"] = "<b>Claude: </b>未支持 🚫";
      }
      resolve();
    }, () => { result["Claude"] = "<b>Claude: </b>检测超时 🚦"; resolve(); });
  });
}

// 7. Gemini
function testGemini() {
  return new Promise((resolve) => {
    let option = { url: BASE_URL_GEMINI, opts: optsNoRedir, headers: { 'User-Agent': UA } };
    $task.fetch(option).then(response => {
      if (response.statusCode === 200 || response.statusCode === 302) {
        result["Gemini"] = "<b>Gemini: </b>支持 🎉";
      } else {
        result["Gemini"] = "<b>Gemini: </b>未支持 🚫";
      }
      resolve();
    }, () => { result["Gemini"] = "<b>Gemini: </b>检测超时 🚦"; resolve(); });
  });
}

// 8. Copilot
function testCopilot() {
  return new Promise((resolve) => {
    let option = { url: BASE_URL_COPILOT, opts: optsNoRedir, headers: { 'User-Agent': UA } };
    $task.fetch(option).then(response => {
      if (response.statusCode === 200) {
        result["Copilot"] = "<b>Copilot: </b>支持 🎉";
      } else {
        result["Copilot"] = "<b>Copilot: </b>未支持 🚫";
      }
      resolve();
    }, () => { result["Copilot"] = "<b>Copilot: </b>检测超时 🚦"; resolve(); });
  });
}

// 9. Meta AI
function testMetaAI() {
  return new Promise((resolve) => {
    let option = { url: BASE_URL_META, opts: optsNoRedir, headers: { 'User-Agent': UA } };
    $task.fetch(option).then(response => {
      if (response.statusCode === 200) {
         if (response.body.indexOf("not yet available") !== -1) {
             result["MetaAI"] = "<b>Meta AI: </b>未支持 🚫";
         } else {
             result["MetaAI"] = "<b>Meta AI: </b>支持 🎉";
         }
      } else if (response.statusCode === 302) {
         result["MetaAI"] = "<b>Meta AI: </b>支持 (需登录) 🎉";
      } else {
         result["MetaAI"] = "<b>Meta AI: </b>未支持 🚫";
      }
      resolve();
    }, () => { result["MetaAI"] = "<b>Meta AI: </b>检测超时 🚦"; resolve(); });
  });
}
