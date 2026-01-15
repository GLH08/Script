/***
 * Surge 流媒体 & AI 服务检测脚本
 * 2026 完整版 - 支持出口IP显示
 * 适配 Surge iOS & Mac
 * 
 * 功能：
 * 1. Netflix、YouTube、Disney+、TikTok 解锁检测
 * 2. ChatGPT、Claude、Gemini、Copilot、Meta AI 支持检测
 * 3. 显示当前出口IP地址
 * 4. 支持通过模块参数指定测试策略/节点
 */

// ========== 常量配置 ==========
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
const BASE_URL_IP_API = 'https://api.ip.sb/geoip';  // IP 查询 API

const FILM_ID = 81280792;
const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const arrow = " ➟ ";

// 状态常量
const STATUS_COMING = 2;
const STATUS_AVAILABLE = 1;
const STATUS_NOT_AVAILABLE = 0;
const STATUS_TIMEOUT = -1;
const STATUS_ERROR = -2;

// 🔥 从模块参数获取策略名称
const TARGET_POLICY = $argument || "DIRECT";

// 地区 Flag 映射
const flags = new Map([
  ["CN", "🇨🇳"], ["HK", "🇭🇰"], ["MO", "🇲🇴"], ["TW", "🇹🇼"], ["US", "🇺🇸"], 
  ["GB", "🇬🇧"], ["JP", "🇯🇵"], ["KR", "🇰🇷"], ["SG", "🇸🇬"], ["CA", "🇨🇦"], 
  ["AU", "🇦🇺"], ["DE", "🇩🇪"], ["FR", "🇫🇷"], ["NL", "🇳🇱"], ["RU", "🇷🇺"], 
  ["IN", "🇮🇳"], ["TH", "🇹🇭"], ["VN", "🇻🇳"], ["PH", "🇵🇭"], ["MY", "🇲🇾"], 
  ["ID", "🇮🇩"], ["TR", "🇹🇷"], ["IT", "🇮🇹"], ["ES", "🇪🇸"], ["BR", "🇧🇷"],
  ["AR", "🇦🇷"], ["MX", "🇲🇽"], ["CL", "🇨🇱"], ["CO", "🇨🇴"], ["PE", "🇵🇪"],
  ["ZA", "🇿🇦"], ["EG", "🇪🇬"], ["SA", "🇸🇦"], ["AE", "🇦🇪"], ["IL", "🇮🇱"],
  ["PL", "🇵🇱"], ["SE", "🇸🇪"], ["NO", "🇳🇴"], ["DK", "🇩🇰"], ["FI", "🇫🇮"],
  ["IE", "🇮🇪"], ["PT", "🇵🇹"], ["GR", "🇬🇷"], ["CZ", "🇨🇿"], ["AT", "🇦🇹"],
  ["CH", "🇨🇭"], ["BE", "🇧🇪"], ["NZ", "🇳🇿"], ["UA", "🇺🇦"], ["RO", "🇷🇴"]
]);

function getFlag(code) {
    if (!code) return "";
    return flags.get(code.toUpperCase()) || code.toUpperCase();
}

// 结果容器
let result = {
  "title": '🚀 流媒体 & AI 检测',
  "ip": '正在获取IP...',
  "YouTube": '等待检测...',
  "Netflix": '等待检测...',
  "Disney": "等待检测...",
  "TikTok": "等待检测...",
  "ChatGPT": "等待检测...",
  "Claude": "等待检测...",
  "Gemini": "等待检测...",
  "Copilot": "等待检测...",
  "MetaAI": "等待检测..."
};

// ========== 通用 HTTP 请求函数 ==========
function makeRequest(url, headers = {}, timeout = 5) {
  return new Promise((resolve, reject) => {
    let option = {
      url: url,
      headers: Object.assign({ 'User-Agent': UA }, headers),
      policy: TARGET_POLICY,  // 🔥 使用指定策略
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

// ========== IP 信息查询 ==========
async function getIPInfo() {
  try {
    const { status, data } = await makeRequest(BASE_URL_IP_API, {}, 8);
    
    if (status === 200) {
      try {
        const ipInfo = JSON.parse(data);
        const ip = ipInfo.ip || "未知";
        const country = ipInfo.country_code || ipInfo.country || "";
        const org = ipInfo.organization || ipInfo.asn_organization || "";
        
        // 格式化输出
        let ipDisplay = `${ip}`;
        if (country) {
          ipDisplay += ` ${getFlag(country)}`;
        }
        if (org && org.length < 30) {  // 限制长度避免过长
          ipDisplay += ` (${org})`;
        }
        
        result["ip"] = ipDisplay;
        console.log(`[IP信息] ${ipDisplay}`);
      } catch (e) {
        // JSON 解析失败，尝试纯文本格式
        const ipMatch = data.match(/\d+\.\d+\.\d+\.\d+/);
        if (ipMatch) {
          result["ip"] = ipMatch[0];
        } else {
          result["ip"] = "IP获取失败";
        }
      }
    } else {
      result["ip"] = "IP获取失败";
    }
  } catch (error) {
    result["ip"] = "IP查询超时";
    console.log(`[IP信息] 查询失败: ${error}`);
  }
}

// ========== 流媒体检测函数 ==========

// 1. TikTok
async function testTikTok() {
  try {
    const { status, data } = await makeRequest(BASE_URL_TIKTOK);
    
    if (status === 200) {
      let regionMatch = data.match(/"region":"([a-zA-Z]{2})"/i);
      
      if (regionMatch && regionMatch[1]) {
        let region = regionMatch[1];
        result["TikTok"] = "TikTok: 支持 " + arrow + getFlag(region) + " 🎉";
      } else if (data.includes('region_restriction')) {
        result["TikTok"] = "TikTok: 未支持 (风控) 🚫";
      } else {
        result["TikTok"] = "TikTok: 支持 (未知地区) 🎉";
      }
    } else {
      result["TikTok"] = "TikTok: 未支持 🚫";
    }
  } catch (error) {
    result["TikTok"] = "TikTok: 检测超时 🚦";
  }
}

// 2. YouTube
async function testYTB() {
  try {
    const { status, data } = await makeRequest(BASE_URL_YTB);
    
    if (status !== 200) {
      result["YouTube"] = "YouTube: 检测失败 ❗️";
    } else if (data.indexOf('Premium is not available in your country') !== -1) {
      result["YouTube"] = "YouTube: 未支持 🚫";
    } else {
      let region = 'US';
      let re = new RegExp('"GL":"(.*?)"', 'gm');
      let ret = re.exec(data);
      if (ret != null && ret.length === 2) {
        region = ret[1];
      } else if (data.indexOf('www.google.cn') !== -1) {
        region = 'CN';
      }
      result["YouTube"] = "YouTube: 支持 " + arrow + getFlag(region) + " 🎉";
    }
  } catch (error) {
    result["YouTube"] = "YouTube: 检测超时 🚦";
  }
}

// 3. Netflix
async function testNf(filmId) {
  try {
    const { status, headers, data } = await makeRequest(BASE_URL_NF + filmId);
    
    if (status === 404) {
      result["Netflix"] = "Netflix: 仅自制剧 ⚠️";
    } else if (status === 403) {
      result["Netflix"] = "Netflix: 未支持 🚫";
    } else if (status === 200) {
      let region = 'US'; 
      try {
        let url = headers['X-Originating-URL'] || headers['x-originating-url'];
        if (url) {
          region = url.split('/')[3].split('-')[0].replace('title', 'us');
        }
      } catch (e) {
        console.log(`[Netflix] 地区解析失败: ${e}`);
      }
      result["Netflix"] = "Netflix: 完整支持 " + arrow + getFlag(region) + " 🎉";
    } else {
      result["Netflix"] = "Netflix: 检测异常 (" + status + ")";
    }
  } catch (error) {
    result["Netflix"] = "Netflix: 检测超时 🚦";
  }
}

// 4. Disney+
async function testDisneyPlus() {
  try {
    const { status, data } = await makeRequest(BASE_URL_DISNEY);
    
    if (status === 200 && data.indexOf('not available in your region') === -1) {
      let match = data.match(/Region: ([A-Za-z]{2})/);
      let region = match ? match[1] : "Global";
      result["Disney"] = "Disney+: 支持 " + arrow + getFlag(region) + " 🎉";
    } else {
      result["Disney"] = "Disney+: 未支持 🚫";
    }
  } catch (error) {
    result["Disney"] = "Disney+: 检测超时 🚦";
  }
}

// ========== AI 服务检测函数 ==========

// 5. ChatGPT
async function testChatGPT() {
  try {
    const { status } = await makeRequest(BASE_URL_GPT, {}, 6);
    
    if (status === 403) {
      result["ChatGPT"] = "ChatGPT: 未支持 🚫";
    } else {
      // 尝试获取详细地区信息
      try {
        const { status: traceStatus, data: traceData } = await makeRequest(BASE_URL_GPT_TRACE, {}, 5);
        
        if (traceStatus === 200 && traceData.includes("loc=")) {
          let region = traceData.split("loc=")[1].split("\n")[0];
          result["ChatGPT"] = "ChatGPT: 支持 " + arrow + getFlag(region) + " 🎉";
        } else {
          result["ChatGPT"] = "ChatGPT: 支持 🎉";
        }
      } catch (e) {
        result["ChatGPT"] = "ChatGPT: 支持 🎉";
      }
    }
  } catch (error) {
    result["ChatGPT"] = "ChatGPT: 检测超时 🚦";
  }
}

// 6. Claude
async function testClaude() {
  try {
    const { status } = await makeRequest(BASE_URL_CLAUDE);
    
    if (status !== 403) {
      result["Claude"] = "Claude: 支持 🎉";
    } else {
      result["Claude"] = "Claude: 未支持 🚫";
    }
  } catch (error) {
    result["Claude"] = "Claude: 检测超时 🚦";
  }
}

// 7. Gemini
async function testGemini() {
  try {
    const { status } = await makeRequest(BASE_URL_GEMINI);
    
    if (status === 200 || status === 302) {
      result["Gemini"] = "Gemini: 支持 🎉";
    } else {
      result["Gemini"] = "Gemini: 未支持 🚫";
    }
  } catch (error) {
    result["Gemini"] = "Gemini: 检测超时 🚦";
  }
}

// 8. Copilot
async function testCopilot() {
  try {
    const { status } = await makeRequest(BASE_URL_COPILOT);
    
    if (status === 200) {
      result["Copilot"] = "Copilot: 支持 🎉";
    } else {
      result["Copilot"] = "Copilot: 未支持 🚫";
    }
  } catch (error) {
    result["Copilot"] = "Copilot: 检测超时 🚦";
  }
}

// 9. Meta AI
async function testMetaAI() {
  try {
    const { status, data } = await makeRequest(BASE_URL_META);
    
    if (status === 200) {
      if (data.indexOf("not yet available") !== -1) {
        result["MetaAI"] = "Meta AI: 未支持 🚫";
      } else {
        result["MetaAI"] = "Meta AI: 支持 🎉";
      }
    } else if (status === 302) {
      result["MetaAI"] = "Meta AI: 支持 🎉";
    } else {
      result["MetaAI"] = "Meta AI: 未支持 🚫";
    }
  } catch (error) {
    result["MetaAI"] = "Meta AI: 检测超时 🚦";
  }
}

// ========== 主执行流程 ==========
;(async () => {
  console.log(`[开始检测] 使用策略: ${TARGET_POLICY}`);
  
  // 首先获取 IP 信息
  await getIPInfo();
  
  // 并行执行所有检测
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

  // 构造输出内容
  let content = "━━━━━━━━━━━━━━━━━━━━\n" +
                "📡 出口信息\n" +
                result["ip"] + "\n\n" +
                "📺 流媒体服务\n" +
                "━━━━━━━━━━━━━━━━━━━━\n" +
                result["YouTube"] + "\n" +
                result["Netflix"] + "\n" +
                result["Disney"] + "\n" +
                result["TikTok"] + "\n\n" +
                "🤖 人工智能\n" +
                "━━━━━━━━━━━━━━━━━━━━\n" +
                result["ChatGPT"] + "\n" +
                result["Claude"] + "\n" +
                result["Gemini"] + "\n" +
                result["Copilot"] + "\n" +
                result["MetaAI"] + "\n" +
                "━━━━━━━━━━━━━━━━━━━━\n" +
                "🔧 测试策略: " + TARGET_POLICY;

  console.log(`[检测完成] 策略: ${TARGET_POLICY}`);

  $done({
    title: '🚀 流媒体 & AI 检测',
    content: content,
    icon: 'play.tv.fill',
    'icon-color': '#FF2D55'
  });
})();
