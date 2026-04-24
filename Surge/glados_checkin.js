/**
 * GlaDOS 自动签到脚本 - Surge 专用版
 * * 说明：Cookie 通过 Surge 配置中的 argument 传递，无需在此处修改脚本。
 */

// 从 Surge 的 argument 中读取 Cookie，如果没传则给出提示
const cookieVal = (typeof $argument !== "undefined" && $argument !== "") ? $argument : "";

if (!cookieVal) {
  $notification.post("GlaDOS 签到失败", "配置错误", "请在 Surge 脚本配置的 argument 中填入 Cookie");
  $done();
}

const header = {
  "Accept": "application/json, text/plain, */*",
  "Content-Type": "application/json;charset=UTF-8",
  "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
  "Cookie": cookieVal,
};

function formatAmount(value) {
  if (value == null) return "未知";
  const str = String(value);
  return str.replace(/(\.\d*?[1-9])0+$/, "$1").replace(/\.0+$/, "");
}

function checkin() {
  const params = {
    url: "https://glados.one/api/user/checkin",
    headers: header,
    body: JSON.stringify({ token: "glados.one" }),
  };

  $httpClient.post(params, function (error, response, data) {
    if (error) {
      $notification.post("GlaDOS 签到错误", "网络请求失败", String(error));
    } else {
      let json;
      try {
        json = JSON.parse(data);
      } catch (e) {
        $notification.post("GlaDOS 返回解析失败", "", "服务器返回了非 JSON 格式数据");
        $done();
        return;
      }
      
      // 根据 code 判断结果：0 通常是成功，1 或其他可能是已签到或错误
      const balance = json.list?.[0]?.balance;
      const message = json.message || "无返回消息";
      
      $notification.post(
        "GlaDOS 签到结果",
        "当前积分总计: " + formatAmount(balance),
        message
      );
    }
    $done();
  });
}

checkin();
