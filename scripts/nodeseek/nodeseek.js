/****************************** 
脚本功能：NodeSeek 论坛签到
Version  : v1.2.0-loon-fix.2
更新时间：2026-05-31
作者：Curtinp118
补丁：2026-09-13，兼容 Loon 状态码，增加不输出凭据和响应原文的 403 诊断
原始脚本：https://github.com/curtinp118/Scripthub/blob/main/scripts/nodeseek/nodeseek.js
Platform : Quantumult X / Loon / Surge

使用说明：
访问 NodeSeek 个人页面保存请求头，定时任务自动签到。

[rewrite_local]
^https://www\.nodeseek\.com/api/account/getInfo/\d+\?readme=1$ url script-request-header https://raw.githubusercontent.com/Mars-hits-Earth/loon-local-rules/main/scripts/nodeseek/nodeseek.js

[task_local]
30 8 * * * https://raw.githubusercontent.com/Mars-hits-Earth/loon-local-rules/main/scripts/nodeseek/nodeseek.js, tag=NS签到, enabled=true

[MITM]
hostname = www.nodeseek.com
*******************************/

// ========== 三端适配层 ==========
var isQX = typeof $task !== "undefined";
var isLoon = typeof $loon !== "undefined";
var isSurge = typeof $httpClient !== "undefined" && !isLoon;

var $http = {
  fetch: function (opts) {
    if (isQX) return $task.fetch(opts);
    return new Promise(function (resolve, reject) {
      var method = (opts.method || "GET").toUpperCase();
      var handler = function (err, resp, data) {
        if (err) reject(err);
        else resolve({
          statusCode: resp.statusCode !== undefined ? resp.statusCode : resp.status,
          headers: resp.headers,
          body: data
        });
      };
      if (method === "POST") $httpClient.post(opts, handler);
      else $httpClient.get(opts, handler);
    });
  }
};

var $store = {
  read: function (key) { return isQX ? $prefs.valueForKey(key) : $persistentStore.read(key); },
  write: function (val, key) { return isQX ? $prefs.setValueForKey(val, key) : $persistentStore.write(val, key); }
};

var notifyFn = isQX
  ? function (t, s, b) { $notify(t, s, b); }
  : function (t, s, b) { $notification.post(t, s, b); };

// ========== Logger 模块 ==========
var Logger = {
  scriptStart: function (name, version, platform, requestType) {
    var now = new Date();
    var pad = function (n) { return String(n).padStart(2, "0"); };
    var time = now.getFullYear() + "-" + pad(now.getMonth() + 1) + "-" + pad(now.getDate()) + " " + pad(now.getHours()) + ":" + pad(now.getMinutes()) + ":" + pad(now.getSeconds());
    console.log("🚀 Script Start");
    console.log("Time     : " + time);
    console.log("Version  : " + version + " | " + platform + " | " + requestType);
    console.log("Platform : " + platform);
    console.log("------------------------------------");
  },

  envCheck: function (headersParsed, headerStatus) {
    console.log("📂 Environment");
    console.log("- Headers: " + headerStatus);
    console.log("- Parsed : " + (headersParsed ? "Yes" : "No"));
    console.log("- Login  : Not verified");
    console.log("------------------------------------");
  },

  accountHeader: function (index, domain) {
    console.log("👤 Account | " + domain);
  },

  field: function (label, value) {
    var padding = "              ";
    var key = (label + padding).substring(0, 14);
    console.log(key + ": " + value);
  },

  status: function (icon, text) { this.field("Status", icon + " " + text); },
  action: function (val) { this.field("Action", val); },
  message: function (val) { this.field("Message", val); },

  separator: function () { console.log("------------------------------------"); },

  summary: function (total, success, duplicate, failed, result) {
    console.log("📊 Summary");
    console.log("Total      : " + total);
    console.log("Success    : " + success);
    console.log("Duplicate  : " + duplicate);
    console.log("Failed     : " + failed);
    console.log("🎯 Result  : " + result);
    console.log("End");
  }
};

// ========== 工具函数 ==========
var SCRIPT_NAME = "NodeSeek";
var SCRIPT_VERSION = "v1.2.0-loon-fix.2";
var NS_HEADER_KEY = "NS_NodeseekHeaders";
var isGetHeader = typeof $request !== "undefined";

var NEED_KEYS = [
  "Connection", "Accept-Encoding", "Priority", "Content-Type", "Origin",
  "refract-sign", "User-Agent", "refract-key", "Sec-Fetch-Mode",
  "Cookie", "Host", "Referer", "Accept-Language", "Accept"
];

function safeJsonParse(text) {
  try { return [JSON.parse(text), null]; } catch (e) { return [null, e]; }
}

function responseHeader(headers, name) {
  var keys = Object.keys(headers || {});
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() === name) return String(headers[keys[i]]);
  }
  return "";
}

// Only log fixed diagnostic labels; never print response headers or body verbatim.
function diagnose403(resp, body, parsed) {
  var contentType = responseHeader(resp.headers, "content-type").toLowerCase();
  var challenge = responseHeader(resp.headers, "cf-mitigated").toLowerCase() === "challenge";
  var html = contentType.indexOf("text/html") !== -1 || /^\s*(?:<!doctype html|<html)/i.test(body);
  var json = parsed[1] === null;
  var challengeMarker = html && /cf-chl-|\/cdn-cgi\/challenge-platform\//i.test(body);
  var hint = "原因未确认";
  if (challenge) hint = "Cloudflare 验证页面（响应头已确认）";
  else if (challengeMarker) hint = "疑似 Cloudflare 验证页面（HTML 特征）";
  else if (json) hint = "JSON 拒绝响应，需结合网页签到结果判断";
  else if (html) hint = "HTML 拒绝页面，无法仅凭 403 确认原因";
  var obj = parsed[0];
  var message = obj && typeof obj === "object" ?
    (typeof obj.message === "string" ? obj.message : (typeof obj.error === "string" ? obj.error : "")) : "";
  if (!challenge && !challengeMarker && message) {
    if (/未登录|未登陆|登录过期|登陆过期|not logged in|unauthenticated|login required/i.test(message)) hint = "响应提示登录状态异常";
    else if (/refract|csrf|signature|签名|令牌|token/i.test(message)) hint = "响应提及请求签名或令牌，需进一步确认";
    else if (/已经签到|已签到|already.*(checked|signed)/i.test(message)) hint = "响应提示今日已签到";
  }
  Logger.field("HTTP", resp.statusCode);
  Logger.field("Response", json ? "JSON" : (html ? "HTML" : (body ? "Other" : "Empty")));
  Logger.field("CF-Challenge", challenge ? "Confirmed" : "Not indicated");
  Logger.field("Hint", hint);
  return hint;
}

function getPlatform() {
  if (isQX) return "Quantumult X";
  if (isLoon) return "Loon";
  if (isSurge) return "Surge";
  return "Unknown";
}

function pickNeedHeaders(src) {
  var dst = {};
  var get = function (name) {
    return src[name] !== undefined ? src[name] : (src[name.toLowerCase()] !== undefined ? src[name.toLowerCase()] : src[name.toUpperCase()]);
  };
  for (var i = 0; i < NEED_KEYS.length; i++) {
    var v = get(NEED_KEYS[i]);
    if (v !== undefined) dst[NEED_KEYS[i]] = v;
  }
  return dst;
}

// ========== 主流程 ==========
if (isGetHeader) {
  Logger.scriptStart(SCRIPT_NAME, SCRIPT_VERSION, getPlatform(), "Manual");

  var allHeaders = $request.headers || {};
  var picked = pickNeedHeaders(allHeaders);

  if (!picked || Object.keys(picked).length === 0) {
    Logger.status("⚠️", "未抓到请求头");
    notifyFn("NodeSeek", "⚠️ 抓包失败", "未获取到请求头");
    $done({});
  } else {
    var ok = $store.write(JSON.stringify(picked), NS_HEADER_KEY);
    Logger.status("✅", ok ? "请求头已保存" : "保存失败");
    Logger.field("Fields", Object.keys(picked).length);
    notifyFn("NodeSeek", ok ? "✅ 抓包成功" : "❌ 保存失败", ok ? "请求头已保存" : "写入存储失败");
    $done({});
  }
} else {
  Logger.scriptStart(SCRIPT_NAME, SCRIPT_VERSION, getPlatform(), "Cron");

  var raw = $store.read(NS_HEADER_KEY);
  if (!raw) {
    Logger.envCheck(false, "Missing");
    Logger.status("⚠️", "缺少请求头");
    notifyFn("NodeSeek", "⚠️ 缺少请求头", "请先访问个人页面");
    $done();
  } else {
    var parsed = safeJsonParse(raw);
    var savedHeaders = parsed[0];

    if (!savedHeaders) {
      Logger.envCheck(false, "Invalid");
      Logger.status("⚠️", "请求头解析失败");
      notifyFn("NodeSeek", "❌ 请求头异常", "数据损坏，请重新抓包");
      $done();
    } else {
      Logger.envCheck(true, "Found");
      Logger.accountHeader(null, "www.nodeseek.com");

      var headers = {
        Connection: savedHeaders["Connection"] || "keep-alive",
        "Accept-Encoding": savedHeaders["Accept-Encoding"] || "gzip, deflate, br",
        Priority: savedHeaders["Priority"] || "u=3, i",
        "Content-Type": savedHeaders["Content-Type"] || "text/plain;charset=UTF-8",
        Origin: savedHeaders["Origin"] || "https://www.nodeseek.com",
        "refract-sign": savedHeaders["refract-sign"] || "",
        "User-Agent": savedHeaders["User-Agent"] || "Mozilla/5.0",
        "refract-key": savedHeaders["refract-key"] || "",
        "Sec-Fetch-Mode": savedHeaders["Sec-Fetch-Mode"] || "cors",
        Cookie: savedHeaders["Cookie"] || "",
        Host: savedHeaders["Host"] || "www.nodeseek.com",
        Referer: savedHeaders["Referer"] || "https://www.nodeseek.com/",
        "Accept-Language": savedHeaders["Accept-Language"] || "zh-CN,zh-Hans;q=0.9",
        Accept: savedHeaders["Accept"] || "*/*"
      };

      $http.fetch({
        url: "https://www.nodeseek.com/api/attendance?random=true",
        method: "POST", headers: headers, body: ""
      }).then(function (resp) {
        var status = resp.statusCode;
        var body = resp.body || "";
        var msg = "";
        var p = safeJsonParse(body);
        if (p[0]) msg = p[0].message ? String(p[0].message) : "";

        if (status === 403) {
          Logger.status("⚠️", "403 请求被拒绝");
          var hint = diagnose403(resp, body, p);
          Logger.separator();
          Logger.summary(1, 0, 0, 1, "HTTP 403，请查看诊断信息");
          notifyFn("NodeSeek", "⚠️ HTTP 403", hint);
        } else if (status === 500) {
          Logger.status("❌", "500 服务器错误");
          Logger.separator();
          Logger.summary(1, 0, 0, 1, "服务器错误");
          notifyFn("NodeSeek", "❌ 服务器错误", "500");
        } else if (status >= 200 && status < 300) {
          Logger.status("✅", "签到成功");
          if (msg) Logger.message(msg);
          Logger.separator();
          Logger.summary(1, 1, 0, 0, "签到成功");
          notifyFn("NodeSeek", "✅ 签到成功", msg || "签到完成");
        } else {
          Logger.status("❌", "请求异常 " + status);
          Logger.separator();
          Logger.summary(1, 0, 0, 1, "请求异常");
          notifyFn("NodeSeek", "❌ 请求异常", "HTTP " + status);
        }
        $done();
      }, function (reason) {
        Logger.status("❌", "网络错误");
        Logger.separator();
        Logger.summary(1, 0, 0, 1, "网络错误");
        notifyFn("NodeSeek", "❌ 网络错误", "请检查网络连接");
        $done();
      });
    }
  }
}
