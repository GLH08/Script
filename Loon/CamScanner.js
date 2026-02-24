/*
 ** CamScanner 解锁部分高级特权
*/

let obj = JSON.parse($response.body);
$done({body: JSON.stringify({
  "data": {
    "psnl_vip_property": {
      "expiry": "2013017600"
    }
  }
})});
