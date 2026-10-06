// site/server/source/main.ts
import { createServer } from "node:http";
import { chmodSync, lstatSync, unlinkSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

// site/node_modules/.pnpm/bcryptjs@3.0.3/node_modules/bcryptjs/index.js
import nodeCrypto from "crypto";
var randomFallback = null;
function randomBytes(len) {
  try {
    return crypto.getRandomValues(new Uint8Array(len));
  } catch {
  }
  try {
    return nodeCrypto.randomBytes(len);
  } catch {
  }
  if (!randomFallback) {
    throw Error(
      "Neither WebCryptoAPI nor a crypto module is available. Use bcrypt.setRandomFallback to set an alternative"
    );
  }
  return randomFallback(len);
}
function setRandomFallback(random2) {
  randomFallback = random2;
}
function genSaltSync(rounds, seed_length) {
  rounds = rounds || GENSALT_DEFAULT_LOG2_ROUNDS;
  if (typeof rounds !== "number")
    throw Error(
      "Illegal arguments: " + typeof rounds + ", " + typeof seed_length
    );
  if (rounds < 4) rounds = 4;
  else if (rounds > 31) rounds = 31;
  var salt = [];
  salt.push("$2b$");
  if (rounds < 10) salt.push("0");
  salt.push(rounds.toString());
  salt.push("$");
  salt.push(base64_encode(randomBytes(BCRYPT_SALT_LEN), BCRYPT_SALT_LEN));
  return salt.join("");
}
function genSalt(rounds, seed_length, callback) {
  if (typeof seed_length === "function")
    callback = seed_length, seed_length = void 0;
  if (typeof rounds === "function") callback = rounds, rounds = void 0;
  if (typeof rounds === "undefined") rounds = GENSALT_DEFAULT_LOG2_ROUNDS;
  else if (typeof rounds !== "number")
    throw Error("illegal arguments: " + typeof rounds);
  function _async(callback2) {
    nextTick(function() {
      try {
        callback2(null, genSaltSync(rounds));
      } catch (err) {
        callback2(err);
      }
    });
  }
  if (callback) {
    if (typeof callback !== "function")
      throw Error("Illegal callback: " + typeof callback);
    _async(callback);
  } else
    return new Promise(function(resolve, reject) {
      _async(function(err, res) {
        if (err) {
          reject(err);
          return;
        }
        resolve(res);
      });
    });
}
function hashSync(password, salt) {
  if (typeof salt === "undefined") salt = GENSALT_DEFAULT_LOG2_ROUNDS;
  if (typeof salt === "number") salt = genSaltSync(salt);
  if (typeof password !== "string" || typeof salt !== "string")
    throw Error("Illegal arguments: " + typeof password + ", " + typeof salt);
  return _hash(password, salt);
}
function hash(password, salt, callback, progressCallback) {
  function _async(callback2) {
    if (typeof password === "string" && typeof salt === "number")
      genSalt(salt, function(err, salt2) {
        _hash(password, salt2, callback2, progressCallback);
      });
    else if (typeof password === "string" && typeof salt === "string")
      _hash(password, salt, callback2, progressCallback);
    else
      nextTick(
        callback2.bind(
          this,
          Error("Illegal arguments: " + typeof password + ", " + typeof salt)
        )
      );
  }
  if (callback) {
    if (typeof callback !== "function")
      throw Error("Illegal callback: " + typeof callback);
    _async(callback);
  } else
    return new Promise(function(resolve, reject) {
      _async(function(err, res) {
        if (err) {
          reject(err);
          return;
        }
        resolve(res);
      });
    });
}
function safeStringCompare(known, unknown) {
  var diff = known.length ^ unknown.length;
  for (var i = 0; i < known.length; ++i) {
    diff |= known.charCodeAt(i) ^ unknown.charCodeAt(i);
  }
  return diff === 0;
}
function compareSync(password, hash2) {
  if (typeof password !== "string" || typeof hash2 !== "string")
    throw Error("Illegal arguments: " + typeof password + ", " + typeof hash2);
  if (hash2.length !== 60) return false;
  return safeStringCompare(
    hashSync(password, hash2.substring(0, hash2.length - 31)),
    hash2
  );
}
function compare(password, hashValue, callback, progressCallback) {
  function _async(callback2) {
    if (typeof password !== "string" || typeof hashValue !== "string") {
      nextTick(
        callback2.bind(
          this,
          Error(
            "Illegal arguments: " + typeof password + ", " + typeof hashValue
          )
        )
      );
      return;
    }
    if (hashValue.length !== 60) {
      nextTick(callback2.bind(this, null, false));
      return;
    }
    hash(
      password,
      hashValue.substring(0, 29),
      function(err, comp) {
        if (err) callback2(err);
        else callback2(null, safeStringCompare(comp, hashValue));
      },
      progressCallback
    );
  }
  if (callback) {
    if (typeof callback !== "function")
      throw Error("Illegal callback: " + typeof callback);
    _async(callback);
  } else
    return new Promise(function(resolve, reject) {
      _async(function(err, res) {
        if (err) {
          reject(err);
          return;
        }
        resolve(res);
      });
    });
}
function getRounds(hash2) {
  if (typeof hash2 !== "string")
    throw Error("Illegal arguments: " + typeof hash2);
  return parseInt(hash2.split("$")[2], 10);
}
function getSalt(hash2) {
  if (typeof hash2 !== "string")
    throw Error("Illegal arguments: " + typeof hash2);
  if (hash2.length !== 60)
    throw Error("Illegal hash length: " + hash2.length + " != 60");
  return hash2.substring(0, 29);
}
function truncates(password) {
  if (typeof password !== "string")
    throw Error("Illegal arguments: " + typeof password);
  return utf8Length(password) > 72;
}
var nextTick = typeof setImmediate === "function" ? setImmediate : typeof scheduler === "object" && typeof scheduler.postTask === "function" ? scheduler.postTask.bind(scheduler) : setTimeout;
function utf8Length(string) {
  var len = 0, c = 0;
  for (var i = 0; i < string.length; ++i) {
    c = string.charCodeAt(i);
    if (c < 128) len += 1;
    else if (c < 2048) len += 2;
    else if ((c & 64512) === 55296 && (string.charCodeAt(i + 1) & 64512) === 56320) {
      ++i;
      len += 4;
    } else len += 3;
  }
  return len;
}
function utf8Array(string) {
  var offset = 0, c1, c2;
  var buffer = new Array(utf8Length(string));
  for (var i = 0, k = string.length; i < k; ++i) {
    c1 = string.charCodeAt(i);
    if (c1 < 128) {
      buffer[offset++] = c1;
    } else if (c1 < 2048) {
      buffer[offset++] = c1 >> 6 | 192;
      buffer[offset++] = c1 & 63 | 128;
    } else if ((c1 & 64512) === 55296 && ((c2 = string.charCodeAt(i + 1)) & 64512) === 56320) {
      c1 = 65536 + ((c1 & 1023) << 10) + (c2 & 1023);
      ++i;
      buffer[offset++] = c1 >> 18 | 240;
      buffer[offset++] = c1 >> 12 & 63 | 128;
      buffer[offset++] = c1 >> 6 & 63 | 128;
      buffer[offset++] = c1 & 63 | 128;
    } else {
      buffer[offset++] = c1 >> 12 | 224;
      buffer[offset++] = c1 >> 6 & 63 | 128;
      buffer[offset++] = c1 & 63 | 128;
    }
  }
  return buffer;
}
var BASE64_CODE = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".split("");
var BASE64_INDEX = [
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  0,
  1,
  54,
  55,
  56,
  57,
  58,
  59,
  60,
  61,
  62,
  63,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24,
  25,
  26,
  27,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  28,
  29,
  30,
  31,
  32,
  33,
  34,
  35,
  36,
  37,
  38,
  39,
  40,
  41,
  42,
  43,
  44,
  45,
  46,
  47,
  48,
  49,
  50,
  51,
  52,
  53,
  -1,
  -1,
  -1,
  -1,
  -1
];
function base64_encode(b, len) {
  var off = 0, rs = [], c1, c2;
  if (len <= 0 || len > b.length) throw Error("Illegal len: " + len);
  while (off < len) {
    c1 = b[off++] & 255;
    rs.push(BASE64_CODE[c1 >> 2 & 63]);
    c1 = (c1 & 3) << 4;
    if (off >= len) {
      rs.push(BASE64_CODE[c1 & 63]);
      break;
    }
    c2 = b[off++] & 255;
    c1 |= c2 >> 4 & 15;
    rs.push(BASE64_CODE[c1 & 63]);
    c1 = (c2 & 15) << 2;
    if (off >= len) {
      rs.push(BASE64_CODE[c1 & 63]);
      break;
    }
    c2 = b[off++] & 255;
    c1 |= c2 >> 6 & 3;
    rs.push(BASE64_CODE[c1 & 63]);
    rs.push(BASE64_CODE[c2 & 63]);
  }
  return rs.join("");
}
function base64_decode(s, len) {
  var off = 0, slen = s.length, olen = 0, rs = [], c1, c2, c3, c4, o, code;
  if (len <= 0) throw Error("Illegal len: " + len);
  while (off < slen - 1 && olen < len) {
    code = s.charCodeAt(off++);
    c1 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
    code = s.charCodeAt(off++);
    c2 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
    if (c1 == -1 || c2 == -1) break;
    o = c1 << 2 >>> 0;
    o |= (c2 & 48) >> 4;
    rs.push(String.fromCharCode(o));
    if (++olen >= len || off >= slen) break;
    code = s.charCodeAt(off++);
    c3 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
    if (c3 == -1) break;
    o = (c2 & 15) << 4 >>> 0;
    o |= (c3 & 60) >> 2;
    rs.push(String.fromCharCode(o));
    if (++olen >= len || off >= slen) break;
    code = s.charCodeAt(off++);
    c4 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
    o = (c3 & 3) << 6 >>> 0;
    o |= c4;
    rs.push(String.fromCharCode(o));
    ++olen;
  }
  var res = [];
  for (off = 0; off < olen; off++) res.push(rs[off].charCodeAt(0));
  return res;
}
var BCRYPT_SALT_LEN = 16;
var GENSALT_DEFAULT_LOG2_ROUNDS = 10;
var BLOWFISH_NUM_ROUNDS = 16;
var MAX_EXECUTION_TIME = 100;
var P_ORIG = [
  608135816,
  2242054355,
  320440878,
  57701188,
  2752067618,
  698298832,
  137296536,
  3964562569,
  1160258022,
  953160567,
  3193202383,
  887688300,
  3232508343,
  3380367581,
  1065670069,
  3041331479,
  2450970073,
  2306472731
];
var S_ORIG = [
  3509652390,
  2564797868,
  805139163,
  3491422135,
  3101798381,
  1780907670,
  3128725573,
  4046225305,
  614570311,
  3012652279,
  134345442,
  2240740374,
  1667834072,
  1901547113,
  2757295779,
  4103290238,
  227898511,
  1921955416,
  1904987480,
  2182433518,
  2069144605,
  3260701109,
  2620446009,
  720527379,
  3318853667,
  677414384,
  3393288472,
  3101374703,
  2390351024,
  1614419982,
  1822297739,
  2954791486,
  3608508353,
  3174124327,
  2024746970,
  1432378464,
  3864339955,
  2857741204,
  1464375394,
  1676153920,
  1439316330,
  715854006,
  3033291828,
  289532110,
  2706671279,
  2087905683,
  3018724369,
  1668267050,
  732546397,
  1947742710,
  3462151702,
  2609353502,
  2950085171,
  1814351708,
  2050118529,
  680887927,
  999245976,
  1800124847,
  3300911131,
  1713906067,
  1641548236,
  4213287313,
  1216130144,
  1575780402,
  4018429277,
  3917837745,
  3693486850,
  3949271944,
  596196993,
  3549867205,
  258830323,
  2213823033,
  772490370,
  2760122372,
  1774776394,
  2652871518,
  566650946,
  4142492826,
  1728879713,
  2882767088,
  1783734482,
  3629395816,
  2517608232,
  2874225571,
  1861159788,
  326777828,
  3124490320,
  2130389656,
  2716951837,
  967770486,
  1724537150,
  2185432712,
  2364442137,
  1164943284,
  2105845187,
  998989502,
  3765401048,
  2244026483,
  1075463327,
  1455516326,
  1322494562,
  910128902,
  469688178,
  1117454909,
  936433444,
  3490320968,
  3675253459,
  1240580251,
  122909385,
  2157517691,
  634681816,
  4142456567,
  3825094682,
  3061402683,
  2540495037,
  79693498,
  3249098678,
  1084186820,
  1583128258,
  426386531,
  1761308591,
  1047286709,
  322548459,
  995290223,
  1845252383,
  2603652396,
  3431023940,
  2942221577,
  3202600964,
  3727903485,
  1712269319,
  422464435,
  3234572375,
  1170764815,
  3523960633,
  3117677531,
  1434042557,
  442511882,
  3600875718,
  1076654713,
  1738483198,
  4213154764,
  2393238008,
  3677496056,
  1014306527,
  4251020053,
  793779912,
  2902807211,
  842905082,
  4246964064,
  1395751752,
  1040244610,
  2656851899,
  3396308128,
  445077038,
  3742853595,
  3577915638,
  679411651,
  2892444358,
  2354009459,
  1767581616,
  3150600392,
  3791627101,
  3102740896,
  284835224,
  4246832056,
  1258075500,
  768725851,
  2589189241,
  3069724005,
  3532540348,
  1274779536,
  3789419226,
  2764799539,
  1660621633,
  3471099624,
  4011903706,
  913787905,
  3497959166,
  737222580,
  2514213453,
  2928710040,
  3937242737,
  1804850592,
  3499020752,
  2949064160,
  2386320175,
  2390070455,
  2415321851,
  4061277028,
  2290661394,
  2416832540,
  1336762016,
  1754252060,
  3520065937,
  3014181293,
  791618072,
  3188594551,
  3933548030,
  2332172193,
  3852520463,
  3043980520,
  413987798,
  3465142937,
  3030929376,
  4245938359,
  2093235073,
  3534596313,
  375366246,
  2157278981,
  2479649556,
  555357303,
  3870105701,
  2008414854,
  3344188149,
  4221384143,
  3956125452,
  2067696032,
  3594591187,
  2921233993,
  2428461,
  544322398,
  577241275,
  1471733935,
  610547355,
  4027169054,
  1432588573,
  1507829418,
  2025931657,
  3646575487,
  545086370,
  48609733,
  2200306550,
  1653985193,
  298326376,
  1316178497,
  3007786442,
  2064951626,
  458293330,
  2589141269,
  3591329599,
  3164325604,
  727753846,
  2179363840,
  146436021,
  1461446943,
  4069977195,
  705550613,
  3059967265,
  3887724982,
  4281599278,
  3313849956,
  1404054877,
  2845806497,
  146425753,
  1854211946,
  1266315497,
  3048417604,
  3681880366,
  3289982499,
  290971e4,
  1235738493,
  2632868024,
  2414719590,
  3970600049,
  1771706367,
  1449415276,
  3266420449,
  422970021,
  1963543593,
  2690192192,
  3826793022,
  1062508698,
  1531092325,
  1804592342,
  2583117782,
  2714934279,
  4024971509,
  1294809318,
  4028980673,
  1289560198,
  2221992742,
  1669523910,
  35572830,
  157838143,
  1052438473,
  1016535060,
  1802137761,
  1753167236,
  1386275462,
  3080475397,
  2857371447,
  1040679964,
  2145300060,
  2390574316,
  1461121720,
  2956646967,
  4031777805,
  4028374788,
  33600511,
  2920084762,
  1018524850,
  629373528,
  3691585981,
  3515945977,
  2091462646,
  2486323059,
  586499841,
  988145025,
  935516892,
  3367335476,
  2599673255,
  2839830854,
  265290510,
  3972581182,
  2759138881,
  3795373465,
  1005194799,
  847297441,
  406762289,
  1314163512,
  1332590856,
  1866599683,
  4127851711,
  750260880,
  613907577,
  1450815602,
  3165620655,
  3734664991,
  3650291728,
  3012275730,
  3704569646,
  1427272223,
  778793252,
  1343938022,
  2676280711,
  2052605720,
  1946737175,
  3164576444,
  3914038668,
  3967478842,
  3682934266,
  1661551462,
  3294938066,
  4011595847,
  840292616,
  3712170807,
  616741398,
  312560963,
  711312465,
  1351876610,
  322626781,
  1910503582,
  271666773,
  2175563734,
  1594956187,
  70604529,
  3617834859,
  1007753275,
  1495573769,
  4069517037,
  2549218298,
  2663038764,
  504708206,
  2263041392,
  3941167025,
  2249088522,
  1514023603,
  1998579484,
  1312622330,
  694541497,
  2582060303,
  2151582166,
  1382467621,
  776784248,
  2618340202,
  3323268794,
  2497899128,
  2784771155,
  503983604,
  4076293799,
  907881277,
  423175695,
  432175456,
  1378068232,
  4145222326,
  3954048622,
  3938656102,
  3820766613,
  2793130115,
  2977904593,
  26017576,
  3274890735,
  3194772133,
  1700274565,
  1756076034,
  4006520079,
  3677328699,
  720338349,
  1533947780,
  354530856,
  688349552,
  3973924725,
  1637815568,
  332179504,
  3949051286,
  53804574,
  2852348879,
  3044236432,
  1282449977,
  3583942155,
  3416972820,
  4006381244,
  1617046695,
  2628476075,
  3002303598,
  1686838959,
  431878346,
  2686675385,
  1700445008,
  1080580658,
  1009431731,
  832498133,
  3223435511,
  2605976345,
  2271191193,
  2516031870,
  1648197032,
  4164389018,
  2548247927,
  300782431,
  375919233,
  238389289,
  3353747414,
  2531188641,
  2019080857,
  1475708069,
  455242339,
  2609103871,
  448939670,
  3451063019,
  1395535956,
  2413381860,
  1841049896,
  1491858159,
  885456874,
  4264095073,
  4001119347,
  1565136089,
  3898914787,
  1108368660,
  540939232,
  1173283510,
  2745871338,
  3681308437,
  4207628240,
  3343053890,
  4016749493,
  1699691293,
  1103962373,
  3625875870,
  2256883143,
  3830138730,
  1031889488,
  3479347698,
  1535977030,
  4236805024,
  3251091107,
  2132092099,
  1774941330,
  1199868427,
  1452454533,
  157007616,
  2904115357,
  342012276,
  595725824,
  1480756522,
  206960106,
  497939518,
  591360097,
  863170706,
  2375253569,
  3596610801,
  1814182875,
  2094937945,
  3421402208,
  1082520231,
  3463918190,
  2785509508,
  435703966,
  3908032597,
  1641649973,
  2842273706,
  3305899714,
  1510255612,
  2148256476,
  2655287854,
  3276092548,
  4258621189,
  236887753,
  3681803219,
  274041037,
  1734335097,
  3815195456,
  3317970021,
  1899903192,
  1026095262,
  4050517792,
  356393447,
  2410691914,
  3873677099,
  3682840055,
  3913112168,
  2491498743,
  4132185628,
  2489919796,
  1091903735,
  1979897079,
  3170134830,
  3567386728,
  3557303409,
  857797738,
  1136121015,
  1342202287,
  507115054,
  2535736646,
  337727348,
  3213592640,
  1301675037,
  2528481711,
  1895095763,
  1721773893,
  3216771564,
  62756741,
  2142006736,
  835421444,
  2531993523,
  1442658625,
  3659876326,
  2882144922,
  676362277,
  1392781812,
  170690266,
  3921047035,
  1759253602,
  3611846912,
  1745797284,
  664899054,
  1329594018,
  3901205900,
  3045908486,
  2062866102,
  2865634940,
  3543621612,
  3464012697,
  1080764994,
  553557557,
  3656615353,
  3996768171,
  991055499,
  499776247,
  1265440854,
  648242737,
  3940784050,
  980351604,
  3713745714,
  1749149687,
  3396870395,
  4211799374,
  3640570775,
  1161844396,
  3125318951,
  1431517754,
  545492359,
  4268468663,
  3499529547,
  1437099964,
  2702547544,
  3433638243,
  2581715763,
  2787789398,
  1060185593,
  1593081372,
  2418618748,
  4260947970,
  69676912,
  2159744348,
  86519011,
  2512459080,
  3838209314,
  1220612927,
  3339683548,
  133810670,
  1090789135,
  1078426020,
  1569222167,
  845107691,
  3583754449,
  4072456591,
  1091646820,
  628848692,
  1613405280,
  3757631651,
  526609435,
  236106946,
  48312990,
  2942717905,
  3402727701,
  1797494240,
  859738849,
  992217954,
  4005476642,
  2243076622,
  3870952857,
  3732016268,
  765654824,
  3490871365,
  2511836413,
  1685915746,
  3888969200,
  1414112111,
  2273134842,
  3281911079,
  4080962846,
  172450625,
  2569994100,
  980381355,
  4109958455,
  2819808352,
  2716589560,
  2568741196,
  3681446669,
  3329971472,
  1835478071,
  660984891,
  3704678404,
  4045999559,
  3422617507,
  3040415634,
  1762651403,
  1719377915,
  3470491036,
  2693910283,
  3642056355,
  3138596744,
  1364962596,
  2073328063,
  1983633131,
  926494387,
  3423689081,
  2150032023,
  4096667949,
  1749200295,
  3328846651,
  309677260,
  2016342300,
  1779581495,
  3079819751,
  111262694,
  1274766160,
  443224088,
  298511866,
  1025883608,
  3806446537,
  1145181785,
  168956806,
  3641502830,
  3584813610,
  1689216846,
  3666258015,
  3200248200,
  1692713982,
  2646376535,
  4042768518,
  1618508792,
  1610833997,
  3523052358,
  4130873264,
  2001055236,
  3610705100,
  2202168115,
  4028541809,
  2961195399,
  1006657119,
  2006996926,
  3186142756,
  1430667929,
  3210227297,
  1314452623,
  4074634658,
  4101304120,
  2273951170,
  1399257539,
  3367210612,
  3027628629,
  1190975929,
  2062231137,
  2333990788,
  2221543033,
  2438960610,
  1181637006,
  548689776,
  2362791313,
  3372408396,
  3104550113,
  3145860560,
  296247880,
  1970579870,
  3078560182,
  3769228297,
  1714227617,
  3291629107,
  3898220290,
  166772364,
  1251581989,
  493813264,
  448347421,
  195405023,
  2709975567,
  677966185,
  3703036547,
  1463355134,
  2715995803,
  1338867538,
  1343315457,
  2802222074,
  2684532164,
  233230375,
  2599980071,
  2000651841,
  3277868038,
  1638401717,
  4028070440,
  3237316320,
  6314154,
  819756386,
  300326615,
  590932579,
  1405279636,
  3267499572,
  3150704214,
  2428286686,
  3959192993,
  3461946742,
  1862657033,
  1266418056,
  963775037,
  2089974820,
  2263052895,
  1917689273,
  448879540,
  3550394620,
  3981727096,
  150775221,
  3627908307,
  1303187396,
  508620638,
  2975983352,
  2726630617,
  1817252668,
  1876281319,
  1457606340,
  908771278,
  3720792119,
  3617206836,
  2455994898,
  1729034894,
  1080033504,
  976866871,
  3556439503,
  2881648439,
  1522871579,
  1555064734,
  1336096578,
  3548522304,
  2579274686,
  3574697629,
  3205460757,
  3593280638,
  3338716283,
  3079412587,
  564236357,
  2993598910,
  1781952180,
  1464380207,
  3163844217,
  3332601554,
  1699332808,
  1393555694,
  1183702653,
  3581086237,
  1288719814,
  691649499,
  2847557200,
  2895455976,
  3193889540,
  2717570544,
  1781354906,
  1676643554,
  2592534050,
  3230253752,
  1126444790,
  2770207658,
  2633158820,
  2210423226,
  2615765581,
  2414155088,
  3127139286,
  673620729,
  2805611233,
  1269405062,
  4015350505,
  3341807571,
  4149409754,
  1057255273,
  2012875353,
  2162469141,
  2276492801,
  2601117357,
  993977747,
  3918593370,
  2654263191,
  753973209,
  36408145,
  2530585658,
  25011837,
  3520020182,
  2088578344,
  530523599,
  2918365339,
  1524020338,
  1518925132,
  3760827505,
  3759777254,
  1202760957,
  3985898139,
  3906192525,
  674977740,
  4174734889,
  2031300136,
  2019492241,
  3983892565,
  4153806404,
  3822280332,
  352677332,
  2297720250,
  60907813,
  90501309,
  3286998549,
  1016092578,
  2535922412,
  2839152426,
  457141659,
  509813237,
  4120667899,
  652014361,
  1966332200,
  2975202805,
  55981186,
  2327461051,
  676427537,
  3255491064,
  2882294119,
  3433927263,
  1307055953,
  942726286,
  933058658,
  2468411793,
  3933900994,
  4215176142,
  1361170020,
  2001714738,
  2830558078,
  3274259782,
  1222529897,
  1679025792,
  2729314320,
  3714953764,
  1770335741,
  151462246,
  3013232138,
  1682292957,
  1483529935,
  471910574,
  1539241949,
  458788160,
  3436315007,
  1807016891,
  3718408830,
  978976581,
  1043663428,
  3165965781,
  1927990952,
  4200891579,
  2372276910,
  3208408903,
  3533431907,
  1412390302,
  2931980059,
  4132332400,
  1947078029,
  3881505623,
  4168226417,
  2941484381,
  1077988104,
  1320477388,
  886195818,
  18198404,
  3786409e3,
  2509781533,
  112762804,
  3463356488,
  1866414978,
  891333506,
  18488651,
  661792760,
  1628790961,
  3885187036,
  3141171499,
  876946877,
  2693282273,
  1372485963,
  791857591,
  2686433993,
  3759982718,
  3167212022,
  3472953795,
  2716379847,
  445679433,
  3561995674,
  3504004811,
  3574258232,
  54117162,
  3331405415,
  2381918588,
  3769707343,
  4154350007,
  1140177722,
  4074052095,
  668550556,
  3214352940,
  367459370,
  261225585,
  2610173221,
  4209349473,
  3468074219,
  3265815641,
  314222801,
  3066103646,
  3808782860,
  282218597,
  3406013506,
  3773591054,
  379116347,
  1285071038,
  846784868,
  2669647154,
  3771962079,
  3550491691,
  2305946142,
  453669953,
  1268987020,
  3317592352,
  3279303384,
  3744833421,
  2610507566,
  3859509063,
  266596637,
  3847019092,
  517658769,
  3462560207,
  3443424879,
  370717030,
  4247526661,
  2224018117,
  4143653529,
  4112773975,
  2788324899,
  2477274417,
  1456262402,
  2901442914,
  1517677493,
  1846949527,
  2295493580,
  3734397586,
  2176403920,
  1280348187,
  1908823572,
  3871786941,
  846861322,
  1172426758,
  3287448474,
  3383383037,
  1655181056,
  3139813346,
  901632758,
  1897031941,
  2986607138,
  3066810236,
  3447102507,
  1393639104,
  373351379,
  950779232,
  625454576,
  3124240540,
  4148612726,
  2007998917,
  544563296,
  2244738638,
  2330496472,
  2058025392,
  1291430526,
  424198748,
  50039436,
  29584100,
  3605783033,
  2429876329,
  2791104160,
  1057563949,
  3255363231,
  3075367218,
  3463963227,
  1469046755,
  985887462
];
var C_ORIG = [
  1332899944,
  1700884034,
  1701343084,
  1684370003,
  1668446532,
  1869963892
];
function _encipher(lr, off, P, S) {
  var n, l = lr[off], r = lr[off + 1];
  l ^= P[0];
  n = S[l >>> 24];
  n += S[256 | l >> 16 & 255];
  n ^= S[512 | l >> 8 & 255];
  n += S[768 | l & 255];
  r ^= n ^ P[1];
  n = S[r >>> 24];
  n += S[256 | r >> 16 & 255];
  n ^= S[512 | r >> 8 & 255];
  n += S[768 | r & 255];
  l ^= n ^ P[2];
  n = S[l >>> 24];
  n += S[256 | l >> 16 & 255];
  n ^= S[512 | l >> 8 & 255];
  n += S[768 | l & 255];
  r ^= n ^ P[3];
  n = S[r >>> 24];
  n += S[256 | r >> 16 & 255];
  n ^= S[512 | r >> 8 & 255];
  n += S[768 | r & 255];
  l ^= n ^ P[4];
  n = S[l >>> 24];
  n += S[256 | l >> 16 & 255];
  n ^= S[512 | l >> 8 & 255];
  n += S[768 | l & 255];
  r ^= n ^ P[5];
  n = S[r >>> 24];
  n += S[256 | r >> 16 & 255];
  n ^= S[512 | r >> 8 & 255];
  n += S[768 | r & 255];
  l ^= n ^ P[6];
  n = S[l >>> 24];
  n += S[256 | l >> 16 & 255];
  n ^= S[512 | l >> 8 & 255];
  n += S[768 | l & 255];
  r ^= n ^ P[7];
  n = S[r >>> 24];
  n += S[256 | r >> 16 & 255];
  n ^= S[512 | r >> 8 & 255];
  n += S[768 | r & 255];
  l ^= n ^ P[8];
  n = S[l >>> 24];
  n += S[256 | l >> 16 & 255];
  n ^= S[512 | l >> 8 & 255];
  n += S[768 | l & 255];
  r ^= n ^ P[9];
  n = S[r >>> 24];
  n += S[256 | r >> 16 & 255];
  n ^= S[512 | r >> 8 & 255];
  n += S[768 | r & 255];
  l ^= n ^ P[10];
  n = S[l >>> 24];
  n += S[256 | l >> 16 & 255];
  n ^= S[512 | l >> 8 & 255];
  n += S[768 | l & 255];
  r ^= n ^ P[11];
  n = S[r >>> 24];
  n += S[256 | r >> 16 & 255];
  n ^= S[512 | r >> 8 & 255];
  n += S[768 | r & 255];
  l ^= n ^ P[12];
  n = S[l >>> 24];
  n += S[256 | l >> 16 & 255];
  n ^= S[512 | l >> 8 & 255];
  n += S[768 | l & 255];
  r ^= n ^ P[13];
  n = S[r >>> 24];
  n += S[256 | r >> 16 & 255];
  n ^= S[512 | r >> 8 & 255];
  n += S[768 | r & 255];
  l ^= n ^ P[14];
  n = S[l >>> 24];
  n += S[256 | l >> 16 & 255];
  n ^= S[512 | l >> 8 & 255];
  n += S[768 | l & 255];
  r ^= n ^ P[15];
  n = S[r >>> 24];
  n += S[256 | r >> 16 & 255];
  n ^= S[512 | r >> 8 & 255];
  n += S[768 | r & 255];
  l ^= n ^ P[16];
  lr[off] = r ^ P[BLOWFISH_NUM_ROUNDS + 1];
  lr[off + 1] = l;
  return lr;
}
function _streamtoword(data, offp) {
  for (var i = 0, word = 0; i < 4; ++i)
    word = word << 8 | data[offp] & 255, offp = (offp + 1) % data.length;
  return { key: word, offp };
}
function _key(key, P, S) {
  var offset = 0, lr = [0, 0], plen = P.length, slen = S.length, sw;
  for (var i = 0; i < plen; i++)
    sw = _streamtoword(key, offset), offset = sw.offp, P[i] = P[i] ^ sw.key;
  for (i = 0; i < plen; i += 2)
    lr = _encipher(lr, 0, P, S), P[i] = lr[0], P[i + 1] = lr[1];
  for (i = 0; i < slen; i += 2)
    lr = _encipher(lr, 0, P, S), S[i] = lr[0], S[i + 1] = lr[1];
}
function _ekskey(data, key, P, S) {
  var offp = 0, lr = [0, 0], plen = P.length, slen = S.length, sw;
  for (var i = 0; i < plen; i++)
    sw = _streamtoword(key, offp), offp = sw.offp, P[i] = P[i] ^ sw.key;
  offp = 0;
  for (i = 0; i < plen; i += 2)
    sw = _streamtoword(data, offp), offp = sw.offp, lr[0] ^= sw.key, sw = _streamtoword(data, offp), offp = sw.offp, lr[1] ^= sw.key, lr = _encipher(lr, 0, P, S), P[i] = lr[0], P[i + 1] = lr[1];
  for (i = 0; i < slen; i += 2)
    sw = _streamtoword(data, offp), offp = sw.offp, lr[0] ^= sw.key, sw = _streamtoword(data, offp), offp = sw.offp, lr[1] ^= sw.key, lr = _encipher(lr, 0, P, S), S[i] = lr[0], S[i + 1] = lr[1];
}
function _crypt(b, salt, rounds, callback, progressCallback) {
  var cdata = C_ORIG.slice(), clen = cdata.length, err;
  if (rounds < 4 || rounds > 31) {
    err = Error("Illegal number of rounds (4-31): " + rounds);
    if (callback) {
      nextTick(callback.bind(this, err));
      return;
    } else throw err;
  }
  if (salt.length !== BCRYPT_SALT_LEN) {
    err = Error(
      "Illegal salt length: " + salt.length + " != " + BCRYPT_SALT_LEN
    );
    if (callback) {
      nextTick(callback.bind(this, err));
      return;
    } else throw err;
  }
  rounds = 1 << rounds >>> 0;
  var P, S, i = 0, j;
  if (typeof Int32Array === "function") {
    P = new Int32Array(P_ORIG);
    S = new Int32Array(S_ORIG);
  } else {
    P = P_ORIG.slice();
    S = S_ORIG.slice();
  }
  _ekskey(salt, b, P, S);
  function next() {
    if (progressCallback) progressCallback(i / rounds);
    if (i < rounds) {
      var start = Date.now();
      for (; i < rounds; ) {
        i = i + 1;
        _key(b, P, S);
        _key(salt, P, S);
        if (Date.now() - start > MAX_EXECUTION_TIME) break;
      }
    } else {
      for (i = 0; i < 64; i++)
        for (j = 0; j < clen >> 1; j++) _encipher(cdata, j << 1, P, S);
      var ret = [];
      for (i = 0; i < clen; i++)
        ret.push((cdata[i] >> 24 & 255) >>> 0), ret.push((cdata[i] >> 16 & 255) >>> 0), ret.push((cdata[i] >> 8 & 255) >>> 0), ret.push((cdata[i] & 255) >>> 0);
      if (callback) {
        callback(null, ret);
        return;
      } else return ret;
    }
    if (callback) nextTick(next);
  }
  if (typeof callback !== "undefined") {
    next();
  } else {
    var res;
    while (true) if (typeof (res = next()) !== "undefined") return res || [];
  }
}
function _hash(password, salt, callback, progressCallback) {
  var err;
  if (typeof password !== "string" || typeof salt !== "string") {
    err = Error("Invalid string / salt: Not a string");
    if (callback) {
      nextTick(callback.bind(this, err));
      return;
    } else throw err;
  }
  var minor, offset;
  if (salt.charAt(0) !== "$" || salt.charAt(1) !== "2") {
    err = Error("Invalid salt version: " + salt.substring(0, 2));
    if (callback) {
      nextTick(callback.bind(this, err));
      return;
    } else throw err;
  }
  if (salt.charAt(2) === "$") minor = String.fromCharCode(0), offset = 3;
  else {
    minor = salt.charAt(2);
    if (minor !== "a" && minor !== "b" && minor !== "y" || salt.charAt(3) !== "$") {
      err = Error("Invalid salt revision: " + salt.substring(2, 4));
      if (callback) {
        nextTick(callback.bind(this, err));
        return;
      } else throw err;
    }
    offset = 4;
  }
  if (salt.charAt(offset + 2) > "$") {
    err = Error("Missing salt rounds");
    if (callback) {
      nextTick(callback.bind(this, err));
      return;
    } else throw err;
  }
  var r1 = parseInt(salt.substring(offset, offset + 1), 10) * 10, r2 = parseInt(salt.substring(offset + 1, offset + 2), 10), rounds = r1 + r2, real_salt = salt.substring(offset + 3, offset + 25);
  password += minor >= "a" ? "\0" : "";
  var passwordb = utf8Array(password), saltb = base64_decode(real_salt, BCRYPT_SALT_LEN);
  function finish(bytes) {
    var res = [];
    res.push("$2");
    if (minor >= "a") res.push(minor);
    res.push("$");
    if (rounds < 10) res.push("0");
    res.push(rounds.toString());
    res.push("$");
    res.push(base64_encode(saltb, saltb.length));
    res.push(base64_encode(bytes, C_ORIG.length * 4 - 1));
    return res.join("");
  }
  if (typeof callback == "undefined")
    return finish(_crypt(passwordb, saltb, rounds));
  else {
    _crypt(
      passwordb,
      saltb,
      rounds,
      function(err2, bytes) {
        if (err2) callback(err2, null);
        else callback(null, finish(bytes));
      },
      progressCallback
    );
  }
}
function encodeBase64(bytes, length) {
  return base64_encode(bytes, length);
}
function decodeBase64(string, length) {
  return base64_decode(string, length);
}
var bcryptjs_default = {
  setRandomFallback,
  genSaltSync,
  genSalt,
  hashSync,
  hash,
  compareSync,
  compare,
  getRounds,
  getSalt,
  truncates,
  encodeBase64,
  decodeBase64
};

// site/server/source/server/game-errors.ts
var GameError = class extends Error {
  constructor(code, status = 400, field) {
    super(code);
    this.code = code;
    this.status = status;
    this.field = field;
  }
};

// site/server/source/db/game.ts
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
var database;
function openGameDatabase(path, migrations) {
  const sqlite = new DatabaseSync(path);
  sqlite.exec("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;");
  sqlite.exec("CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, sha256 TEXT NOT NULL)");
  for (const name of readdirSync(migrations).filter((x) => x.endsWith(".sql")).sort()) {
    const sql = readFileSync(`${migrations}/${name}`, "utf8"), hash2 = createHash("sha256").update(sql).digest("hex");
    const applied = sqlite.prepare("SELECT sha256 FROM schema_migrations WHERE name=?").get(name);
    if (applied) {
      if (applied.sha256 !== hash2) throw new Error("An applied migration was modified");
      continue;
    }
    sqlite.exec("BEGIN IMMEDIATE");
    try {
      sqlite.exec(sql);
      sqlite.prepare("INSERT INTO schema_migrations VALUES (?,?)").run(name, hash2);
      sqlite.exec("COMMIT");
    } catch (e) {
      sqlite.exec("ROLLBACK");
      sqlite.close();
      throw e;
    }
  }
  class Statement {
    constructor(sql, args = []) {
      this.sql = sql;
      this.args = args;
    }
    bind(...args) {
      return new Statement(this.sql, args);
    }
    first(column) {
      const value = sqlite.prepare(this.sql).get(...this.args) || null;
      return Promise.resolve(column && value ? value[column] : value);
    }
    all() {
      return Promise.resolve({ results: sqlite.prepare(this.sql).all(...this.args) });
    }
    execute() {
      const result = sqlite.prepare(this.sql).run(...this.args);
      return { success: true, results: [], meta: { changes: Number(result.changes), last_row_id: Number(result.lastInsertRowid) } };
    }
    run() {
      return Promise.resolve(this.execute());
    }
  }
  return { sqlite, prepare: (sql) => new Statement(sql), batch: async (statements) => {
    sqlite.exec("BEGIN IMMEDIATE");
    try {
      const result = statements.map((s) => s.execute());
      sqlite.exec("COMMIT");
      return result;
    } catch (e) {
      sqlite.exec("ROLLBACK");
      throw e;
    }
  } };
}
function initGameDatabase(path, migrations) {
  database = openGameDatabase(path, migrations);
  return database;
}
function gameDb() {
  if (!database) throw new Error("Game database is unavailable");
  return database;
}
function gameConfig() {
  const pepper = process.env.AUTH_PEPPER, origin = process.env.SITE_ORIGIN;
  if (!pepper || pepper.length < 32 || !origin || !/^https:\/\/[a-z0-9.-]+$/.test(origin)) throw new Error("Game authentication is unavailable");
  return { pepper, origin };
}

// site/server/source/app/catalog.json
var catalog_default = [
  {
    id: 1,
    slug: "bulbasaur",
    name: {
      ru: "\u0411\u0443\u043B\u044C\u0431\u0430\u0437\u0430\u0432\u0440",
      en: "Bulbasaur"
    },
    genus: {
      ru: "\u0421\u0435\u043C\u0435\u043D\u043D\u043E\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Seed Pok\xE9mon"
    },
    description: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D \u0441 \u0441\u0435\u043C\u0435\u043D\u0435\u043C \u043D\u0430 \u0441\u043F\u0438\u043D\u0435. \u0412 \u043F\u0435\u0440\u0432\u044B\u0435 \u043C\u0435\u0441\u044F\u0446\u044B \u0436\u0438\u0437\u043D\u0438 \u0437\u0430\u043F\u0430\u0441 \u043F\u0438\u0442\u0430\u0442\u0435\u043B\u044C\u043D\u044B\u0445 \u0432\u0435\u0449\u0435\u0441\u0442\u0432 \u0432 \u0441\u0435\u043C\u0435\u043D\u0438 \u043F\u043E\u043C\u043E\u0433\u0430\u0435\u0442 \u0435\u043C\u0443 \u0440\u0430\u0441\u0442\u0438.",
      en: "A seed grows on its back. Stored nutrients support Bulbasaur during its early life."
    },
    habitat: "grassland",
    types: [
      "grass",
      "poison"
    ],
    height: 0.7,
    weight: 6.9,
    stats: [
      45,
      49,
      49,
      65,
      65,
      45
    ],
    abilities: [
      {
        id: 65,
        slug: "overgrow",
        name: {
          ru: "\u0420\u0430\u0437\u0440\u0430\u0441\u0442\u0430\u043D\u0438\u0435",
          en: "Overgrow"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0442\u0440\u0430\u0432\u044F\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438, \u043A\u043E\u0433\u0434\u0430 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043D\u0438\u0437\u043A\u043E\u0435.",
          en: "Boosts Grass moves when HP is low."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/65/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 34,
        slug: "chlorophyll",
        name: {
          ru: "\u0425\u043B\u043E\u0440\u043E\u0444\u0438\u043B\u043B",
          en: "Chlorophyll"
        },
        description: {
          ru: "\u0423\u0434\u0432\u0430\u0438\u0432\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u0440\u0438 \u044F\u0440\u043A\u043E\u043C \u0441\u043E\u043B\u043D\u0435\u0447\u043D\u043E\u043C \u0441\u0432\u0435\u0442\u0435.",
          en: "Doubles Speed in strong sunlight."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/34/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 22,
        slug: "vine-whip",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043B\u043E\u0437\u043E\u0439",
          en: "Vine Whip"
        },
        description: {
          ru: "\u0425\u043B\u0435\u0449\u0435\u0442 \u0446\u0435\u043B\u044C \u0433\u0438\u0431\u043A\u0438\u043C\u0438 \u0440\u0430\u0441\u0442\u0438\u0442\u0435\u043B\u044C\u043D\u044B\u043C\u0438 \u043B\u043E\u0437\u0430\u043C\u0438.",
          en: "Whips the target with flexible vines."
        },
        type: "grass",
        power: 45,
        accuracy: 100,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/22/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/1/"
        }
      },
      {
        id: 75,
        slug: "razor-leaf",
        name: {
          ru: "\u041E\u0441\u0442\u0440\u044B\u0435 \u043B\u0438\u0441\u0442\u044C\u044F",
          en: "Razor Leaf"
        },
        description: {
          ru: "\u0411\u0440\u043E\u0441\u0430\u0435\u0442 \u043E\u0441\u0442\u0440\u044B\u0435 \u043B\u0438\u0441\u0442\u044C\u044F; \u0448\u0430\u043D\u0441 \u043A\u0440\u0438\u0442\u0438\u0447\u0435\u0441\u043A\u043E\u0433\u043E \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u044F \u0432\u044B\u0448\u0435.",
          en: "Throws sharp leaves with an increased critical-hit chance."
        },
        type: "grass",
        power: 55,
        accuracy: 95,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/75/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 1,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/1/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 1,
          name: {
            ru: "\u0411\u0443\u043B\u044C\u0431\u0430\u0437\u0430\u0432\u0440",
            en: "Bulbasaur"
          }
        },
        {
          id: 2,
          name: {
            ru: "\u0418\u0432\u0438\u0437\u0430\u0432\u0440",
            en: "Ivysaur"
          }
        },
        {
          id: 3,
          name: {
            ru: "\u0412\u0435\u043D\u0443\u0437\u0430\u0432\u0440",
            en: "Venusaur"
          }
        }
      ],
      edges: [
        {
          from: 1,
          to: 2,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 16",
            en: "Level 16"
          },
          isDefault: true
        },
        {
          from: 2,
          to: 3,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 32",
            en: "Level 32"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 2,
    slug: "ivysaur",
    name: {
      ru: "\u0418\u0432\u0438\u0437\u0430\u0432\u0440",
      en: "Ivysaur"
    },
    genus: {
      ru: "\u0421\u0435\u043C\u0435\u043D\u043D\u043E\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Seed Pok\xE9mon"
    },
    description: {
      ru: "\u0421\u043E\u043B\u043D\u0435\u0447\u043D\u044B\u0439 \u0441\u0432\u0435\u0442 \u043F\u0440\u0438\u0434\u0430\u0451\u0442 \u0435\u043C\u0443 \u0441\u0438\u043B\u044B \u0438 \u043F\u043E\u043C\u043E\u0433\u0430\u0435\u0442 \u0431\u0443\u0442\u043E\u043D\u0443 \u043D\u0430 \u0441\u043F\u0438\u043D\u0435 \u0440\u0430\u0441\u0442\u0438.",
      en: "Sunlight strengthens Ivysaur and nourishes the growing bud on its back."
    },
    habitat: "grassland",
    types: [
      "grass",
      "poison"
    ],
    height: 1,
    weight: 13,
    stats: [
      60,
      62,
      63,
      80,
      80,
      60
    ],
    abilities: [
      {
        id: 65,
        slug: "overgrow",
        name: {
          ru: "\u0420\u0430\u0437\u0440\u0430\u0441\u0442\u0430\u043D\u0438\u0435",
          en: "Overgrow"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0442\u0440\u0430\u0432\u044F\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438, \u043A\u043E\u0433\u0434\u0430 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043D\u0438\u0437\u043A\u043E\u0435.",
          en: "Boosts Grass moves when HP is low."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/65/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 34,
        slug: "chlorophyll",
        name: {
          ru: "\u0425\u043B\u043E\u0440\u043E\u0444\u0438\u043B\u043B",
          en: "Chlorophyll"
        },
        description: {
          ru: "\u0423\u0434\u0432\u0430\u0438\u0432\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u0440\u0438 \u044F\u0440\u043A\u043E\u043C \u0441\u043E\u043B\u043D\u0435\u0447\u043D\u043E\u043C \u0441\u0432\u0435\u0442\u0435.",
          en: "Doubles Speed in strong sunlight."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/34/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 75,
        slug: "razor-leaf",
        name: {
          ru: "\u041E\u0441\u0442\u0440\u044B\u0435 \u043B\u0438\u0441\u0442\u044C\u044F",
          en: "Razor Leaf"
        },
        description: {
          ru: "\u0411\u0440\u043E\u0441\u0430\u0435\u0442 \u043E\u0441\u0442\u0440\u044B\u0435 \u043B\u0438\u0441\u0442\u044C\u044F; \u0448\u0430\u043D\u0441 \u043A\u0440\u0438\u0442\u0438\u0447\u0435\u0441\u043A\u043E\u0433\u043E \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u044F \u0432\u044B\u0448\u0435.",
          en: "Throws sharp leaves with an increased critical-hit chance."
        },
        type: "grass",
        power: 55,
        accuracy: 95,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/75/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 1,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/2/"
        }
      },
      {
        id: 22,
        slug: "vine-whip",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043B\u043E\u0437\u043E\u0439",
          en: "Vine Whip"
        },
        description: {
          ru: "\u0425\u043B\u0435\u0449\u0435\u0442 \u0446\u0435\u043B\u044C \u0433\u0438\u0431\u043A\u0438\u043C\u0438 \u0440\u0430\u0441\u0442\u0438\u0442\u0435\u043B\u044C\u043D\u044B\u043C\u0438 \u043B\u043E\u0437\u0430\u043C\u0438.",
          en: "Whips the target with flexible vines."
        },
        type: "grass",
        power: 45,
        accuracy: 100,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/22/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/2/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 1,
          name: {
            ru: "\u0411\u0443\u043B\u044C\u0431\u0430\u0437\u0430\u0432\u0440",
            en: "Bulbasaur"
          }
        },
        {
          id: 2,
          name: {
            ru: "\u0418\u0432\u0438\u0437\u0430\u0432\u0440",
            en: "Ivysaur"
          }
        },
        {
          id: 3,
          name: {
            ru: "\u0412\u0435\u043D\u0443\u0437\u0430\u0432\u0440",
            en: "Venusaur"
          }
        }
      ],
      edges: [
        {
          from: 1,
          to: 2,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 16",
            en: "Level 16"
          },
          isDefault: true
        },
        {
          from: 2,
          to: 3,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 32",
            en: "Level 32"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 3,
    slug: "venusaur",
    name: {
      ru: "\u0412\u0435\u043D\u0443\u0437\u0430\u0432\u0440",
      en: "Venusaur"
    },
    genus: {
      ru: "\u0421\u0435\u043C\u0435\u043D\u043D\u043E\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Seed Pok\xE9mon"
    },
    description: {
      ru: "\u0410\u0440\u043E\u043C\u0430\u0442 \u0431\u043E\u043B\u044C\u0448\u043E\u0433\u043E \u0446\u0432\u0435\u0442\u043A\u0430 \u0443\u0441\u043F\u043E\u043A\u0430\u0438\u0432\u0430\u0435\u0442 \u0442\u0435\u0445, \u043A\u0442\u043E \u0432\u0441\u0442\u0443\u043F\u0438\u043B \u0432 \u0441\u0445\u0432\u0430\u0442\u043A\u0443.",
      en: "The scent of its large flower can soothe those caught in a battle."
    },
    habitat: "grassland",
    types: [
      "grass",
      "poison"
    ],
    height: 2,
    weight: 100,
    stats: [
      80,
      82,
      83,
      100,
      100,
      80
    ],
    abilities: [
      {
        id: 65,
        slug: "overgrow",
        name: {
          ru: "\u0420\u0430\u0437\u0440\u0430\u0441\u0442\u0430\u043D\u0438\u0435",
          en: "Overgrow"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0442\u0440\u0430\u0432\u044F\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438, \u043A\u043E\u0433\u0434\u0430 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043D\u0438\u0437\u043A\u043E\u0435.",
          en: "Boosts Grass moves when HP is low."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/65/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 34,
        slug: "chlorophyll",
        name: {
          ru: "\u0425\u043B\u043E\u0440\u043E\u0444\u0438\u043B\u043B",
          en: "Chlorophyll"
        },
        description: {
          ru: "\u0423\u0434\u0432\u0430\u0438\u0432\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u0440\u0438 \u044F\u0440\u043A\u043E\u043C \u0441\u043E\u043B\u043D\u0435\u0447\u043D\u043E\u043C \u0441\u0432\u0435\u0442\u0435.",
          en: "Doubles Speed in strong sunlight."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/34/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 75,
        slug: "razor-leaf",
        name: {
          ru: "\u041E\u0441\u0442\u0440\u044B\u0435 \u043B\u0438\u0441\u0442\u044C\u044F",
          en: "Razor Leaf"
        },
        description: {
          ru: "\u0411\u0440\u043E\u0441\u0430\u0435\u0442 \u043E\u0441\u0442\u0440\u044B\u0435 \u043B\u0438\u0441\u0442\u044C\u044F; \u0448\u0430\u043D\u0441 \u043A\u0440\u0438\u0442\u0438\u0447\u0435\u0441\u043A\u043E\u0433\u043E \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u044F \u0432\u044B\u0448\u0435.",
          en: "Throws sharp leaves with an increased critical-hit chance."
        },
        type: "grass",
        power: 55,
        accuracy: 95,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/75/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 1,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/3/"
        }
      },
      {
        id: 22,
        slug: "vine-whip",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043B\u043E\u0437\u043E\u0439",
          en: "Vine Whip"
        },
        description: {
          ru: "\u0425\u043B\u0435\u0449\u0435\u0442 \u0446\u0435\u043B\u044C \u0433\u0438\u0431\u043A\u0438\u043C\u0438 \u0440\u0430\u0441\u0442\u0438\u0442\u0435\u043B\u044C\u043D\u044B\u043C\u0438 \u043B\u043E\u0437\u0430\u043C\u0438.",
          en: "Whips the target with flexible vines."
        },
        type: "grass",
        power: 45,
        accuracy: 100,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/22/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/3/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 1,
          name: {
            ru: "\u0411\u0443\u043B\u044C\u0431\u0430\u0437\u0430\u0432\u0440",
            en: "Bulbasaur"
          }
        },
        {
          id: 2,
          name: {
            ru: "\u0418\u0432\u0438\u0437\u0430\u0432\u0440",
            en: "Ivysaur"
          }
        },
        {
          id: 3,
          name: {
            ru: "\u0412\u0435\u043D\u0443\u0437\u0430\u0432\u0440",
            en: "Venusaur"
          }
        }
      ],
      edges: [
        {
          from: 1,
          to: 2,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 16",
            en: "Level 16"
          },
          isDefault: true
        },
        {
          from: 2,
          to: 3,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 32",
            en: "Level 32"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 4,
    slug: "charmander",
    name: {
      ru: "\u0427\u0430\u0440\u043C\u0430\u043D\u0434\u0435\u0440",
      en: "Charmander"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u044F\u0449\u0435\u0440\u0438\u0446\u0430",
      en: "Lizard Pok\xE9mon"
    },
    description: {
      ru: "\u041E\u0433\u043E\u043D\u0451\u043A \u043D\u0430 \u043A\u043E\u043D\u0447\u0438\u043A\u0435 \u0445\u0432\u043E\u0441\u0442\u0430 \u0433\u043E\u0440\u0438\u0442 \u0441 \u0440\u043E\u0436\u0434\u0435\u043D\u0438\u044F. \u0415\u0433\u043E \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u0435 \u0441\u0432\u044F\u0437\u0430\u043D\u043E \u0441 \u0436\u0438\u0437\u043D\u0435\u043D\u043D\u043E\u0439 \u0441\u0438\u043B\u043E\u0439 \u0427\u0430\u0440\u043C\u0430\u043D\u0434\u0435\u0440\u0430.",
      en: "A flame has burned at the tip of its tail since birth. Its condition reflects Charmander\u2019s vitality."
    },
    habitat: "mountain",
    types: [
      "fire"
    ],
    height: 0.6,
    weight: 8.5,
    stats: [
      39,
      52,
      43,
      60,
      50,
      65
    ],
    abilities: [
      {
        id: 66,
        slug: "blaze",
        name: {
          ru: "\u041F\u043B\u0430\u043C\u044F",
          en: "Blaze"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u043E\u0433\u043D\u0435\u043D\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438, \u043A\u043E\u0433\u0434\u0430 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043D\u0438\u0437\u043A\u043E\u0435.",
          en: "Boosts Fire moves when HP is low."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/66/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 94,
        slug: "solar-power",
        name: {
          ru: "\u0421\u043E\u043B\u043D\u0435\u0447\u043D\u0430\u044F \u0441\u0438\u043B\u0430",
          en: "Solar Power"
        },
        description: {
          ru: "\u041D\u0430 \u0441\u043E\u043B\u043D\u0446\u0435 \u0443\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443, \u0440\u0430\u0441\u0445\u043E\u0434\u0443\u044F \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435.",
          en: "Sunlight boosts Special Attack at the cost of some HP."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/94/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 52,
        slug: "ember",
        name: {
          ru: "\u0418\u0441\u043A\u0440\u044B",
          en: "Ember"
        },
        description: {
          ru: "\u041F\u043E\u0442\u043E\u043A \u043C\u0430\u043B\u0435\u043D\u044C\u043A\u0438\u0445 \u044F\u0437\u044B\u043A\u043E\u0432 \u043F\u043B\u0430\u043C\u0435\u043D\u0438 \u043C\u043E\u0436\u0435\u0442 \u0432\u044B\u0437\u0432\u0430\u0442\u044C \u043E\u0436\u043E\u0433.",
          en: "A burst of small flames may burn the target."
        },
        type: "fire",
        power: 40,
        accuracy: 100,
        pp: 25,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/52/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/4/"
        }
      },
      {
        id: 53,
        slug: "flamethrower",
        name: {
          ru: "\u041E\u0433\u043D\u0435\u043C\u0451\u0442",
          en: "Flamethrower"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u0441\u0438\u043B\u044C\u043D\u0443\u044E \u0441\u0442\u0440\u0443\u044E \u043F\u043B\u0430\u043C\u0435\u043D\u0438; \u043C\u043E\u0436\u0435\u0442 \u0432\u044B\u0437\u0432\u0430\u0442\u044C \u043E\u0436\u043E\u0433.",
          en: "Unleashes a powerful stream of fire that may cause a burn."
        },
        type: "fire",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/53/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/4/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 4,
          name: {
            ru: "\u0427\u0430\u0440\u043C\u0430\u043D\u0434\u0435\u0440",
            en: "Charmander"
          }
        },
        {
          id: 5,
          name: {
            ru: "\u0427\u0430\u0440\u043C\u0438\u043B\u0438\u043E\u043D",
            en: "Charmeleon"
          }
        },
        {
          id: 6,
          name: {
            ru: "\u0427\u0430\u0440\u0438\u0437\u0430\u0440\u0434",
            en: "Charizard"
          }
        }
      ],
      edges: [
        {
          from: 4,
          to: 5,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 16",
            en: "Level 16"
          },
          isDefault: true
        },
        {
          from: 5,
          to: 6,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 36",
            en: "Level 36"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 5,
    slug: "charmeleon",
    name: {
      ru: "\u0427\u0430\u0440\u043C\u0438\u043B\u0438\u043E\u043D",
      en: "Charmeleon"
    },
    genus: {
      ru: "\u041F\u043B\u0430\u043C\u0435\u043D\u043D\u044B\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Flame Pok\xE9mon"
    },
    description: {
      ru: "\u0412 \u0440\u0430\u0437\u0433\u0430\u0440 \u0431\u043E\u044F \u0432\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u043D\u0430\u0441\u0442\u043E\u043B\u044C\u043A\u043E \u0441\u0438\u043B\u044C\u043D\u043E\u0435 \u043F\u043B\u0430\u043C\u044F, \u0447\u0442\u043E \u043C\u043E\u0436\u0435\u0442 \u043E\u043F\u0430\u043B\u0438\u0442\u044C \u0432\u0441\u0451 \u0432\u043E\u043A\u0440\u0443\u0433.",
      en: "An agitated Charmeleon releases flames fierce enough to scorch its surroundings."
    },
    habitat: "mountain",
    types: [
      "fire"
    ],
    height: 1.1,
    weight: 19,
    stats: [
      58,
      64,
      58,
      80,
      65,
      80
    ],
    abilities: [
      {
        id: 66,
        slug: "blaze",
        name: {
          ru: "\u041F\u043B\u0430\u043C\u044F",
          en: "Blaze"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u043E\u0433\u043D\u0435\u043D\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438, \u043A\u043E\u0433\u0434\u0430 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043D\u0438\u0437\u043A\u043E\u0435.",
          en: "Boosts Fire moves when HP is low."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/66/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 94,
        slug: "solar-power",
        name: {
          ru: "\u0421\u043E\u043B\u043D\u0435\u0447\u043D\u0430\u044F \u0441\u0438\u043B\u0430",
          en: "Solar Power"
        },
        description: {
          ru: "\u041D\u0430 \u0441\u043E\u043B\u043D\u0446\u0435 \u0443\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443, \u0440\u0430\u0441\u0445\u043E\u0434\u0443\u044F \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435.",
          en: "Sunlight boosts Special Attack at the cost of some HP."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/94/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 53,
        slug: "flamethrower",
        name: {
          ru: "\u041E\u0433\u043D\u0435\u043C\u0451\u0442",
          en: "Flamethrower"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u0441\u0438\u043B\u044C\u043D\u0443\u044E \u0441\u0442\u0440\u0443\u044E \u043F\u043B\u0430\u043C\u0435\u043D\u0438; \u043C\u043E\u0436\u0435\u0442 \u0432\u044B\u0437\u0432\u0430\u0442\u044C \u043E\u0436\u043E\u0433.",
          en: "Unleashes a powerful stream of fire that may cause a burn."
        },
        type: "fire",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/53/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/5/"
        }
      },
      {
        id: 52,
        slug: "ember",
        name: {
          ru: "\u0418\u0441\u043A\u0440\u044B",
          en: "Ember"
        },
        description: {
          ru: "\u041F\u043E\u0442\u043E\u043A \u043C\u0430\u043B\u0435\u043D\u044C\u043A\u0438\u0445 \u044F\u0437\u044B\u043A\u043E\u0432 \u043F\u043B\u0430\u043C\u0435\u043D\u0438 \u043C\u043E\u0436\u0435\u0442 \u0432\u044B\u0437\u0432\u0430\u0442\u044C \u043E\u0436\u043E\u0433.",
          en: "A burst of small flames may burn the target."
        },
        type: "fire",
        power: 40,
        accuracy: 100,
        pp: 25,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/52/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/5/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 4,
          name: {
            ru: "\u0427\u0430\u0440\u043C\u0430\u043D\u0434\u0435\u0440",
            en: "Charmander"
          }
        },
        {
          id: 5,
          name: {
            ru: "\u0427\u0430\u0440\u043C\u0438\u043B\u0438\u043E\u043D",
            en: "Charmeleon"
          }
        },
        {
          id: 6,
          name: {
            ru: "\u0427\u0430\u0440\u0438\u0437\u0430\u0440\u0434",
            en: "Charizard"
          }
        }
      ],
      edges: [
        {
          from: 4,
          to: 5,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 16",
            en: "Level 16"
          },
          isDefault: true
        },
        {
          from: 5,
          to: 6,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 36",
            en: "Level 36"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 6,
    slug: "charizard",
    name: {
      ru: "\u0427\u0430\u0440\u0438\u0437\u0430\u0440\u0434",
      en: "Charizard"
    },
    genus: {
      ru: "\u041F\u043B\u0430\u043C\u0435\u043D\u043D\u044B\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Flame Pok\xE9mon"
    },
    description: {
      ru: "\u041C\u043E\u0449\u043D\u044B\u0435 \u043A\u0440\u044B\u043B\u044C\u044F \u043F\u043E\u0434\u043D\u0438\u043C\u0430\u044E\u0442 \u0435\u0433\u043E \u0432\u044B\u0441\u043E\u043A\u043E \u0432 \u043D\u0435\u0431\u043E. \u0414\u044B\u0445\u0430\u043D\u0438\u0435 \u0427\u0430\u0440\u0438\u0437\u0430\u0440\u0434\u0430 \u043E\u0431\u0436\u0438\u0433\u0430\u0435\u0442 \u0440\u0430\u0441\u043A\u0430\u043B\u0451\u043D\u043D\u044B\u043C \u043F\u043B\u0430\u043C\u0435\u043D\u0435\u043C.",
      en: "Powerful wings lift Charizard high into the sky, where it breathes intensely hot fire."
    },
    habitat: "mountain",
    types: [
      "fire",
      "flying"
    ],
    height: 1.7,
    weight: 90.5,
    stats: [
      78,
      84,
      78,
      109,
      85,
      100
    ],
    abilities: [
      {
        id: 66,
        slug: "blaze",
        name: {
          ru: "\u041F\u043B\u0430\u043C\u044F",
          en: "Blaze"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u043E\u0433\u043D\u0435\u043D\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438, \u043A\u043E\u0433\u0434\u0430 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043D\u0438\u0437\u043A\u043E\u0435.",
          en: "Boosts Fire moves when HP is low."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/66/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 94,
        slug: "solar-power",
        name: {
          ru: "\u0421\u043E\u043B\u043D\u0435\u0447\u043D\u0430\u044F \u0441\u0438\u043B\u0430",
          en: "Solar Power"
        },
        description: {
          ru: "\u041D\u0430 \u0441\u043E\u043B\u043D\u0446\u0435 \u0443\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443, \u0440\u0430\u0441\u0445\u043E\u0434\u0443\u044F \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435.",
          en: "Sunlight boosts Special Attack at the cost of some HP."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/94/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 53,
        slug: "flamethrower",
        name: {
          ru: "\u041E\u0433\u043D\u0435\u043C\u0451\u0442",
          en: "Flamethrower"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u0441\u0438\u043B\u044C\u043D\u0443\u044E \u0441\u0442\u0440\u0443\u044E \u043F\u043B\u0430\u043C\u0435\u043D\u0438; \u043C\u043E\u0436\u0435\u0442 \u0432\u044B\u0437\u0432\u0430\u0442\u044C \u043E\u0436\u043E\u0433.",
          en: "Unleashes a powerful stream of fire that may cause a burn."
        },
        type: "fire",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/53/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/6/"
        }
      },
      {
        id: 17,
        slug: "wing-attack",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043A\u0440\u044B\u043B\u043E\u043C",
          en: "Wing Attack"
        },
        description: {
          ru: "\u041D\u0430\u043D\u043E\u0441\u0438\u0442 \u0443\u0434\u0430\u0440 \u0448\u0438\u0440\u043E\u043A\u043E \u0440\u0430\u0441\u043A\u0440\u044B\u0442\u044B\u043C\u0438 \u043A\u0440\u044B\u043B\u044C\u044F\u043C\u0438.",
          en: "Strikes the target with outstretched wings."
        },
        type: "flying",
        power: 60,
        accuracy: 100,
        pp: 35,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/17/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/6/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 4,
          name: {
            ru: "\u0427\u0430\u0440\u043C\u0430\u043D\u0434\u0435\u0440",
            en: "Charmander"
          }
        },
        {
          id: 5,
          name: {
            ru: "\u0427\u0430\u0440\u043C\u0438\u043B\u0438\u043E\u043D",
            en: "Charmeleon"
          }
        },
        {
          id: 6,
          name: {
            ru: "\u0427\u0430\u0440\u0438\u0437\u0430\u0440\u0434",
            en: "Charizard"
          }
        }
      ],
      edges: [
        {
          from: 4,
          to: 5,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 16",
            en: "Level 16"
          },
          isDefault: true
        },
        {
          from: 5,
          to: 6,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 36",
            en: "Level 36"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 7,
    slug: "squirtle",
    name: {
      ru: "\u0421\u043A\u0432\u0438\u0440\u0442\u043B",
      en: "Squirtle"
    },
    genus: {
      ru: "\u041C\u0430\u043B\u0435\u043D\u044C\u043A\u0430\u044F \u0447\u0435\u0440\u0435\u043F\u0430\u0445\u0430",
      en: "Tiny Turtle Pok\xE9mon"
    },
    description: {
      ru: "\u041F\u0440\u0438 \u043E\u043F\u0430\u0441\u043D\u043E\u0441\u0442\u0438 \u043F\u0440\u044F\u0447\u0435\u0442\u0441\u044F \u0432 \u043F\u0430\u043D\u0446\u0438\u0440\u044C \u0438 \u0437\u0430\u0449\u0438\u0449\u0430\u0435\u0442\u0441\u044F \u0441\u0442\u0440\u0443\u0451\u0439 \u0432\u043E\u0434\u044B. \u041C\u0430\u043B\u0435\u043D\u044C\u043A\u0438\u0439, \u043D\u043E \u0443\u0432\u0435\u0440\u0435\u043D\u043D\u044B\u0439 \u043F\u043B\u043E\u0432\u0435\u0446.",
      en: "When threatened, Squirtle retreats into its shell and fires a jet of water."
    },
    habitat: "water",
    types: [
      "water"
    ],
    height: 0.5,
    weight: 9,
    stats: [
      44,
      48,
      65,
      50,
      64,
      43
    ],
    abilities: [
      {
        id: 67,
        slug: "torrent",
        name: {
          ru: "\u041F\u043E\u0442\u043E\u043A",
          en: "Torrent"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0432\u043E\u0434\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438, \u043A\u043E\u0433\u0434\u0430 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043D\u0438\u0437\u043A\u043E\u0435.",
          en: "Boosts Water moves when HP is low."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/67/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 44,
        slug: "rain-dish",
        name: {
          ru: "\u0414\u043E\u0436\u0434\u0435\u0432\u0430\u044F \u0447\u0430\u0448\u0430",
          en: "Rain Dish"
        },
        description: {
          ru: "\u041F\u043E\u0441\u0442\u0435\u043F\u0435\u043D\u043D\u043E \u0432\u043E\u0441\u0441\u0442\u0430\u043D\u0430\u0432\u043B\u0438\u0432\u0430\u0435\u0442 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043F\u043E\u0434 \u0434\u043E\u0436\u0434\u0451\u043C.",
          en: "Restores some HP each turn in rain."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/44/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 55,
        slug: "water-gun",
        name: {
          ru: "\u0412\u043E\u0434\u044F\u043D\u0430\u044F \u043F\u0443\u0448\u043A\u0430",
          en: "Water Gun"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u043D\u0430\u043F\u0440\u0430\u0432\u043B\u0435\u043D\u043D\u0443\u044E \u0441\u0442\u0440\u0443\u044E \u0432\u043E\u0434\u044B.",
          en: "Fires a focused jet of water."
        },
        type: "water",
        power: 40,
        accuracy: 100,
        pp: 25,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/55/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/7/"
        }
      },
      {
        id: 352,
        slug: "water-pulse",
        name: {
          ru: "\u0412\u043E\u0434\u043D\u044B\u0439 \u0438\u043C\u043F\u0443\u043B\u044C\u0441",
          en: "Water Pulse"
        },
        description: {
          ru: "\u0412\u043E\u0434\u044F\u043D\u0430\u044F \u0432\u043E\u043B\u043D\u0430 \u043C\u043E\u0436\u0435\u0442 \u043F\u0440\u0438\u0432\u0435\u0441\u0442\u0438 \u0446\u0435\u043B\u044C \u0432 \u0437\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u043E.",
          en: "A pulsing wave of water may confuse the target."
        },
        type: "water",
        power: 60,
        accuracy: 100,
        pp: 20,
        damageClass: "special",
        priority: 0,
        effectChance: 20,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/352/",
        meta: {
          ailment: {
            name: "confusion"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: 2,
          max_turns: 5,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 20,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/7/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 7,
          name: {
            ru: "\u0421\u043A\u0432\u0438\u0440\u0442\u043B",
            en: "Squirtle"
          }
        },
        {
          id: 8,
          name: {
            ru: "\u0412\u0430\u0440\u0442\u043E\u0440\u0442\u043B",
            en: "Wartortle"
          }
        },
        {
          id: 9,
          name: {
            ru: "\u0411\u043B\u0430\u0441\u0442\u043E\u0439\u0437",
            en: "Blastoise"
          }
        }
      ],
      edges: [
        {
          from: 7,
          to: 8,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 16",
            en: "Level 16"
          },
          isDefault: true
        },
        {
          from: 8,
          to: 9,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 36",
            en: "Level 36"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 8,
    slug: "wartortle",
    name: {
      ru: "\u0412\u0430\u0440\u0442\u043E\u0440\u0442\u043B",
      en: "Wartortle"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0447\u0435\u0440\u0435\u043F\u0430\u0445\u0430",
      en: "Turtle Pok\xE9mon"
    },
    description: {
      ru: "\u041F\u0443\u0448\u0438\u0441\u0442\u044B\u0435 \u0443\u0448\u0438 \u0438 \u0445\u0432\u043E\u0441\u0442 \u043F\u043E\u043C\u043E\u0433\u0430\u044E\u0442 \u0435\u043C\u0443 \u0441\u043E\u0445\u0440\u0430\u043D\u044F\u0442\u044C \u0440\u0430\u0432\u043D\u043E\u0432\u0435\u0441\u0438\u0435 \u0432 \u0432\u043E\u0434\u0435.",
      en: "Its furry ears and tail act as balancing aids while it swims."
    },
    habitat: "water",
    types: [
      "water"
    ],
    height: 1,
    weight: 22.5,
    stats: [
      59,
      63,
      80,
      65,
      80,
      58
    ],
    abilities: [
      {
        id: 67,
        slug: "torrent",
        name: {
          ru: "\u041F\u043E\u0442\u043E\u043A",
          en: "Torrent"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0432\u043E\u0434\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438, \u043A\u043E\u0433\u0434\u0430 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043D\u0438\u0437\u043A\u043E\u0435.",
          en: "Boosts Water moves when HP is low."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/67/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 44,
        slug: "rain-dish",
        name: {
          ru: "\u0414\u043E\u0436\u0434\u0435\u0432\u0430\u044F \u0447\u0430\u0448\u0430",
          en: "Rain Dish"
        },
        description: {
          ru: "\u041F\u043E\u0441\u0442\u0435\u043F\u0435\u043D\u043D\u043E \u0432\u043E\u0441\u0441\u0442\u0430\u043D\u0430\u0432\u043B\u0438\u0432\u0430\u0435\u0442 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043F\u043E\u0434 \u0434\u043E\u0436\u0434\u0451\u043C.",
          en: "Restores some HP each turn in rain."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/44/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 57,
        slug: "surf",
        name: {
          ru: "\u0421\u0451\u0440\u0444\u0438\u043D\u0433",
          en: "Surf"
        },
        description: {
          ru: "\u041D\u0430\u043A\u0440\u044B\u0432\u0430\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u0431\u043E\u043B\u044C\u0448\u043E\u0439 \u0432\u043E\u0434\u044F\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Sweeps over opponents with a large wave of water."
        },
        type: "water",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/57/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/8/"
        }
      },
      {
        id: 352,
        slug: "water-pulse",
        name: {
          ru: "\u0412\u043E\u0434\u043D\u044B\u0439 \u0438\u043C\u043F\u0443\u043B\u044C\u0441",
          en: "Water Pulse"
        },
        description: {
          ru: "\u0412\u043E\u0434\u044F\u043D\u0430\u044F \u0432\u043E\u043B\u043D\u0430 \u043C\u043E\u0436\u0435\u0442 \u043F\u0440\u0438\u0432\u0435\u0441\u0442\u0438 \u0446\u0435\u043B\u044C \u0432 \u0437\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u043E.",
          en: "A pulsing wave of water may confuse the target."
        },
        type: "water",
        power: 60,
        accuracy: 100,
        pp: 20,
        damageClass: "special",
        priority: 0,
        effectChance: 20,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/352/",
        meta: {
          ailment: {
            name: "confusion"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: 2,
          max_turns: 5,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 20,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/8/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 7,
          name: {
            ru: "\u0421\u043A\u0432\u0438\u0440\u0442\u043B",
            en: "Squirtle"
          }
        },
        {
          id: 8,
          name: {
            ru: "\u0412\u0430\u0440\u0442\u043E\u0440\u0442\u043B",
            en: "Wartortle"
          }
        },
        {
          id: 9,
          name: {
            ru: "\u0411\u043B\u0430\u0441\u0442\u043E\u0439\u0437",
            en: "Blastoise"
          }
        }
      ],
      edges: [
        {
          from: 7,
          to: 8,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 16",
            en: "Level 16"
          },
          isDefault: true
        },
        {
          from: 8,
          to: 9,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 36",
            en: "Level 36"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 9,
    slug: "blastoise",
    name: {
      ru: "\u0411\u043B\u0430\u0441\u0442\u043E\u0439\u0437",
      en: "Blastoise"
    },
    genus: {
      ru: "\u041F\u0430\u043D\u0446\u0438\u0440\u043D\u044B\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Shellfish Pok\xE9mon"
    },
    description: {
      ru: "\u0412\u043E\u0434\u044F\u043D\u044B\u0435 \u043F\u0443\u0448\u043A\u0438 \u043D\u0430 \u043F\u0430\u043D\u0446\u0438\u0440\u0435 \u043F\u0440\u043E\u0431\u0438\u0432\u0430\u044E\u0442 \u0434\u0430\u0436\u0435 \u0442\u043E\u043B\u0441\u0442\u0443\u044E \u0441\u0442\u0430\u043B\u044C.",
      en: "The water cannons mounted on its shell can pierce thick steel."
    },
    habitat: "water",
    types: [
      "water"
    ],
    height: 1.6,
    weight: 85.5,
    stats: [
      79,
      83,
      100,
      85,
      105,
      78
    ],
    abilities: [
      {
        id: 67,
        slug: "torrent",
        name: {
          ru: "\u041F\u043E\u0442\u043E\u043A",
          en: "Torrent"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0432\u043E\u0434\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438, \u043A\u043E\u0433\u0434\u0430 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043D\u0438\u0437\u043A\u043E\u0435.",
          en: "Boosts Water moves when HP is low."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/67/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 44,
        slug: "rain-dish",
        name: {
          ru: "\u0414\u043E\u0436\u0434\u0435\u0432\u0430\u044F \u0447\u0430\u0448\u0430",
          en: "Rain Dish"
        },
        description: {
          ru: "\u041F\u043E\u0441\u0442\u0435\u043F\u0435\u043D\u043D\u043E \u0432\u043E\u0441\u0441\u0442\u0430\u043D\u0430\u0432\u043B\u0438\u0432\u0430\u0435\u0442 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043F\u043E\u0434 \u0434\u043E\u0436\u0434\u0451\u043C.",
          en: "Restores some HP each turn in rain."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/44/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 57,
        slug: "surf",
        name: {
          ru: "\u0421\u0451\u0440\u0444\u0438\u043D\u0433",
          en: "Surf"
        },
        description: {
          ru: "\u041D\u0430\u043A\u0440\u044B\u0432\u0430\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u0431\u043E\u043B\u044C\u0448\u043E\u0439 \u0432\u043E\u0434\u044F\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Sweeps over opponents with a large wave of water."
        },
        type: "water",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/57/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/9/"
        }
      },
      {
        id: 352,
        slug: "water-pulse",
        name: {
          ru: "\u0412\u043E\u0434\u043D\u044B\u0439 \u0438\u043C\u043F\u0443\u043B\u044C\u0441",
          en: "Water Pulse"
        },
        description: {
          ru: "\u0412\u043E\u0434\u044F\u043D\u0430\u044F \u0432\u043E\u043B\u043D\u0430 \u043C\u043E\u0436\u0435\u0442 \u043F\u0440\u0438\u0432\u0435\u0441\u0442\u0438 \u0446\u0435\u043B\u044C \u0432 \u0437\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u043E.",
          en: "A pulsing wave of water may confuse the target."
        },
        type: "water",
        power: 60,
        accuracy: 100,
        pp: 20,
        damageClass: "special",
        priority: 0,
        effectChance: 20,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/352/",
        meta: {
          ailment: {
            name: "confusion"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: 2,
          max_turns: 5,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 20,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/9/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 7,
          name: {
            ru: "\u0421\u043A\u0432\u0438\u0440\u0442\u043B",
            en: "Squirtle"
          }
        },
        {
          id: 8,
          name: {
            ru: "\u0412\u0430\u0440\u0442\u043E\u0440\u0442\u043B",
            en: "Wartortle"
          }
        },
        {
          id: 9,
          name: {
            ru: "\u0411\u043B\u0430\u0441\u0442\u043E\u0439\u0437",
            en: "Blastoise"
          }
        }
      ],
      edges: [
        {
          from: 7,
          to: 8,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 16",
            en: "Level 16"
          },
          isDefault: true
        },
        {
          from: 8,
          to: 9,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 36",
            en: "Level 36"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 10,
    slug: "caterpie",
    name: {
      ru: "\u041A\u0430\u0442\u0435\u0440\u043F\u0438",
      en: "Caterpie"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0433\u0443\u0441\u0435\u043D\u0438\u0446\u0430",
      en: "Worm Pok\xE9mon"
    },
    description: {
      ru: "\u041F\u0440\u0438\u0441\u043E\u0441\u043A\u0438 \u043D\u0430 \u043A\u043E\u0440\u043E\u0442\u043A\u0438\u0445 \u043B\u0430\u043F\u043A\u0430\u0445 \u043F\u043E\u043C\u043E\u0433\u0430\u044E\u0442 \u0435\u043C\u0443 \u043F\u043E\u0434\u043D\u0438\u043C\u0430\u0442\u044C\u0441\u044F \u043F\u043E \u043A\u0440\u0443\u0442\u044B\u043C \u043F\u043E\u0432\u0435\u0440\u0445\u043D\u043E\u0441\u0442\u044F\u043C. \u041A\u0430\u0442\u0435\u0440\u043F\u0438 \u0447\u0443\u0432\u0441\u0442\u0432\u0443\u0435\u0442 \u0441\u0435\u0431\u044F \u0434\u043E\u043C\u0430 \u0441\u0440\u0435\u0434\u0438 \u043B\u0438\u0441\u0442\u0432\u044B.",
      en: "Suction pads on its feet help Caterpie climb steep surfaces and explore leafy surroundings."
    },
    habitat: "forest",
    types: [
      "bug"
    ],
    height: 0.3,
    weight: 2.9,
    stats: [
      45,
      30,
      35,
      20,
      20,
      45
    ],
    abilities: [
      {
        id: 19,
        slug: "shield-dust",
        name: {
          ru: "\u0417\u0430\u0449\u0438\u0442\u043D\u0430\u044F \u043F\u044B\u043B\u044C",
          en: "Shield Dust"
        },
        description: {
          ru: "\u0411\u043B\u043E\u043A\u0438\u0440\u0443\u0435\u0442 \u0434\u043E\u043F\u043E\u043B\u043D\u0438\u0442\u0435\u043B\u044C\u043D\u044B\u0435 \u044D\u0444\u0444\u0435\u043A\u0442\u044B \u0430\u0442\u0430\u043A \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Blocks the extra effects of incoming moves."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/19/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 50,
        slug: "run-away",
        name: {
          ru: "\u041F\u043E\u0431\u0435\u0433",
          en: "Run Away"
        },
        description: {
          ru: "\u041F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0443\u0441\u043F\u0435\u0448\u043D\u043E \u0443\u0431\u0435\u0436\u0430\u0442\u044C \u043E\u0442 \u0434\u0438\u043A\u043E\u0433\u043E \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u0430.",
          en: "Ensures escape from wild Pok\xE9mon battles."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/50/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 33,
        slug: "tackle",
        name: {
          ru: "\u0422\u0430\u0440\u0430\u043D",
          en: "Tackle"
        },
        description: {
          ru: "\u0420\u0430\u0437\u0433\u043E\u043D\u044F\u0435\u0442\u0441\u044F \u0438 \u0441\u0442\u0430\u043B\u043A\u0438\u0432\u0430\u0435\u0442\u0441\u044F \u0441 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u043E\u043C \u0432\u0441\u0435\u043C \u0442\u0435\u043B\u043E\u043C.",
          en: "Charges into the target with its whole body."
        },
        type: "normal",
        power: 40,
        accuracy: 100,
        pp: 35,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/33/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/10/"
        }
      },
      {
        id: 450,
        slug: "bug-bite",
        name: {
          ru: "\u0423\u043A\u0443\u0441 \u043D\u0430\u0441\u0435\u043A\u043E\u043C\u043E\u0433\u043E",
          en: "Bug Bite"
        },
        description: {
          ru: "\u041A\u0443\u0441\u0430\u0435\u0442 \u0446\u0435\u043B\u044C \u0438 \u043C\u043E\u0436\u0435\u0442 \u0441\u044A\u0435\u0441\u0442\u044C \u0443\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u043C\u0443\u044E \u0435\u044E \u044F\u0433\u043E\u0434\u0443.",
          en: "Bites the target and may eat its held berry."
        },
        type: "bug",
        power: 60,
        accuracy: 100,
        pp: 20,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/450/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/10/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 10,
          name: {
            ru: "\u041A\u0430\u0442\u0435\u0440\u043F\u0438",
            en: "Caterpie"
          }
        },
        {
          id: 11,
          name: {
            ru: "\u041C\u0435\u0442\u0430\u043F\u043E\u0434",
            en: "Metapod"
          }
        },
        {
          id: 12,
          name: {
            ru: "\u0411\u0430\u0442\u0442\u0435\u0440\u0444\u0440\u0438",
            en: "Butterfree"
          }
        }
      ],
      edges: [
        {
          from: 10,
          to: 11,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 7",
            en: "Level 7"
          },
          isDefault: true
        },
        {
          from: 11,
          to: 12,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 10",
            en: "Level 10"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 11,
    slug: "metapod",
    name: {
      ru: "\u041C\u0435\u0442\u0430\u043F\u043E\u0434",
      en: "Metapod"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043A\u043E\u043A\u043E\u043D",
      en: "Cocoon Pok\xE9mon"
    },
    description: {
      ru: "\u041F\u0440\u043E\u0447\u043D\u044B\u0439 \u043A\u043E\u043A\u043E\u043D \u0437\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043C\u044F\u0433\u043A\u043E\u0435 \u0442\u0435\u043B\u043E, \u043D\u043E \u0441\u0438\u043B\u044C\u043D\u044B\u0439 \u0443\u0434\u0430\u0440 \u0432\u0441\u0451 \u0436\u0435 \u043E\u043F\u0430\u0441\u0435\u043D.",
      en: "A firm cocoon shelters its soft body, which remains vulnerable to a heavy blow."
    },
    habitat: "forest",
    types: [
      "bug"
    ],
    height: 0.7,
    weight: 9.9,
    stats: [
      50,
      20,
      55,
      25,
      25,
      30
    ],
    abilities: [
      {
        id: 61,
        slug: "shed-skin",
        name: {
          ru: "\u041B\u0438\u043D\u044C\u043A\u0430",
          en: "Shed Skin"
        },
        description: {
          ru: "\u0412 \u043A\u043E\u043D\u0446\u0435 \u0445\u043E\u0434\u0430 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u044F\u0442\u044C \u043F\u0440\u043E\u0431\u043B\u0435\u043C\u0443 \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u044F.",
          en: "May cure a status condition at the end of a turn."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/61/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 450,
        slug: "bug-bite",
        name: {
          ru: "\u0423\u043A\u0443\u0441 \u043D\u0430\u0441\u0435\u043A\u043E\u043C\u043E\u0433\u043E",
          en: "Bug Bite"
        },
        description: {
          ru: "\u041A\u0443\u0441\u0430\u0435\u0442 \u0446\u0435\u043B\u044C \u0438 \u043C\u043E\u0436\u0435\u0442 \u0441\u044A\u0435\u0441\u0442\u044C \u0443\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u043C\u0443\u044E \u0435\u044E \u044F\u0433\u043E\u0434\u0443.",
          en: "Bites the target and may eat its held berry."
        },
        type: "bug",
        power: 60,
        accuracy: 100,
        pp: 20,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/450/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/11/"
        }
      },
      {
        id: 33,
        slug: "tackle",
        name: {
          ru: "\u0422\u0430\u0440\u0430\u043D",
          en: "Tackle"
        },
        description: {
          ru: "\u0420\u0430\u0437\u0433\u043E\u043D\u044F\u0435\u0442\u0441\u044F \u0438 \u0441\u0442\u0430\u043B\u043A\u0438\u0432\u0430\u0435\u0442\u0441\u044F \u0441 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u043E\u043C \u0432\u0441\u0435\u043C \u0442\u0435\u043B\u043E\u043C. \u041C\u043E\u0436\u0435\u0442 \u0441\u043E\u0445\u0440\u0430\u043D\u044F\u0442\u044C\u0441\u044F \u043F\u043E\u0441\u043B\u0435 \u044D\u0432\u043E\u043B\u044E\u0446\u0438\u0438 \u0438\u0437 \u041A\u0430\u0442\u0435\u0440\u043F\u0438.",
          en: "Charges into the target with its whole body. It can be retained after evolving from Caterpie."
        },
        type: "normal",
        power: 40,
        accuracy: 100,
        pp: 35,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/33/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "inherited",
          speciesId: 10,
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/10/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 10,
          name: {
            ru: "\u041A\u0430\u0442\u0435\u0440\u043F\u0438",
            en: "Caterpie"
          }
        },
        {
          id: 11,
          name: {
            ru: "\u041C\u0435\u0442\u0430\u043F\u043E\u0434",
            en: "Metapod"
          }
        },
        {
          id: 12,
          name: {
            ru: "\u0411\u0430\u0442\u0442\u0435\u0440\u0444\u0440\u0438",
            en: "Butterfree"
          }
        }
      ],
      edges: [
        {
          from: 10,
          to: 11,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 7",
            en: "Level 7"
          },
          isDefault: true
        },
        {
          from: 11,
          to: 12,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 10",
            en: "Level 10"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 12,
    slug: "butterfree",
    name: {
      ru: "\u0411\u0430\u0442\u0442\u0435\u0440\u0444\u0440\u0438",
      en: "Butterfree"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0431\u0430\u0431\u043E\u0447\u043A\u0430",
      en: "Butterfly Pok\xE9mon"
    },
    description: {
      ru: "\u041A\u0430\u0436\u0434\u044B\u0439 \u0434\u0435\u043D\u044C \u0441\u043E\u0431\u0438\u0440\u0430\u0435\u0442 \u043C\u0451\u0434 \u0438 \u043D\u0435\u0441\u0451\u0442 \u0435\u0433\u043E \u043A \u0433\u043D\u0435\u0437\u0434\u0443 \u043D\u0430 \u0432\u043E\u043B\u043E\u0441\u043A\u0430\u0445 \u043B\u0430\u043F.",
      en: "It gathers honey daily, carrying it home on the hairs of its legs."
    },
    habitat: "forest",
    types: [
      "bug",
      "flying"
    ],
    height: 1.1,
    weight: 32,
    stats: [
      60,
      45,
      50,
      90,
      80,
      70
    ],
    abilities: [
      {
        id: 14,
        slug: "compound-eyes",
        name: {
          ru: "\u0424\u0430\u0441\u0435\u0442\u043E\u0447\u043D\u044B\u0435 \u0433\u043B\u0430\u0437\u0430",
          en: "Compound Eyes"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0442\u043E\u0447\u043D\u043E\u0441\u0442\u044C \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0445 \u0430\u0442\u0430\u043A.",
          en: "Improves the accuracy of its moves."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/14/",
        descriptionSource: "editorial-summary-of-core-ability"
      },
      {
        id: 110,
        slug: "tinted-lens",
        name: {
          ru: "\u0422\u043E\u043D\u0438\u0440\u043E\u0432\u0430\u043D\u043D\u044B\u0435 \u043B\u0438\u043D\u0437\u044B",
          en: "Tinted Lens"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0430\u0442\u0430\u043A\u0438, \u043A\u043E\u0442\u043E\u0440\u044B\u0435 \u043C\u0430\u043B\u043E\u044D\u0444\u0444\u0435\u043A\u0442\u0438\u0432\u043D\u044B \u043F\u0440\u043E\u0442\u0438\u0432 \u0446\u0435\u043B\u0438.",
          en: "Boosts attacks that would otherwise be resisted by the target."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/110/",
        descriptionSource: "editorial-summary-of-core-ability"
      }
    ],
    moves: [
      {
        id: 450,
        slug: "bug-bite",
        name: {
          ru: "\u0423\u043A\u0443\u0441 \u043D\u0430\u0441\u0435\u043A\u043E\u043C\u043E\u0433\u043E",
          en: "Bug Bite"
        },
        description: {
          ru: "\u041A\u0443\u0441\u0430\u0435\u0442 \u0446\u0435\u043B\u044C \u0438 \u043C\u043E\u0436\u0435\u0442 \u0441\u044A\u0435\u0441\u0442\u044C \u0443\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u043C\u0443\u044E \u0435\u044E \u044F\u0433\u043E\u0434\u0443.",
          en: "Bites the target and may eat its held berry."
        },
        type: "bug",
        power: 60,
        accuracy: 100,
        pp: 20,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/450/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/12/"
        }
      },
      {
        id: 16,
        slug: "gust",
        name: {
          ru: "\u041F\u043E\u0440\u044B\u0432 \u0432\u0435\u0442\u0440\u0430",
          en: "Gust"
        },
        description: {
          ru: "\u0411\u044C\u0451\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u0441\u0438\u043B\u044C\u043D\u044B\u043C \u0432\u043E\u0437\u0434\u0443\u0448\u043D\u044B\u043C \u043F\u043E\u0442\u043E\u043A\u043E\u043C.",
          en: "Buffets the target with a strong gust of wind."
        },
        type: "flying",
        power: 40,
        accuracy: 100,
        pp: 35,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/16/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/12/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 10,
          name: {
            ru: "\u041A\u0430\u0442\u0435\u0440\u043F\u0438",
            en: "Caterpie"
          }
        },
        {
          id: 11,
          name: {
            ru: "\u041C\u0435\u0442\u0430\u043F\u043E\u0434",
            en: "Metapod"
          }
        },
        {
          id: 12,
          name: {
            ru: "\u0411\u0430\u0442\u0442\u0435\u0440\u0444\u0440\u0438",
            en: "Butterfree"
          }
        }
      ],
      edges: [
        {
          from: 10,
          to: 11,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 7",
            en: "Level 7"
          },
          isDefault: true
        },
        {
          from: 11,
          to: 12,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 10",
            en: "Level 10"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 16,
    slug: "pidgey",
    name: {
      ru: "\u041F\u0438\u0434\u0436\u0438",
      en: "Pidgey"
    },
    genus: {
      ru: "\u041C\u0430\u043B\u0435\u043D\u044C\u043A\u0430\u044F \u043F\u0442\u0438\u0446\u0430",
      en: "Tiny Bird Pok\xE9mon"
    },
    description: {
      ru: "\u0421\u043F\u043E\u043A\u043E\u0439\u043D\u0430\u044F \u043B\u0435\u0441\u043D\u0430\u044F \u043F\u0442\u0438\u0446\u0430. \u041F\u0440\u0438 \u043D\u0430\u043F\u0430\u0434\u0435\u043D\u0438\u0438 \u0447\u0430\u0449\u0435 \u043F\u043E\u0434\u043D\u0438\u043C\u0430\u0435\u0442 \u043F\u0435\u0441\u043E\u043A, \u0447\u0442\u043E\u0431\u044B \u0437\u0430\u0449\u0438\u0442\u0438\u0442\u044C\u0441\u044F, \u0447\u0435\u043C \u0432\u0441\u0442\u0443\u043F\u0430\u0435\u0442 \u0432 \u0431\u043E\u0439.",
      en: "A gentle forest bird that prefers kicking up sand to protect itself over fighting."
    },
    habitat: "forest",
    types: [
      "normal",
      "flying"
    ],
    height: 0.3,
    weight: 1.8,
    stats: [
      40,
      45,
      40,
      35,
      35,
      56
    ],
    abilities: [
      {
        id: 51,
        slug: "keen-eye",
        name: {
          ru: "\u041E\u0441\u0442\u0440\u044B\u0439 \u0432\u0437\u0433\u043B\u044F\u0434",
          en: "Keen Eye"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u0442\u043E\u0447\u043D\u043E\u0441\u0442\u044C \u043E\u0442 \u0441\u043D\u0438\u0436\u0435\u043D\u0438\u044F.",
          en: "Prevents accuracy from being lowered."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/51/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 77,
        slug: "tangled-feet",
        name: {
          ru: "\u0417\u0430\u043F\u0443\u0442\u0430\u043D\u043D\u044B\u0435 \u043D\u043E\u0433\u0438",
          en: "Tangled Feet"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0443\u043A\u043B\u043E\u043D\u0435\u043D\u0438\u0435 \u043F\u0440\u0438 \u0437\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u0435.",
          en: "Improves evasion while confused."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/77/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 145,
        slug: "big-pecks",
        name: {
          ru: "\u041A\u0440\u0435\u043F\u043A\u0430\u044F \u0433\u0440\u0443\u0434\u044C",
          en: "Big Pecks"
        },
        description: {
          ru: "\u041D\u0435 \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0443 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0437\u0430\u0449\u0438\u0442\u0443.",
          en: "Prevents opponents from lowering Defense."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/145/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 16,
        slug: "gust",
        name: {
          ru: "\u041F\u043E\u0440\u044B\u0432 \u0432\u0435\u0442\u0440\u0430",
          en: "Gust"
        },
        description: {
          ru: "\u0411\u044C\u0451\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u0441\u0438\u043B\u044C\u043D\u044B\u043C \u0432\u043E\u0437\u0434\u0443\u0448\u043D\u044B\u043C \u043F\u043E\u0442\u043E\u043A\u043E\u043C.",
          en: "Buffets the target with a strong gust of wind."
        },
        type: "flying",
        power: 40,
        accuracy: 100,
        pp: 35,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/16/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/16/"
        }
      },
      {
        id: 98,
        slug: "quick-attack",
        name: {
          ru: "\u0411\u044B\u0441\u0442\u0440\u0430\u044F \u0430\u0442\u0430\u043A\u0430",
          en: "Quick Attack"
        },
        description: {
          ru: "\u0420\u0435\u0437\u043A\u0438\u0439 \u0440\u044B\u0432\u043E\u043A \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0430\u0442\u0430\u043A\u043E\u0432\u0430\u0442\u044C \u0441 \u043F\u043E\u0432\u044B\u0448\u0435\u043D\u043D\u044B\u043C \u043F\u0440\u0438\u043E\u0440\u0438\u0442\u0435\u0442\u043E\u043C.",
          en: "A swift lunge with increased move priority."
        },
        type: "normal",
        power: 40,
        accuracy: 100,
        pp: 30,
        damageClass: "physical",
        priority: 1,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/98/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/16/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 16,
          name: {
            ru: "\u041F\u0438\u0434\u0436\u0438",
            en: "Pidgey"
          }
        },
        {
          id: 17,
          name: {
            ru: "\u041F\u0438\u0434\u0436\u0435\u043E\u0442\u0442\u043E",
            en: "Pidgeotto"
          }
        },
        {
          id: 18,
          name: {
            ru: "\u041F\u0438\u0434\u0436\u0435\u043E\u0442",
            en: "Pidgeot"
          }
        }
      ],
      edges: [
        {
          from: 16,
          to: 17,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 18",
            en: "Level 18"
          },
          isDefault: true
        },
        {
          from: 17,
          to: 18,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 36",
            en: "Level 36"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 17,
    slug: "pidgeotto",
    name: {
      ru: "\u041F\u0438\u0434\u0436\u0435\u043E\u0442\u0442\u043E",
      en: "Pidgeotto"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043F\u0442\u0438\u0446\u0430",
      en: "Bird Pok\xE9mon"
    },
    description: {
      ru: "\u041F\u043E\u0441\u0442\u043E\u044F\u043D\u043D\u043E \u043E\u0431\u043B\u0435\u0442\u0430\u0435\u0442 \u0431\u043E\u043B\u044C\u0448\u0443\u044E \u0442\u0435\u0440\u0440\u0438\u0442\u043E\u0440\u0438\u044E \u0432 \u043F\u043E\u0438\u0441\u043A\u0430\u0445 \u0434\u043E\u0431\u044B\u0447\u0438.",
      en: "This energetic bird patrols a large territory while searching for food."
    },
    habitat: "forest",
    types: [
      "normal",
      "flying"
    ],
    height: 1.1,
    weight: 30,
    stats: [
      63,
      60,
      55,
      50,
      50,
      71
    ],
    abilities: [
      {
        id: 51,
        slug: "keen-eye",
        name: {
          ru: "\u041E\u0441\u0442\u0440\u044B\u0439 \u0432\u0437\u0433\u043B\u044F\u0434",
          en: "Keen Eye"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u0442\u043E\u0447\u043D\u043E\u0441\u0442\u044C \u043E\u0442 \u0441\u043D\u0438\u0436\u0435\u043D\u0438\u044F.",
          en: "Prevents accuracy from being lowered."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/51/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 77,
        slug: "tangled-feet",
        name: {
          ru: "\u0417\u0430\u043F\u0443\u0442\u0430\u043D\u043D\u044B\u0435 \u043D\u043E\u0433\u0438",
          en: "Tangled Feet"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0443\u043A\u043B\u043E\u043D\u0435\u043D\u0438\u0435 \u043F\u0440\u0438 \u0437\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u0435.",
          en: "Improves evasion while confused."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/77/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 145,
        slug: "big-pecks",
        name: {
          ru: "\u041A\u0440\u0435\u043F\u043A\u0430\u044F \u0433\u0440\u0443\u0434\u044C",
          en: "Big Pecks"
        },
        description: {
          ru: "\u041D\u0435 \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0443 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0437\u0430\u0449\u0438\u0442\u0443.",
          en: "Prevents opponents from lowering Defense."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/145/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 129,
        slug: "swift",
        name: {
          ru: "\u0417\u0432\u0451\u0437\u0434\u043D\u044B\u0439 \u0443\u0434\u0430\u0440",
          en: "Swift"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u0441\u0432\u0435\u0442\u044F\u0449\u0438\u0435\u0441\u044F \u0437\u0432\u0451\u0437\u0434\u044B, \u043A\u043E\u0442\u043E\u0440\u044B\u0435 \u043D\u0435 \u043F\u0440\u043E\u043C\u0430\u0445\u0438\u0432\u0430\u044E\u0442\u0441\u044F.",
          en: "Fires glowing stars that do not miss."
        },
        type: "normal",
        power: 60,
        accuracy: null,
        pp: 20,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/129/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/17/"
        }
      },
      {
        id: 17,
        slug: "wing-attack",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043A\u0440\u044B\u043B\u043E\u043C",
          en: "Wing Attack"
        },
        description: {
          ru: "\u041D\u0430\u043D\u043E\u0441\u0438\u0442 \u0443\u0434\u0430\u0440 \u0448\u0438\u0440\u043E\u043A\u043E \u0440\u0430\u0441\u043A\u0440\u044B\u0442\u044B\u043C\u0438 \u043A\u0440\u044B\u043B\u044C\u044F\u043C\u0438.",
          en: "Strikes the target with outstretched wings."
        },
        type: "flying",
        power: 60,
        accuracy: 100,
        pp: 35,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/17/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/17/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 16,
          name: {
            ru: "\u041F\u0438\u0434\u0436\u0438",
            en: "Pidgey"
          }
        },
        {
          id: 17,
          name: {
            ru: "\u041F\u0438\u0434\u0436\u0435\u043E\u0442\u0442\u043E",
            en: "Pidgeotto"
          }
        },
        {
          id: 18,
          name: {
            ru: "\u041F\u0438\u0434\u0436\u0435\u043E\u0442",
            en: "Pidgeot"
          }
        }
      ],
      edges: [
        {
          from: 16,
          to: 17,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 18",
            en: "Level 18"
          },
          isDefault: true
        },
        {
          from: 17,
          to: 18,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 36",
            en: "Level 36"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 18,
    slug: "pidgeot",
    name: {
      ru: "\u041F\u0438\u0434\u0436\u0435\u043E\u0442",
      en: "Pidgeot"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043F\u0442\u0438\u0446\u0430",
      en: "Bird Pok\xE9mon"
    },
    description: {
      ru: "\u041B\u0435\u0442\u0430\u0435\u0442 \u0441 \u043E\u0433\u0440\u043E\u043C\u043D\u043E\u0439 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C\u044E. \u041C\u043E\u0449\u043D\u044B\u0435 \u043A\u043E\u0433\u0442\u0438 \u043F\u043E\u043C\u043E\u0433\u0430\u044E\u0442 \u0445\u0432\u0430\u0442\u0430\u0442\u044C \u0434\u043E\u0431\u044B\u0447\u0443.",
      en: "Pidgeot hunts at remarkable speed and seizes prey with its large talons."
    },
    habitat: "forest",
    types: [
      "normal",
      "flying"
    ],
    height: 1.5,
    weight: 39.5,
    stats: [
      83,
      80,
      75,
      70,
      70,
      101
    ],
    abilities: [
      {
        id: 51,
        slug: "keen-eye",
        name: {
          ru: "\u041E\u0441\u0442\u0440\u044B\u0439 \u0432\u0437\u0433\u043B\u044F\u0434",
          en: "Keen Eye"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u0442\u043E\u0447\u043D\u043E\u0441\u0442\u044C \u043E\u0442 \u0441\u043D\u0438\u0436\u0435\u043D\u0438\u044F.",
          en: "Prevents accuracy from being lowered."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/51/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 77,
        slug: "tangled-feet",
        name: {
          ru: "\u0417\u0430\u043F\u0443\u0442\u0430\u043D\u043D\u044B\u0435 \u043D\u043E\u0433\u0438",
          en: "Tangled Feet"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0443\u043A\u043B\u043E\u043D\u0435\u043D\u0438\u0435 \u043F\u0440\u0438 \u0437\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u0435.",
          en: "Improves evasion while confused."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/77/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 145,
        slug: "big-pecks",
        name: {
          ru: "\u041A\u0440\u0435\u043F\u043A\u0430\u044F \u0433\u0440\u0443\u0434\u044C",
          en: "Big Pecks"
        },
        description: {
          ru: "\u041D\u0435 \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0443 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0437\u0430\u0449\u0438\u0442\u0443.",
          en: "Prevents opponents from lowering Defense."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/145/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 129,
        slug: "swift",
        name: {
          ru: "\u0417\u0432\u0451\u0437\u0434\u043D\u044B\u0439 \u0443\u0434\u0430\u0440",
          en: "Swift"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u0441\u0432\u0435\u0442\u044F\u0449\u0438\u0435\u0441\u044F \u0437\u0432\u0451\u0437\u0434\u044B, \u043A\u043E\u0442\u043E\u0440\u044B\u0435 \u043D\u0435 \u043F\u0440\u043E\u043C\u0430\u0445\u0438\u0432\u0430\u044E\u0442\u0441\u044F.",
          en: "Fires glowing stars that do not miss."
        },
        type: "normal",
        power: 60,
        accuracy: null,
        pp: 20,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/129/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/18/"
        }
      },
      {
        id: 17,
        slug: "wing-attack",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043A\u0440\u044B\u043B\u043E\u043C",
          en: "Wing Attack"
        },
        description: {
          ru: "\u041D\u0430\u043D\u043E\u0441\u0438\u0442 \u0443\u0434\u0430\u0440 \u0448\u0438\u0440\u043E\u043A\u043E \u0440\u0430\u0441\u043A\u0440\u044B\u0442\u044B\u043C\u0438 \u043A\u0440\u044B\u043B\u044C\u044F\u043C\u0438.",
          en: "Strikes the target with outstretched wings."
        },
        type: "flying",
        power: 60,
        accuracy: 100,
        pp: 35,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/17/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/18/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 16,
          name: {
            ru: "\u041F\u0438\u0434\u0436\u0438",
            en: "Pidgey"
          }
        },
        {
          id: 17,
          name: {
            ru: "\u041F\u0438\u0434\u0436\u0435\u043E\u0442\u0442\u043E",
            en: "Pidgeotto"
          }
        },
        {
          id: 18,
          name: {
            ru: "\u041F\u0438\u0434\u0436\u0435\u043E\u0442",
            en: "Pidgeot"
          }
        }
      ],
      edges: [
        {
          from: 16,
          to: 17,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 18",
            en: "Level 18"
          },
          isDefault: true
        },
        {
          from: 17,
          to: 18,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 36",
            en: "Level 36"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 25,
    slug: "pikachu",
    name: {
      ru: "\u041F\u0438\u043A\u0430\u0447\u0443",
      en: "Pikachu"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043C\u044B\u0448\u044C",
      en: "Mouse Pok\xE9mon"
    },
    description: {
      ru: "\u041D\u0430\u043A\u0430\u043F\u043B\u0438\u0432\u0430\u0435\u0442 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u0442\u0432\u043E \u0432 \u043C\u0435\u0448\u043E\u0447\u043A\u0430\u0445 \u043D\u0430 \u0449\u0435\u043A\u0430\u0445. \u042D\u0442\u043E\u0442 \u0441\u043E\u043E\u0431\u0440\u0430\u0437\u0438\u0442\u0435\u043B\u044C\u043D\u044B\u0439 \u0436\u0438\u0442\u0435\u043B\u044C \u043B\u0435\u0441\u0430 \u0434\u0430\u0436\u0435 \u043F\u043E\u0434\u0436\u0430\u0440\u0438\u0432\u0430\u0435\u0442 \u0436\u0451\u0441\u0442\u043A\u0438\u0435 \u044F\u0433\u043E\u0434\u044B \u0440\u0430\u0437\u0440\u044F\u0434\u043E\u043C.",
      en: "Cheek pouches store its electricity. This clever forest dweller even uses a shock to roast tough berries."
    },
    habitat: "forest",
    types: [
      "electric"
    ],
    height: 0.4,
    weight: 6,
    stats: [
      35,
      55,
      40,
      50,
      50,
      90
    ],
    abilities: [
      {
        id: 9,
        slug: "static",
        name: {
          ru: "\u0421\u0442\u0430\u0442\u0438\u043A\u0430",
          en: "Static"
        },
        description: {
          ru: "\u041A\u043E\u043D\u0442\u0430\u043A\u0442\u043D\u0430\u044F \u0430\u0442\u0430\u043A\u0430 \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C \u0430\u0442\u0430\u043A\u0443\u044E\u0449\u0435\u0433\u043E.",
          en: "Contact attacks may paralyze the attacker."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/9/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 31,
        slug: "lightning-rod",
        name: {
          ru: "\u0413\u0440\u043E\u043C\u043E\u043E\u0442\u0432\u043E\u0434",
          en: "Lightning Rod"
        },
        description: {
          ru: "\u041F\u0440\u0438\u0442\u044F\u0433\u0438\u0432\u0430\u0435\u0442 \u0438 \u043F\u043E\u0433\u043B\u043E\u0449\u0430\u0435\u0442 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0435 \u0430\u0442\u0430\u043A\u0438, \u043F\u043E\u0432\u044B\u0448\u0430\u044F \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443.",
          en: "Draws in and absorbs Electric moves to raise Special Attack."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/31/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 85,
        slug: "thunderbolt",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043C\u043E\u043B\u043D\u0438\u0438",
          en: "Thunderbolt"
        },
        description: {
          ru: "\u041C\u043E\u0449\u043D\u044B\u0439 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0439 \u0440\u0430\u0437\u0440\u044F\u0434 \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C \u0446\u0435\u043B\u044C.",
          en: "A strong electric bolt may paralyze the target."
        },
        type: "electric",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/85/",
        meta: {
          ailment: {
            name: "paralysis"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/25/"
        }
      },
      {
        id: 98,
        slug: "quick-attack",
        name: {
          ru: "\u0411\u044B\u0441\u0442\u0440\u0430\u044F \u0430\u0442\u0430\u043A\u0430",
          en: "Quick Attack"
        },
        description: {
          ru: "\u0420\u0435\u0437\u043A\u0438\u0439 \u0440\u044B\u0432\u043E\u043A \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0430\u0442\u0430\u043A\u043E\u0432\u0430\u0442\u044C \u0441 \u043F\u043E\u0432\u044B\u0448\u0435\u043D\u043D\u044B\u043C \u043F\u0440\u0438\u043E\u0440\u0438\u0442\u0435\u0442\u043E\u043C.",
          en: "A swift lunge with increased move priority."
        },
        type: "normal",
        power: 40,
        accuracy: 100,
        pp: 30,
        damageClass: "physical",
        priority: 1,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/98/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/25/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 172,
          name: {
            ru: "\u041F\u0438\u0447\u0443",
            en: "Pichu"
          }
        },
        {
          id: 25,
          name: {
            ru: "\u041F\u0438\u043A\u0430\u0447\u0443",
            en: "Pikachu"
          }
        },
        {
          id: 26,
          name: {
            ru: "\u0420\u0430\u0439\u0447\u0443",
            en: "Raichu"
          }
        }
      ],
      edges: [
        {
          from: 172,
          to: 25,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 220",
            en: "Level up \xB7 friendship \u2265 220"
          },
          isDefault: true
        },
        {
          from: 25,
          to: 26,
          condition: {
            ru: "\u0413\u0440\u043E\u043C\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Thunder Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 26,
    slug: "raichu",
    name: {
      ru: "\u0420\u0430\u0439\u0447\u0443",
      en: "Raichu"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043C\u044B\u0448\u044C",
      en: "Mouse Pok\xE9mon"
    },
    description: {
      ru: "\u0421\u043F\u043E\u0441\u043E\u0431\u0435\u043D \u0432\u044B\u043F\u0443\u0441\u043A\u0430\u0442\u044C \u0447\u0440\u0435\u0437\u0432\u044B\u0447\u0430\u0439\u043D\u043E \u043C\u043E\u0449\u043D\u044B\u0435 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0435 \u0440\u0430\u0437\u0440\u044F\u0434\u044B.",
      en: "Raichu can release electrical bursts strong enough to overwhelm much larger creatures."
    },
    habitat: "forest",
    types: [
      "electric"
    ],
    height: 0.8,
    weight: 30,
    stats: [
      60,
      90,
      55,
      90,
      80,
      110
    ],
    abilities: [
      {
        id: 9,
        slug: "static",
        name: {
          ru: "\u0421\u0442\u0430\u0442\u0438\u043A\u0430",
          en: "Static"
        },
        description: {
          ru: "\u041A\u043E\u043D\u0442\u0430\u043A\u0442\u043D\u0430\u044F \u0430\u0442\u0430\u043A\u0430 \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C \u0430\u0442\u0430\u043A\u0443\u044E\u0449\u0435\u0433\u043E.",
          en: "Contact attacks may paralyze the attacker."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/9/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 31,
        slug: "lightning-rod",
        name: {
          ru: "\u0413\u0440\u043E\u043C\u043E\u043E\u0442\u0432\u043E\u0434",
          en: "Lightning Rod"
        },
        description: {
          ru: "\u041F\u0440\u0438\u0442\u044F\u0433\u0438\u0432\u0430\u0435\u0442 \u0438 \u043F\u043E\u0433\u043B\u043E\u0449\u0430\u0435\u0442 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0435 \u0430\u0442\u0430\u043A\u0438, \u043F\u043E\u0432\u044B\u0448\u0430\u044F \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443.",
          en: "Draws in and absorbs Electric moves to raise Special Attack."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/31/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 85,
        slug: "thunderbolt",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043C\u043E\u043B\u043D\u0438\u0438",
          en: "Thunderbolt"
        },
        description: {
          ru: "\u041C\u043E\u0449\u043D\u044B\u0439 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0439 \u0440\u0430\u0437\u0440\u044F\u0434 \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C \u0446\u0435\u043B\u044C.",
          en: "A strong electric bolt may paralyze the target."
        },
        type: "electric",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/85/",
        meta: {
          ailment: {
            name: "paralysis"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/26/"
        }
      },
      {
        id: 84,
        slug: "thunder-shock",
        name: {
          ru: "\u042D\u043B\u0435\u043A\u0442\u0440\u043E\u0448\u043E\u043A",
          en: "Thunder Shock"
        },
        description: {
          ru: "\u041D\u0435\u0431\u043E\u043B\u044C\u0448\u043E\u0439 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0439 \u0440\u0430\u0437\u0440\u044F\u0434 \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C.",
          en: "A small electric discharge may cause paralysis."
        },
        type: "electric",
        power: 40,
        accuracy: 100,
        pp: 30,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/84/",
        meta: {
          ailment: {
            name: "paralysis"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/26/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 172,
          name: {
            ru: "\u041F\u0438\u0447\u0443",
            en: "Pichu"
          }
        },
        {
          id: 25,
          name: {
            ru: "\u041F\u0438\u043A\u0430\u0447\u0443",
            en: "Pikachu"
          }
        },
        {
          id: 26,
          name: {
            ru: "\u0420\u0430\u0439\u0447\u0443",
            en: "Raichu"
          }
        }
      ],
      edges: [
        {
          from: 172,
          to: 25,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 220",
            en: "Level up \xB7 friendship \u2265 220"
          },
          isDefault: true
        },
        {
          from: 25,
          to: 26,
          condition: {
            ru: "\u0413\u0440\u043E\u043C\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Thunder Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 27,
    slug: "sandshrew",
    name: {
      ru: "\u0421\u044D\u043D\u0434\u0448\u0440\u044E",
      en: "Sandshrew"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043C\u044B\u0448\u044C",
      en: "Mouse Pok\xE9mon"
    },
    description: {
      ru: "\u0420\u043E\u0435\u0442 \u043F\u043E\u0434\u0437\u0435\u043C\u043D\u044B\u0435 \u043D\u043E\u0440\u044B. \u041E\u0441\u0442\u0440\u044B\u0435 \u043A\u043E\u0433\u0442\u0438 \u043F\u043E\u043C\u043E\u0433\u0430\u044E\u0442 \u0435\u043C\u0443 \u0440\u0430\u0437\u0431\u0438\u0432\u0430\u0442\u044C \u043A\u0430\u043C\u043D\u0438, \u043A\u043E\u0442\u043E\u0440\u044B\u0435 \u0432\u0441\u0442\u0440\u0435\u0447\u0430\u044E\u0442\u0441\u044F \u043D\u0430 \u043F\u0443\u0442\u0438.",
      en: "Sandshrew builds underground burrows, breaking obstructing stones with its sharp claws."
    },
    habitat: "mountain",
    types: [
      "ground"
    ],
    height: 0.6,
    weight: 12,
    stats: [
      50,
      75,
      85,
      20,
      30,
      40
    ],
    abilities: [
      {
        id: 8,
        slug: "sand-veil",
        name: {
          ru: "\u041F\u0435\u0441\u0447\u0430\u043D\u0430\u044F \u0437\u0430\u0432\u0435\u0441\u0430",
          en: "Sand Veil"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0443\u043A\u043B\u043E\u043D\u0435\u043D\u0438\u0435 \u0438 \u0437\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u043F\u0435\u0441\u0447\u0430\u043D\u043E\u0439 \u0431\u0443\u0440\u0438.",
          en: "Improves evasion and protects from sandstorm damage."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/8/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 146,
        slug: "sand-rush",
        name: {
          ru: "\u041F\u0435\u0441\u0447\u0430\u043D\u0430\u044F \u0441\u043F\u0435\u0448\u043A\u0430",
          en: "Sand Rush"
        },
        description: {
          ru: "\u0423\u0434\u0432\u0430\u0438\u0432\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u0432 \u043F\u0435\u0441\u0447\u0430\u043D\u043E\u0439 \u0431\u0443\u0440\u0435.",
          en: "Doubles Speed in a sandstorm."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/146/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 10,
        slug: "scratch",
        name: {
          ru: "\u0426\u0430\u0440\u0430\u043F\u0430\u043D\u044C\u0435",
          en: "Scratch"
        },
        description: {
          ru: "\u0426\u0430\u0440\u0430\u043F\u0430\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u043E\u0441\u0442\u0440\u044B\u043C\u0438 \u043A\u043E\u0433\u0442\u044F\u043C\u0438.",
          en: "Rakes the target with sharp claws."
        },
        type: "normal",
        power: 40,
        accuracy: 100,
        pp: 35,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/10/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/27/"
        }
      },
      {
        id: 89,
        slug: "earthquake",
        name: {
          ru: "\u0417\u0435\u043C\u043B\u0435\u0442\u0440\u044F\u0441\u0435\u043D\u0438\u0435",
          en: "Earthquake"
        },
        description: {
          ru: "\u0421\u043E\u0442\u0440\u044F\u0441\u0430\u0435\u0442 \u0437\u0435\u043C\u043B\u044E \u043C\u043E\u0449\u043D\u043E\u0439 \u0443\u0434\u0430\u0440\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Shakes the ground with a powerful shock wave."
        },
        type: "ground",
        power: 100,
        accuracy: 100,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/89/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/27/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 27,
          name: {
            ru: "\u0421\u044D\u043D\u0434\u0448\u0440\u044E",
            en: "Sandshrew"
          }
        },
        {
          id: 28,
          name: {
            ru: "\u0421\u044D\u043D\u0434\u0441\u043B\u044D\u0448",
            en: "Sandslash"
          }
        }
      ],
      edges: [
        {
          from: 27,
          to: 28,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 22",
            en: "Level 22"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 28,
    slug: "sandslash",
    name: {
      ru: "\u0421\u044D\u043D\u0434\u0441\u043B\u044D\u0448",
      en: "Sandslash"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043C\u044B\u0448\u044C",
      en: "Mouse Pok\xE9mon"
    },
    description: {
      ru: "\u041E\u0441\u0442\u0440\u044B\u043C\u0438 \u043A\u043E\u0433\u0442\u044F\u043C\u0438 \u0432\u0437\u0431\u0438\u0440\u0430\u0435\u0442\u0441\u044F \u043D\u0430 \u0434\u0435\u0440\u0435\u0432\u044C\u044F. \u0421\u043E\u0431\u0440\u0430\u043D\u043D\u044B\u0435 \u044F\u0433\u043E\u0434\u044B \u0441\u0431\u0440\u0430\u0441\u044B\u0432\u0430\u0435\u0442 \u0421\u044D\u043D\u0434\u0448\u0440\u044E \u0432\u043D\u0438\u0437\u0443.",
      en: "Sharp claws help it climb trees and drop gathered berries to Sandshrew below."
    },
    habitat: "mountain",
    types: [
      "ground"
    ],
    height: 1,
    weight: 29.5,
    stats: [
      75,
      100,
      110,
      45,
      55,
      65
    ],
    abilities: [
      {
        id: 8,
        slug: "sand-veil",
        name: {
          ru: "\u041F\u0435\u0441\u0447\u0430\u043D\u0430\u044F \u0437\u0430\u0432\u0435\u0441\u0430",
          en: "Sand Veil"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0443\u043A\u043B\u043E\u043D\u0435\u043D\u0438\u0435 \u0438 \u0437\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u043F\u0435\u0441\u0447\u0430\u043D\u043E\u0439 \u0431\u0443\u0440\u0438.",
          en: "Improves evasion and protects from sandstorm damage."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/8/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 146,
        slug: "sand-rush",
        name: {
          ru: "\u041F\u0435\u0441\u0447\u0430\u043D\u0430\u044F \u0441\u043F\u0435\u0448\u043A\u0430",
          en: "Sand Rush"
        },
        description: {
          ru: "\u0423\u0434\u0432\u0430\u0438\u0432\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u0432 \u043F\u0435\u0441\u0447\u0430\u043D\u043E\u0439 \u0431\u0443\u0440\u0435.",
          en: "Doubles Speed in a sandstorm."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/146/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 89,
        slug: "earthquake",
        name: {
          ru: "\u0417\u0435\u043C\u043B\u0435\u0442\u0440\u044F\u0441\u0435\u043D\u0438\u0435",
          en: "Earthquake"
        },
        description: {
          ru: "\u0421\u043E\u0442\u0440\u044F\u0441\u0430\u0435\u0442 \u0437\u0435\u043C\u043B\u044E \u043C\u043E\u0449\u043D\u043E\u0439 \u0443\u0434\u0430\u0440\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Shakes the ground with a powerful shock wave."
        },
        type: "ground",
        power: 100,
        accuracy: 100,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/89/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/28/"
        }
      },
      {
        id: 91,
        slug: "dig",
        name: {
          ru: "\u041F\u043E\u0434\u043A\u043E\u043F",
          en: "Dig"
        },
        description: {
          ru: "\u0421\u043A\u0440\u044B\u0432\u0430\u0435\u0442\u0441\u044F \u043F\u043E\u0434 \u0437\u0435\u043C\u043B\u0451\u0439, \u0437\u0430\u0442\u0435\u043C \u0430\u0442\u0430\u043A\u0443\u0435\u0442 \u043D\u0430 \u0441\u043B\u0435\u0434\u0443\u044E\u0449\u0435\u043C \u0445\u043E\u0434\u0443.",
          en: "Digs underground before attacking on the next turn."
        },
        type: "ground",
        power: 80,
        accuracy: 100,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/91/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/28/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 27,
          name: {
            ru: "\u0421\u044D\u043D\u0434\u0448\u0440\u044E",
            en: "Sandshrew"
          }
        },
        {
          id: 28,
          name: {
            ru: "\u0421\u044D\u043D\u0434\u0441\u043B\u044D\u0448",
            en: "Sandslash"
          }
        }
      ],
      edges: [
        {
          from: 27,
          to: 28,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 22",
            en: "Level 22"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 35,
    slug: "clefairy",
    name: {
      ru: "\u041A\u043B\u0435\u0444\u0435\u0439\u0440\u0438",
      en: "Clefairy"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0444\u0435\u044F",
      en: "Fairy Pok\xE9mon"
    },
    description: {
      ru: "\u0412 \u043F\u043E\u043B\u043D\u043E\u043B\u0443\u043D\u0438\u0435 \u0435\u0433\u043E \u043C\u043E\u0436\u043D\u043E \u0432\u0441\u0442\u0440\u0435\u0442\u0438\u0442\u044C \u0432 \u0442\u0438\u0445\u0438\u0445 \u0433\u043E\u0440\u0430\u0445. \u0422\u0430\u043D\u0446\u044B \u0438 \u0441\u043B\u0430\u0431\u043E \u0441\u0432\u0435\u0442\u044F\u0449\u0438\u0435\u0441\u044F \u043A\u0440\u044B\u043B\u044C\u044F \u0441\u043E\u0437\u0434\u0430\u044E\u0442 \u0441\u043A\u0430\u0437\u043E\u0447\u043D\u043E\u0435 \u0437\u0440\u0435\u043B\u0438\u0449\u0435.",
      en: "Quiet mountains and full-moon nights are good places to spot its dances and softly glowing wings."
    },
    habitat: "mountain",
    types: [
      "fairy"
    ],
    height: 0.6,
    weight: 7.5,
    stats: [
      70,
      45,
      48,
      60,
      65,
      35
    ],
    abilities: [
      {
        id: 56,
        slug: "cute-charm",
        name: {
          ru: "\u041C\u0438\u043B\u043E\u0435 \u043E\u0447\u0430\u0440\u043E\u0432\u0430\u043D\u0438\u0435",
          en: "Cute Charm"
        },
        description: {
          ru: "\u041A\u043E\u043D\u0442\u0430\u043A\u0442\u043D\u0430\u044F \u0430\u0442\u0430\u043A\u0430 \u043C\u043E\u0436\u0435\u0442 \u0432\u043B\u044E\u0431\u0438\u0442\u044C \u0430\u0442\u0430\u043A\u0443\u044E\u0449\u0435\u0433\u043E \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Contact attacks may cause the attacker to become infatuated."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/56/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 98,
        slug: "magic-guard",
        name: {
          ru: "\u041C\u0430\u0433\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0437\u0430\u0449\u0438\u0442\u0430",
          en: "Magic Guard"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u043A\u043E\u0441\u0432\u0435\u043D\u043D\u043E\u0433\u043E \u0443\u0440\u043E\u043D\u0430, \u043D\u0430\u043F\u0440\u0438\u043C\u0435\u0440 \u043E\u0442 \u043F\u043E\u0433\u043E\u0434\u044B.",
          en: "Prevents indirect damage, such as weather damage."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/98/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 132,
        slug: "friend-guard",
        name: {
          ru: "\u0417\u0430\u0449\u0438\u0442\u0430 \u0434\u0440\u0443\u0433\u0430",
          en: "Friend Guard"
        },
        description: {
          ru: "\u0423\u043C\u0435\u043D\u044C\u0448\u0430\u0435\u0442 \u0443\u0440\u043E\u043D, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u043F\u043E\u043B\u0443\u0447\u0430\u044E\u0442 \u0441\u043E\u044E\u0437\u043D\u0438\u043A\u0438.",
          en: "Reduces damage taken by allies."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/132/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 1,
        slug: "pound",
        name: {
          ru: "\u0428\u043B\u0435\u043F\u043E\u043A",
          en: "Pound"
        },
        description: {
          ru: "\u041D\u0430\u043D\u043E\u0441\u0438\u0442 \u043F\u0440\u043E\u0441\u0442\u043E\u0439 \u0444\u0438\u0437\u0438\u0447\u0435\u0441\u043A\u0438\u0439 \u0443\u0434\u0430\u0440.",
          en: "Delivers a straightforward physical strike."
        },
        type: "normal",
        power: 40,
        accuracy: 100,
        pp: 35,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/1/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/35/"
        }
      },
      {
        id: 585,
        slug: "moonblast",
        name: {
          ru: "\u041B\u0443\u043D\u043D\u044B\u0439 \u0432\u0437\u0440\u044B\u0432",
          en: "Moonblast"
        },
        description: {
          ru: "\u0421\u0438\u043B\u0430 \u043B\u0443\u043D\u044B \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Moonlight energy may lower the target\u2019s Special Attack."
        },
        type: "fairy",
        power: 95,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 30,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/585/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 30
        },
        statChanges: [
          {
            stat: "special-attack",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/35/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 173,
          name: {
            ru: "\u041A\u043B\u0435\u0444\u0444\u0430",
            en: "Cleffa"
          }
        },
        {
          id: 35,
          name: {
            ru: "\u041A\u043B\u0435\u0444\u0435\u0439\u0440\u0438",
            en: "Clefairy"
          }
        },
        {
          id: 36,
          name: {
            ru: "\u041A\u043B\u0435\u0444\u0435\u0439\u0431\u043B",
            en: "Clefable"
          }
        }
      ],
      edges: [
        {
          from: 173,
          to: 35,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160",
            en: "Level up \xB7 friendship \u2265 160"
          },
          isDefault: true
        },
        {
          from: 35,
          to: 36,
          condition: {
            ru: "\u041B\u0443\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Moon Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 36,
    slug: "clefable",
    name: {
      ru: "\u041A\u043B\u0435\u0444\u0435\u0439\u0431\u043B",
      en: "Clefable"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0444\u0435\u044F",
      en: "Fairy Pok\xE9mon"
    },
    description: {
      ru: "\u0412 \u0442\u0438\u0445\u0438\u0435 \u044F\u0441\u043D\u044B\u0435 \u043D\u043E\u0447\u0438, \u043F\u043E \u043F\u0440\u0435\u0434\u0430\u043D\u0438\u044E, \u043F\u0440\u0438\u0441\u043B\u0443\u0448\u0438\u0432\u0430\u0435\u0442\u0441\u044F \u043A \u0433\u043E\u043B\u043E\u0441\u0430\u043C \u0441\u043E\u0440\u043E\u0434\u0438\u0447\u0435\u0439 \u043D\u0430 \u041B\u0443\u043D\u0435.",
      en: "Legends say it listens on quiet, clear nights for relatives calling from the moon."
    },
    habitat: "mountain",
    types: [
      "fairy"
    ],
    height: 1.3,
    weight: 40,
    stats: [
      95,
      70,
      73,
      95,
      90,
      60
    ],
    abilities: [
      {
        id: 56,
        slug: "cute-charm",
        name: {
          ru: "\u041C\u0438\u043B\u043E\u0435 \u043E\u0447\u0430\u0440\u043E\u0432\u0430\u043D\u0438\u0435",
          en: "Cute Charm"
        },
        description: {
          ru: "\u041A\u043E\u043D\u0442\u0430\u043A\u0442\u043D\u0430\u044F \u0430\u0442\u0430\u043A\u0430 \u043C\u043E\u0436\u0435\u0442 \u0432\u043B\u044E\u0431\u0438\u0442\u044C \u0430\u0442\u0430\u043A\u0443\u044E\u0449\u0435\u0433\u043E \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Contact attacks may cause the attacker to become infatuated."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/56/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 98,
        slug: "magic-guard",
        name: {
          ru: "\u041C\u0430\u0433\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0437\u0430\u0449\u0438\u0442\u0430",
          en: "Magic Guard"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u043A\u043E\u0441\u0432\u0435\u043D\u043D\u043E\u0433\u043E \u0443\u0440\u043E\u043D\u0430, \u043D\u0430\u043F\u0440\u0438\u043C\u0435\u0440 \u043E\u0442 \u043F\u043E\u0433\u043E\u0434\u044B.",
          en: "Prevents indirect damage, such as weather damage."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/98/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 109,
        slug: "unaware",
        name: {
          ru: "\u041D\u0435\u0437\u043D\u0430\u043D\u0438\u0435",
          en: "Unaware"
        },
        description: {
          ru: "\u041F\u0440\u0438 \u0440\u0430\u0441\u0447\u0451\u0442\u0435 \u0431\u043E\u044F \u0438\u0433\u043D\u043E\u0440\u0438\u0440\u0443\u0435\u0442 \u0438\u0437\u043C\u0435\u043D\u0435\u043D\u0438\u044F \u0445\u0430\u0440\u0430\u043A\u0442\u0435\u0440\u0438\u0441\u0442\u0438\u043A \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Ignores the opponent's stat changes when resolving attacks."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/109/",
        descriptionSource: "editorial-summary-of-core-ability"
      }
    ],
    moves: [
      {
        id: 585,
        slug: "moonblast",
        name: {
          ru: "\u041B\u0443\u043D\u043D\u044B\u0439 \u0432\u0437\u0440\u044B\u0432",
          en: "Moonblast"
        },
        description: {
          ru: "\u0421\u0438\u043B\u0430 \u043B\u0443\u043D\u044B \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Moonlight energy may lower the target\u2019s Special Attack."
        },
        type: "fairy",
        power: 95,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 30,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/585/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 30
        },
        statChanges: [
          {
            stat: "special-attack",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/36/"
        }
      },
      {
        id: 85,
        slug: "thunderbolt",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043C\u043E\u043B\u043D\u0438\u0438",
          en: "Thunderbolt"
        },
        description: {
          ru: "\u041C\u043E\u0449\u043D\u044B\u0439 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0439 \u0440\u0430\u0437\u0440\u044F\u0434 \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C \u0446\u0435\u043B\u044C.",
          en: "A strong electric bolt may paralyze the target."
        },
        type: "electric",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/85/",
        meta: {
          ailment: {
            name: "paralysis"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/36/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 173,
          name: {
            ru: "\u041A\u043B\u0435\u0444\u0444\u0430",
            en: "Cleffa"
          }
        },
        {
          id: 35,
          name: {
            ru: "\u041A\u043B\u0435\u0444\u0435\u0439\u0440\u0438",
            en: "Clefairy"
          }
        },
        {
          id: 36,
          name: {
            ru: "\u041A\u043B\u0435\u0444\u0435\u0439\u0431\u043B",
            en: "Clefable"
          }
        }
      ],
      edges: [
        {
          from: 173,
          to: 35,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160",
            en: "Level up \xB7 friendship \u2265 160"
          },
          isDefault: true
        },
        {
          from: 35,
          to: 36,
          condition: {
            ru: "\u041B\u0443\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Moon Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 37,
    slug: "vulpix",
    name: {
      ru: "\u0412\u0443\u043B\u044C\u043F\u0438\u043A\u0441",
      en: "Vulpix"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043B\u0438\u0441\u0430",
      en: "Fox Pok\xE9mon"
    },
    description: {
      ru: "\u0412\u043D\u0443\u0442\u0440\u0438 \u043D\u0435\u0433\u043E \u0433\u043E\u0440\u0438\u0442 \u043E\u0433\u043E\u043D\u044C, \u043A\u043E\u0442\u043E\u0440\u044B\u043C \u043E\u043D \u0430\u0442\u0430\u043A\u0443\u0435\u0442. \u0415\u0434\u0438\u043D\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0439 \u0445\u0432\u043E\u0441\u0442 \u0434\u0435\u0442\u0451\u043D\u044B\u0448\u0430 \u0441\u043E \u0432\u0440\u0435\u043C\u0435\u043D\u0435\u043C \u0440\u0430\u0437\u0434\u0435\u043B\u044F\u0435\u0442\u0441\u044F \u043D\u0430 \u0448\u0435\u0441\u0442\u044C.",
      en: "An inner fire fuels its attacks. Its single young tail eventually divides into six."
    },
    habitat: "grassland",
    types: [
      "fire"
    ],
    height: 0.6,
    weight: 9.9,
    stats: [
      38,
      41,
      40,
      50,
      65,
      65
    ],
    abilities: [
      {
        id: 18,
        slug: "flash-fire",
        name: {
          ru: "\u0412\u0441\u043F\u044B\u0448\u043A\u0430 \u043E\u0433\u043D\u044F",
          en: "Flash Fire"
        },
        description: {
          ru: "\u041F\u043E\u0433\u043B\u043E\u0449\u0430\u0435\u0442 \u043E\u0433\u043D\u0435\u043D\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438 \u0438 \u0443\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0439 \u043E\u0433\u043E\u043D\u044C.",
          en: "Absorbs Fire moves and boosts its own Fire attacks."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/18/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 70,
        slug: "drought",
        name: {
          ru: "\u0417\u0430\u0441\u0443\u0445\u0430",
          en: "Drought"
        },
        description: {
          ru: "\u041F\u0440\u0438 \u0432\u044B\u0445\u043E\u0434\u0435 \u0432 \u0431\u043E\u0439 \u0432\u044B\u0437\u044B\u0432\u0430\u0435\u0442 \u044F\u0440\u043A\u0438\u0439 \u0441\u043E\u043B\u043D\u0435\u0447\u043D\u044B\u0439 \u0441\u0432\u0435\u0442.",
          en: "Brings strong sunlight upon entering battle."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/70/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 52,
        slug: "ember",
        name: {
          ru: "\u0418\u0441\u043A\u0440\u044B",
          en: "Ember"
        },
        description: {
          ru: "\u041F\u043E\u0442\u043E\u043A \u043C\u0430\u043B\u0435\u043D\u044C\u043A\u0438\u0445 \u044F\u0437\u044B\u043A\u043E\u0432 \u043F\u043B\u0430\u043C\u0435\u043D\u0438 \u043C\u043E\u0436\u0435\u0442 \u0432\u044B\u0437\u0432\u0430\u0442\u044C \u043E\u0436\u043E\u0433.",
          en: "A burst of small flames may burn the target."
        },
        type: "fire",
        power: 40,
        accuracy: 100,
        pp: 25,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/52/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/37/"
        }
      },
      {
        id: 53,
        slug: "flamethrower",
        name: {
          ru: "\u041E\u0433\u043D\u0435\u043C\u0451\u0442",
          en: "Flamethrower"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u0441\u0438\u043B\u044C\u043D\u0443\u044E \u0441\u0442\u0440\u0443\u044E \u043F\u043B\u0430\u043C\u0435\u043D\u0438; \u043C\u043E\u0436\u0435\u0442 \u0432\u044B\u0437\u0432\u0430\u0442\u044C \u043E\u0436\u043E\u0433.",
          en: "Unleashes a powerful stream of fire that may cause a burn."
        },
        type: "fire",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/53/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/37/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 37,
          name: {
            ru: "\u0412\u0443\u043B\u044C\u043F\u0438\u043A\u0441",
            en: "Vulpix"
          }
        },
        {
          id: 38,
          name: {
            ru: "\u041D\u0430\u0439\u043D\u0442\u0435\u0439\u043B\u0441",
            en: "Ninetales"
          }
        }
      ],
      edges: [
        {
          from: 37,
          to: 38,
          condition: {
            ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Fire Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 38,
    slug: "ninetales",
    name: {
      ru: "\u041D\u0430\u0439\u043D\u0442\u0435\u0439\u043B\u0441",
      en: "Ninetales"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043B\u0438\u0441\u0430",
      en: "Fox Pok\xE9mon"
    },
    description: {
      ru: "\u0414\u0435\u0432\u044F\u0442\u044C \u0445\u0432\u043E\u0441\u0442\u043E\u0432 \u0438 \u0437\u043E\u043B\u043E\u0442\u0438\u0441\u0442\u0430\u044F \u0448\u0435\u0440\u0441\u0442\u044C \u043E\u043A\u0440\u0443\u0436\u0435\u043D\u044B \u043B\u0435\u0433\u0435\u043D\u0434\u0430\u043C\u0438. \u0413\u043E\u0432\u043E\u0440\u044F\u0442, \u043E\u043D \u0436\u0438\u0432\u0451\u0442 \u0442\u044B\u0441\u044F\u0447\u0443 \u043B\u0435\u0442.",
      en: "Legends link its nine tails and golden coat with sacred power and a thousand-year lifespan."
    },
    habitat: "grassland",
    types: [
      "fire"
    ],
    height: 1.1,
    weight: 19.9,
    stats: [
      73,
      76,
      75,
      81,
      100,
      100
    ],
    abilities: [
      {
        id: 18,
        slug: "flash-fire",
        name: {
          ru: "\u0412\u0441\u043F\u044B\u0448\u043A\u0430 \u043E\u0433\u043D\u044F",
          en: "Flash Fire"
        },
        description: {
          ru: "\u041F\u043E\u0433\u043B\u043E\u0449\u0430\u0435\u0442 \u043E\u0433\u043D\u0435\u043D\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438 \u0438 \u0443\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0439 \u043E\u0433\u043E\u043D\u044C.",
          en: "Absorbs Fire moves and boosts its own Fire attacks."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/18/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 70,
        slug: "drought",
        name: {
          ru: "\u0417\u0430\u0441\u0443\u0445\u0430",
          en: "Drought"
        },
        description: {
          ru: "\u041F\u0440\u0438 \u0432\u044B\u0445\u043E\u0434\u0435 \u0432 \u0431\u043E\u0439 \u0432\u044B\u0437\u044B\u0432\u0430\u0435\u0442 \u044F\u0440\u043A\u0438\u0439 \u0441\u043E\u043B\u043D\u0435\u0447\u043D\u044B\u0439 \u0441\u0432\u0435\u0442.",
          en: "Brings strong sunlight upon entering battle."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/70/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 53,
        slug: "flamethrower",
        name: {
          ru: "\u041E\u0433\u043D\u0435\u043C\u0451\u0442",
          en: "Flamethrower"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u0441\u0438\u043B\u044C\u043D\u0443\u044E \u0441\u0442\u0440\u0443\u044E \u043F\u043B\u0430\u043C\u0435\u043D\u0438; \u043C\u043E\u0436\u0435\u0442 \u0432\u044B\u0437\u0432\u0430\u0442\u044C \u043E\u0436\u043E\u0433.",
          en: "Unleashes a powerful stream of fire that may cause a burn."
        },
        type: "fire",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/53/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/38/"
        }
      },
      {
        id: 172,
        slug: "flame-wheel",
        name: {
          ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u043E\u0435 \u043A\u043E\u043B\u0435\u0441\u043E",
          en: "Flame Wheel"
        },
        description: {
          ru: "\u041E\u043A\u0440\u0443\u0436\u0430\u0435\u0442 \u0441\u0435\u0431\u044F \u043F\u043B\u0430\u043C\u0435\u043D\u0435\u043C \u0438 \u0430\u0442\u0430\u043A\u0443\u0435\u0442; \u043C\u043E\u0436\u0435\u0442 \u043E\u0431\u0436\u0435\u0447\u044C \u0446\u0435\u043B\u044C.",
          en: "Charges within a ring of fire and may burn the target."
        },
        type: "fire",
        power: 60,
        accuracy: 100,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/172/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/38/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 37,
          name: {
            ru: "\u0412\u0443\u043B\u044C\u043F\u0438\u043A\u0441",
            en: "Vulpix"
          }
        },
        {
          id: 38,
          name: {
            ru: "\u041D\u0430\u0439\u043D\u0442\u0435\u0439\u043B\u0441",
            en: "Ninetales"
          }
        }
      ],
      edges: [
        {
          from: 37,
          to: 38,
          condition: {
            ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Fire Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 39,
    slug: "jigglypuff",
    name: {
      ru: "\u0414\u0436\u0438\u0433\u0433\u043B\u0438\u043F\u0430\u0444\u0444",
      en: "Jigglypuff"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0448\u0430\u0440",
      en: "Balloon Pok\xE9mon"
    },
    description: {
      ru: "\u0423\u043F\u0440\u0430\u0432\u043B\u044F\u044F \u0441\u0432\u043E\u0438\u043C \u0433\u043E\u043B\u043E\u0441\u043E\u043C, \u0438\u0441\u043F\u043E\u043B\u043D\u044F\u0435\u0442 \u0437\u0430\u0433\u0430\u0434\u043E\u0447\u043D\u0443\u044E \u043C\u0435\u043B\u043E\u0434\u0438\u044E. \u0422\u043E\u0442, \u043A\u0442\u043E \u0441\u043B\u044B\u0448\u0438\u0442 \u044D\u0442\u0443 \u043F\u0435\u0441\u043D\u044E, \u0431\u044B\u0441\u0442\u0440\u043E \u043D\u0430\u0447\u0438\u043D\u0430\u0435\u0442 \u0437\u0430\u0441\u044B\u043F\u0430\u0442\u044C.",
      en: "Jigglypuff shapes its voice into a mysterious melody that makes listeners drowsy."
    },
    habitat: "grassland",
    types: [
      "normal",
      "fairy"
    ],
    height: 0.5,
    weight: 5.5,
    stats: [
      115,
      45,
      20,
      45,
      25,
      20
    ],
    abilities: [
      {
        id: 56,
        slug: "cute-charm",
        name: {
          ru: "\u041C\u0438\u043B\u043E\u0435 \u043E\u0447\u0430\u0440\u043E\u0432\u0430\u043D\u0438\u0435",
          en: "Cute Charm"
        },
        description: {
          ru: "\u041A\u043E\u043D\u0442\u0430\u043A\u0442\u043D\u0430\u044F \u0430\u0442\u0430\u043A\u0430 \u043C\u043E\u0436\u0435\u0442 \u0432\u043B\u044E\u0431\u0438\u0442\u044C \u0430\u0442\u0430\u043A\u0443\u044E\u0449\u0435\u0433\u043E \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Contact attacks may cause the attacker to become infatuated."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/56/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 172,
        slug: "competitive",
        name: {
          ru: "\u0421\u043E\u043F\u0435\u0440\u043D\u0438\u0447\u0435\u0441\u0442\u0432\u043E",
          en: "Competitive"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443, \u0435\u0441\u043B\u0438 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A \u0441\u043D\u0438\u0436\u0430\u0435\u0442 \u0445\u0430\u0440\u0430\u043A\u0442\u0435\u0440\u0438\u0441\u0442\u0438\u043A\u0438.",
          en: "Raises Special Attack when an opponent lowers a stat."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/172/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 132,
        slug: "friend-guard",
        name: {
          ru: "\u0417\u0430\u0449\u0438\u0442\u0430 \u0434\u0440\u0443\u0433\u0430",
          en: "Friend Guard"
        },
        description: {
          ru: "\u0423\u043C\u0435\u043D\u044C\u0448\u0430\u0435\u0442 \u0443\u0440\u043E\u043D, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u043F\u043E\u043B\u0443\u0447\u0430\u044E\u0442 \u0441\u043E\u044E\u0437\u043D\u0438\u043A\u0438.",
          en: "Reduces damage taken by allies."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/132/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 1,
        slug: "pound",
        name: {
          ru: "\u0428\u043B\u0435\u043F\u043E\u043A",
          en: "Pound"
        },
        description: {
          ru: "\u041D\u0430\u043D\u043E\u0441\u0438\u0442 \u043F\u0440\u043E\u0441\u0442\u043E\u0439 \u0444\u0438\u0437\u0438\u0447\u0435\u0441\u043A\u0438\u0439 \u0443\u0434\u0430\u0440.",
          en: "Delivers a straightforward physical strike."
        },
        type: "normal",
        power: 40,
        accuracy: 100,
        pp: 35,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/1/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/39/"
        }
      },
      {
        id: 304,
        slug: "hyper-voice",
        name: {
          ru: "\u0413\u0438\u043F\u0435\u0440\u0433\u043E\u043B\u043E\u0441",
          en: "Hyper Voice"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0443\u0435\u0442 \u043C\u043E\u0449\u043D\u043E\u0439 \u0437\u0432\u0443\u043A\u043E\u0432\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Attacks with a powerful wave of sound."
        },
        type: "normal",
        power: 90,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/304/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/39/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 174,
          name: {
            ru: "\u0418\u0433\u0433\u043B\u0438\u0431\u0430\u0444\u0444",
            en: "Igglybuff"
          }
        },
        {
          id: 39,
          name: {
            ru: "\u0414\u0436\u0438\u0433\u0433\u043B\u0438\u043F\u0430\u0444\u0444",
            en: "Jigglypuff"
          }
        },
        {
          id: 40,
          name: {
            ru: "\u0412\u0438\u0433\u0433\u043B\u0438\u0442\u0430\u0444\u0444",
            en: "Wigglytuff"
          }
        }
      ],
      edges: [
        {
          from: 174,
          to: 39,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160",
            en: "Level up \xB7 friendship \u2265 160"
          },
          isDefault: true
        },
        {
          from: 39,
          to: 40,
          condition: {
            ru: "\u041B\u0443\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Moon Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 40,
    slug: "wigglytuff",
    name: {
      ru: "\u0412\u0438\u0433\u0433\u043B\u0438\u0442\u0430\u0444\u0444",
      en: "Wigglytuff"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0448\u0430\u0440",
      en: "Balloon Pok\xE9mon"
    },
    description: {
      ru: "\u0413\u043E\u0440\u0434\u0438\u0442\u0441\u044F \u0441\u0432\u043E\u0435\u0439 \u043C\u044F\u0433\u043A\u043E\u0439 \u0448\u0435\u0440\u0441\u0442\u044C\u044E. \u0417\u0430\u0432\u0438\u0442\u043E\u043A \u043D\u0430 \u043B\u0431\u0443 \u043E\u0441\u043E\u0431\u0435\u043D\u043D\u043E \u043F\u0440\u0438\u044F\u0442\u0435\u043D \u043D\u0430 \u043E\u0449\u0443\u043F\u044C.",
      en: "Its prized fur is exceptionally fine, especially the soft curl on its forehead."
    },
    habitat: "grassland",
    types: [
      "normal",
      "fairy"
    ],
    height: 1,
    weight: 12,
    stats: [
      140,
      70,
      45,
      85,
      50,
      45
    ],
    abilities: [
      {
        id: 56,
        slug: "cute-charm",
        name: {
          ru: "\u041C\u0438\u043B\u043E\u0435 \u043E\u0447\u0430\u0440\u043E\u0432\u0430\u043D\u0438\u0435",
          en: "Cute Charm"
        },
        description: {
          ru: "\u041A\u043E\u043D\u0442\u0430\u043A\u0442\u043D\u0430\u044F \u0430\u0442\u0430\u043A\u0430 \u043C\u043E\u0436\u0435\u0442 \u0432\u043B\u044E\u0431\u0438\u0442\u044C \u0430\u0442\u0430\u043A\u0443\u044E\u0449\u0435\u0433\u043E \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Contact attacks may cause the attacker to become infatuated."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/56/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 172,
        slug: "competitive",
        name: {
          ru: "\u0421\u043E\u043F\u0435\u0440\u043D\u0438\u0447\u0435\u0441\u0442\u0432\u043E",
          en: "Competitive"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443, \u0435\u0441\u043B\u0438 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A \u0441\u043D\u0438\u0436\u0430\u0435\u0442 \u0445\u0430\u0440\u0430\u043A\u0442\u0435\u0440\u0438\u0441\u0442\u0438\u043A\u0438.",
          en: "Raises Special Attack when an opponent lowers a stat."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/172/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 119,
        slug: "frisk",
        name: {
          ru: "\u041E\u0431\u044B\u0441\u043A",
          en: "Frisk"
        },
        description: {
          ru: "\u041F\u0440\u0438 \u0432\u044B\u0445\u043E\u0434\u0435 \u0432 \u0431\u043E\u0439 \u0443\u0437\u043D\u0430\u0451\u0442, \u043A\u0430\u043A\u043E\u0439 \u043F\u0440\u0435\u0434\u043C\u0435\u0442 \u0434\u0435\u0440\u0436\u0438\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A.",
          en: "Reveals an opponent's held item upon entering battle."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/119/",
        descriptionSource: "editorial-summary-of-core-ability"
      }
    ],
    moves: [
      {
        id: 304,
        slug: "hyper-voice",
        name: {
          ru: "\u0413\u0438\u043F\u0435\u0440\u0433\u043E\u043B\u043E\u0441",
          en: "Hyper Voice"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0443\u0435\u0442 \u043C\u043E\u0449\u043D\u043E\u0439 \u0437\u0432\u0443\u043A\u043E\u0432\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Attacks with a powerful wave of sound."
        },
        type: "normal",
        power: 90,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/304/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/40/"
        }
      },
      {
        id: 34,
        slug: "body-slam",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u0442\u0435\u043B\u043E\u043C",
          en: "Body Slam"
        },
        description: {
          ru: "\u041E\u0431\u0440\u0443\u0448\u0438\u0432\u0430\u0435\u0442\u0441\u044F \u043D\u0430 \u0446\u0435\u043B\u044C \u0432\u0441\u0435\u043C \u0442\u0435\u043B\u043E\u043C; \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C.",
          en: "Slams into the target and may cause paralysis."
        },
        type: "normal",
        power: 85,
        accuracy: 100,
        pp: 15,
        damageClass: "physical",
        priority: 0,
        effectChance: 30,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/34/",
        meta: {
          ailment: {
            name: "paralysis"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 30,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/40/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 174,
          name: {
            ru: "\u0418\u0433\u0433\u043B\u0438\u0431\u0430\u0444\u0444",
            en: "Igglybuff"
          }
        },
        {
          id: 39,
          name: {
            ru: "\u0414\u0436\u0438\u0433\u0433\u043B\u0438\u043F\u0430\u0444\u0444",
            en: "Jigglypuff"
          }
        },
        {
          id: 40,
          name: {
            ru: "\u0412\u0438\u0433\u0433\u043B\u0438\u0442\u0430\u0444\u0444",
            en: "Wigglytuff"
          }
        }
      ],
      edges: [
        {
          from: 174,
          to: 39,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160",
            en: "Level up \xB7 friendship \u2265 160"
          },
          isDefault: true
        },
        {
          from: 39,
          to: 40,
          condition: {
            ru: "\u041B\u0443\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Moon Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 41,
    slug: "zubat",
    name: {
      ru: "\u0417\u0443\u0431\u0430\u0442",
      en: "Zubat"
    },
    genus: {
      ru: "\u041B\u0435\u0442\u0443\u0447\u0430\u044F \u043C\u044B\u0448\u044C",
      en: "Bat Pok\xE9mon"
    },
    description: {
      ru: "\u041E\u0431\u0438\u0442\u0430\u0435\u0442 \u0432 \u0442\u0451\u043C\u043D\u044B\u0445 \u043F\u0435\u0449\u0435\u0440\u0430\u0445. \u0412\u043C\u0435\u0441\u0442\u043E \u0437\u0440\u0435\u043D\u0438\u044F \u043E\u0440\u0438\u0435\u043D\u0442\u0438\u0440\u0443\u0435\u0442\u0441\u044F \u043F\u043E \u0437\u0432\u0443\u043A\u043E\u0432\u044B\u043C \u0432\u043E\u043B\u043D\u0430\u043C, \u043A\u043E\u0442\u043E\u0440\u044B\u0435 \u0438\u0437\u0434\u0430\u0451\u0442 \u0432\u043E \u0432\u0440\u0435\u043C\u044F \u043F\u043E\u043B\u0451\u0442\u0430.",
      en: "At home in dark caves, Zubat navigates by emitting sound waves rather than relying on sight."
    },
    habitat: "cave",
    types: [
      "poison",
      "flying"
    ],
    height: 0.8,
    weight: 7.5,
    stats: [
      40,
      45,
      35,
      30,
      40,
      55
    ],
    abilities: [
      {
        id: 39,
        slug: "inner-focus",
        name: {
          ru: "\u0421\u043E\u0441\u0440\u0435\u0434\u043E\u0442\u043E\u0447\u0435\u043D\u043D\u043E\u0441\u0442\u044C",
          en: "Inner Focus"
        },
        description: {
          ru: "\u041D\u0435 \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0438\u0441\u043F\u0443\u0433\u0430\u0442\u044C\u0441\u044F \u0438 \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Prevents flinching."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/39/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 151,
        slug: "infiltrator",
        name: {
          ru: "\u041F\u0440\u043E\u043D\u0438\u043A\u043D\u043E\u0432\u0435\u043D\u0438\u0435",
          en: "Infiltrator"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0438 \u043F\u0440\u043E\u0445\u043E\u0434\u044F\u0442 \u0441\u043A\u0432\u043E\u0437\u044C \u0437\u0430\u0449\u0438\u0442\u043D\u044B\u0435 \u044D\u043A\u0440\u0430\u043D\u044B \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Moves bypass the opponent\u2019s protective screens."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/151/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 44,
        slug: "bite",
        name: {
          ru: "\u0423\u043A\u0443\u0441",
          en: "Bite"
        },
        description: {
          ru: "\u041A\u0443\u0441\u0430\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430; \u043C\u043E\u0436\u0435\u0442 \u0437\u0430\u0441\u0442\u0430\u0432\u0438\u0442\u044C \u0435\u0433\u043E \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Bites the target and may make it flinch."
        },
        type: "dark",
        power: 60,
        accuracy: 100,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: 30,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/44/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 30,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/41/"
        }
      },
      {
        id: 17,
        slug: "wing-attack",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043A\u0440\u044B\u043B\u043E\u043C",
          en: "Wing Attack"
        },
        description: {
          ru: "\u041D\u0430\u043D\u043E\u0441\u0438\u0442 \u0443\u0434\u0430\u0440 \u0448\u0438\u0440\u043E\u043A\u043E \u0440\u0430\u0441\u043A\u0440\u044B\u0442\u044B\u043C\u0438 \u043A\u0440\u044B\u043B\u044C\u044F\u043C\u0438.",
          en: "Strikes the target with outstretched wings."
        },
        type: "flying",
        power: 60,
        accuracy: 100,
        pp: 35,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/17/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/41/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 41,
          name: {
            ru: "\u0417\u0443\u0431\u0430\u0442",
            en: "Zubat"
          }
        },
        {
          id: 42,
          name: {
            ru: "\u0413\u043E\u043B\u0431\u0430\u0442",
            en: "Golbat"
          }
        },
        {
          id: 169,
          name: {
            ru: "\u041A\u0440\u043E\u0431\u0430\u0442",
            en: "Crobat"
          }
        }
      ],
      edges: [
        {
          from: 41,
          to: 42,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 22",
            en: "Level 22"
          },
          isDefault: true
        },
        {
          from: 42,
          to: 169,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160",
            en: "Level up \xB7 friendship \u2265 160"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 42,
    slug: "golbat",
    name: {
      ru: "\u0413\u043E\u043B\u0431\u0430\u0442",
      en: "Golbat"
    },
    genus: {
      ru: "\u041B\u0435\u0442\u0443\u0447\u0430\u044F \u043C\u044B\u0448\u044C",
      en: "Bat Pok\xE9mon"
    },
    description: {
      ru: "\u041F\u043E\u043B\u044B\u043C\u0438 \u043A\u043B\u044B\u043A\u0430\u043C\u0438 \u043F\u0440\u043E\u043A\u0430\u043B\u044B\u0432\u0430\u0435\u0442 \u0434\u043E\u0431\u044B\u0447\u0443 \u0438 \u043F\u044C\u0451\u0442 \u043A\u0440\u043E\u0432\u044C, \u0441\u043B\u043E\u0432\u043D\u043E \u0447\u0435\u0440\u0435\u0437 \u0442\u0440\u0443\u0431\u043E\u0447\u043A\u0438.",
      en: "Hollow fangs pierce prey and draw blood like tiny drinking straws."
    },
    habitat: "cave",
    types: [
      "poison",
      "flying"
    ],
    height: 1.6,
    weight: 55,
    stats: [
      75,
      80,
      70,
      65,
      75,
      90
    ],
    abilities: [
      {
        id: 39,
        slug: "inner-focus",
        name: {
          ru: "\u0421\u043E\u0441\u0440\u0435\u0434\u043E\u0442\u043E\u0447\u0435\u043D\u043D\u043E\u0441\u0442\u044C",
          en: "Inner Focus"
        },
        description: {
          ru: "\u041D\u0435 \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0438\u0441\u043F\u0443\u0433\u0430\u0442\u044C\u0441\u044F \u0438 \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Prevents flinching."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/39/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 151,
        slug: "infiltrator",
        name: {
          ru: "\u041F\u0440\u043E\u043D\u0438\u043A\u043D\u043E\u0432\u0435\u043D\u0438\u0435",
          en: "Infiltrator"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0438 \u043F\u0440\u043E\u0445\u043E\u0434\u044F\u0442 \u0441\u043A\u0432\u043E\u0437\u044C \u0437\u0430\u0449\u0438\u0442\u043D\u044B\u0435 \u044D\u043A\u0440\u0430\u043D\u044B \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Moves bypass the opponent\u2019s protective screens."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/151/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 17,
        slug: "wing-attack",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043A\u0440\u044B\u043B\u043E\u043C",
          en: "Wing Attack"
        },
        description: {
          ru: "\u041D\u0430\u043D\u043E\u0441\u0438\u0442 \u0443\u0434\u0430\u0440 \u0448\u0438\u0440\u043E\u043A\u043E \u0440\u0430\u0441\u043A\u0440\u044B\u0442\u044B\u043C\u0438 \u043A\u0440\u044B\u043B\u044C\u044F\u043C\u0438.",
          en: "Strikes the target with outstretched wings."
        },
        type: "flying",
        power: 60,
        accuracy: 100,
        pp: 35,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/17/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/42/"
        }
      },
      {
        id: 16,
        slug: "gust",
        name: {
          ru: "\u041F\u043E\u0440\u044B\u0432 \u0432\u0435\u0442\u0440\u0430",
          en: "Gust"
        },
        description: {
          ru: "\u0411\u044C\u0451\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u0441\u0438\u043B\u044C\u043D\u044B\u043C \u0432\u043E\u0437\u0434\u0443\u0448\u043D\u044B\u043C \u043F\u043E\u0442\u043E\u043A\u043E\u043C.",
          en: "Buffets the target with a strong gust of wind."
        },
        type: "flying",
        power: 40,
        accuracy: 100,
        pp: 35,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/16/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/42/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 41,
          name: {
            ru: "\u0417\u0443\u0431\u0430\u0442",
            en: "Zubat"
          }
        },
        {
          id: 42,
          name: {
            ru: "\u0413\u043E\u043B\u0431\u0430\u0442",
            en: "Golbat"
          }
        },
        {
          id: 169,
          name: {
            ru: "\u041A\u0440\u043E\u0431\u0430\u0442",
            en: "Crobat"
          }
        }
      ],
      edges: [
        {
          from: 41,
          to: 42,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 22",
            en: "Level 22"
          },
          isDefault: true
        },
        {
          from: 42,
          to: 169,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160",
            en: "Level up \xB7 friendship \u2265 160"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 43,
    slug: "oddish",
    name: {
      ru: "\u041E\u0434\u0434\u0438\u0448",
      en: "Oddish"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0442\u0440\u0430\u0432\u0430",
      en: "Weed Pok\xE9mon"
    },
    description: {
      ru: "\u0414\u043D\u0451\u043C \u0441\u043A\u0440\u044B\u0432\u0430\u0435\u0442\u0441\u044F \u0432 \u043F\u0440\u043E\u0445\u043B\u0430\u0434\u043D\u043E\u0439 \u0437\u0435\u043C\u043B\u0435, \u0430 \u043D\u043E\u0447\u044C\u044E \u0440\u0430\u0441\u0442\u0451\u0442 \u0432 \u043B\u0443\u043D\u043D\u043E\u043C \u0441\u0432\u0435\u0442\u0435. \u041B\u0438\u0441\u0442\u044C\u044F \u043D\u0430 \u0433\u043E\u043B\u043E\u0432\u0435 \u0432\u044B\u0434\u0430\u044E\u0442 \u0435\u0433\u043E \u0440\u0430\u0441\u0442\u0438\u0442\u0435\u043B\u044C\u043D\u0443\u044E \u043F\u0440\u0438\u0440\u043E\u0434\u0443.",
      en: "Oddish hides in cool soil by day and grows in moonlight at night."
    },
    habitat: "grassland",
    types: [
      "grass",
      "poison"
    ],
    height: 0.5,
    weight: 5.4,
    stats: [
      45,
      50,
      55,
      75,
      65,
      30
    ],
    abilities: [
      {
        id: 34,
        slug: "chlorophyll",
        name: {
          ru: "\u0425\u043B\u043E\u0440\u043E\u0444\u0438\u043B\u043B",
          en: "Chlorophyll"
        },
        description: {
          ru: "\u0423\u0434\u0432\u0430\u0438\u0432\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u0440\u0438 \u044F\u0440\u043A\u043E\u043C \u0441\u043E\u043B\u043D\u0435\u0447\u043D\u043E\u043C \u0441\u0432\u0435\u0442\u0435.",
          en: "Doubles Speed in strong sunlight."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/34/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 50,
        slug: "run-away",
        name: {
          ru: "\u041F\u043E\u0431\u0435\u0433",
          en: "Run Away"
        },
        description: {
          ru: "\u041F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0443\u0441\u043F\u0435\u0448\u043D\u043E \u0443\u0431\u0435\u0436\u0430\u0442\u044C \u043E\u0442 \u0434\u0438\u043A\u043E\u0433\u043E \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u0430.",
          en: "Ensures escape from wild Pok\xE9mon battles."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/50/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 71,
        slug: "absorb",
        name: {
          ru: "\u041F\u043E\u0433\u043B\u043E\u0449\u0435\u043D\u0438\u0435",
          en: "Absorb"
        },
        description: {
          ru: "\u041F\u043E\u0433\u043B\u043E\u0449\u0430\u0435\u0442 \u044D\u043D\u0435\u0440\u0433\u0438\u044E \u0446\u0435\u043B\u0438 \u0438 \u0432\u043E\u0441\u0441\u0442\u0430\u043D\u0430\u0432\u043B\u0438\u0432\u0430\u0435\u0442 \u0447\u0430\u0441\u0442\u044C \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u044F.",
          en: "Drains the target\u2019s energy to restore some HP."
        },
        type: "grass",
        power: 20,
        accuracy: 100,
        pp: 25,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/71/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-heal"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 50,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/43/"
        }
      },
      {
        id: 51,
        slug: "acid",
        name: {
          ru: "\u041A\u0438\u0441\u043B\u043E\u0442\u0430",
          en: "Acid"
        },
        description: {
          ru: "\u041E\u0431\u0440\u044B\u0437\u0433\u0438\u0432\u0430\u0435\u0442 \u0446\u0435\u043B\u044C \u043A\u0438\u0441\u043B\u043E\u0442\u043E\u0439; \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443.",
          en: "Sprays acid and may lower the target\u2019s Special Defense."
        },
        type: "poison",
        power: 40,
        accuracy: 100,
        pp: 30,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/51/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 10
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/43/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 43,
          name: {
            ru: "\u041E\u0434\u0434\u0438\u0448",
            en: "Oddish"
          }
        },
        {
          id: 44,
          name: {
            ru: "\u0413\u043B\u0443\u043C",
            en: "Gloom"
          }
        },
        {
          id: 45,
          name: {
            ru: "\u0412\u0430\u0439\u043B\u043F\u043B\u0443\u043C",
            en: "Vileplume"
          }
        },
        {
          id: 182,
          name: {
            ru: "\u0411\u0435\u043B\u043B\u043E\u0441\u0441\u043E\u043C",
            en: "Bellossom"
          }
        }
      ],
      edges: [
        {
          from: 43,
          to: 44,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 21",
            en: "Level 21"
          },
          isDefault: true
        },
        {
          from: 44,
          to: 45,
          condition: {
            ru: "\u041B\u0438\u0441\u0442\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Leaf Stone"
          },
          isDefault: true
        },
        {
          from: 44,
          to: 182,
          condition: {
            ru: "\u0421\u043E\u043B\u043D\u0435\u0447\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Sun Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 44,
    slug: "gloom",
    name: {
      ru: "\u0413\u043B\u0443\u043C",
      en: "Gloom"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0442\u0440\u0430\u0432\u0430",
      en: "Weed Pok\xE9mon"
    },
    description: {
      ru: "\u0418\u0437\u043E \u0440\u0442\u0430 \u0432\u044B\u0434\u0435\u043B\u044F\u0435\u0442\u0441\u044F \u0441\u043B\u0430\u0434\u043A\u0438\u0439, \u043E\u0447\u0435\u043D\u044C \u043B\u0438\u043F\u043A\u0438\u0439 \u043C\u0451\u0434, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u043B\u0435\u0433\u043A\u043E \u043F\u0440\u0438\u043D\u044F\u0442\u044C \u0437\u0430 \u0441\u043B\u044E\u043D\u0443.",
      en: "The sticky sweetness dripping from its mouth is honey rather than ordinary drool."
    },
    habitat: "grassland",
    types: [
      "grass",
      "poison"
    ],
    height: 0.8,
    weight: 8.6,
    stats: [
      60,
      65,
      70,
      85,
      75,
      40
    ],
    abilities: [
      {
        id: 34,
        slug: "chlorophyll",
        name: {
          ru: "\u0425\u043B\u043E\u0440\u043E\u0444\u0438\u043B\u043B",
          en: "Chlorophyll"
        },
        description: {
          ru: "\u0423\u0434\u0432\u0430\u0438\u0432\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u0440\u0438 \u044F\u0440\u043A\u043E\u043C \u0441\u043E\u043B\u043D\u0435\u0447\u043D\u043E\u043C \u0441\u0432\u0435\u0442\u0435.",
          en: "Doubles Speed in strong sunlight."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/34/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 1,
        slug: "stench",
        name: {
          ru: "\u0417\u043B\u043E\u0432\u043E\u043D\u0438\u0435",
          en: "Stench"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0438 \u043C\u043E\u0433\u0443\u0442 \u0437\u0430\u0441\u0442\u0430\u0432\u0438\u0442\u044C \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u0438\u0441\u043F\u0443\u0433\u0430\u0442\u044C\u0441\u044F.",
          en: "Its attacks may cause the opponent to flinch."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/1/",
        descriptionSource: "editorial-summary-of-core-ability"
      }
    ],
    moves: [
      {
        id: 75,
        slug: "razor-leaf",
        name: {
          ru: "\u041E\u0441\u0442\u0440\u044B\u0435 \u043B\u0438\u0441\u0442\u044C\u044F",
          en: "Razor Leaf"
        },
        description: {
          ru: "\u0411\u0440\u043E\u0441\u0430\u0435\u0442 \u043E\u0441\u0442\u0440\u044B\u0435 \u043B\u0438\u0441\u0442\u044C\u044F; \u0448\u0430\u043D\u0441 \u043A\u0440\u0438\u0442\u0438\u0447\u0435\u0441\u043A\u043E\u0433\u043E \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u044F \u0432\u044B\u0448\u0435.",
          en: "Throws sharp leaves with an increased critical-hit chance."
        },
        type: "grass",
        power: 55,
        accuracy: 95,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/75/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 1,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/44/"
        }
      },
      {
        id: 51,
        slug: "acid",
        name: {
          ru: "\u041A\u0438\u0441\u043B\u043E\u0442\u0430",
          en: "Acid"
        },
        description: {
          ru: "\u041E\u0431\u0440\u044B\u0437\u0433\u0438\u0432\u0430\u0435\u0442 \u0446\u0435\u043B\u044C \u043A\u0438\u0441\u043B\u043E\u0442\u043E\u0439; \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443.",
          en: "Sprays acid and may lower the target\u2019s Special Defense."
        },
        type: "poison",
        power: 40,
        accuracy: 100,
        pp: 30,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/51/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 10
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/44/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 43,
          name: {
            ru: "\u041E\u0434\u0434\u0438\u0448",
            en: "Oddish"
          }
        },
        {
          id: 44,
          name: {
            ru: "\u0413\u043B\u0443\u043C",
            en: "Gloom"
          }
        },
        {
          id: 45,
          name: {
            ru: "\u0412\u0430\u0439\u043B\u043F\u043B\u0443\u043C",
            en: "Vileplume"
          }
        },
        {
          id: 182,
          name: {
            ru: "\u0411\u0435\u043B\u043B\u043E\u0441\u0441\u043E\u043C",
            en: "Bellossom"
          }
        }
      ],
      edges: [
        {
          from: 43,
          to: 44,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 21",
            en: "Level 21"
          },
          isDefault: true
        },
        {
          from: 44,
          to: 45,
          condition: {
            ru: "\u041B\u0438\u0441\u0442\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Leaf Stone"
          },
          isDefault: true
        },
        {
          from: 44,
          to: 182,
          condition: {
            ru: "\u0421\u043E\u043B\u043D\u0435\u0447\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Sun Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 45,
    slug: "vileplume",
    name: {
      ru: "\u0412\u0430\u0439\u043B\u043F\u043B\u0443\u043C",
      en: "Vileplume"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0446\u0432\u0435\u0442\u043E\u043A",
      en: "Flower Pok\xE9mon"
    },
    description: {
      ru: "\u0411\u043E\u043B\u044C\u0448\u0438\u0435 \u043B\u0435\u043F\u0435\u0441\u0442\u043A\u0438 \u0432\u043C\u0435\u0449\u0430\u044E\u0442 \u043C\u043D\u043E\u0433\u043E \u044F\u0434\u043E\u0432\u0438\u0442\u043E\u0439 \u043F\u044B\u043B\u044C\u0446\u044B, \u043D\u043E \u0434\u0435\u043B\u0430\u044E\u0442 \u0433\u043E\u043B\u043E\u0432\u0443 \u0442\u044F\u0436\u0451\u043B\u043E\u0439.",
      en: "Larger petals hold more toxic pollen and make its enormous head harder to support."
    },
    habitat: "grassland",
    types: [
      "grass",
      "poison"
    ],
    height: 1.2,
    weight: 18.6,
    stats: [
      75,
      80,
      85,
      110,
      90,
      50
    ],
    abilities: [
      {
        id: 34,
        slug: "chlorophyll",
        name: {
          ru: "\u0425\u043B\u043E\u0440\u043E\u0444\u0438\u043B\u043B",
          en: "Chlorophyll"
        },
        description: {
          ru: "\u0423\u0434\u0432\u0430\u0438\u0432\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u0440\u0438 \u044F\u0440\u043A\u043E\u043C \u0441\u043E\u043B\u043D\u0435\u0447\u043D\u043E\u043C \u0441\u0432\u0435\u0442\u0435.",
          en: "Doubles Speed in strong sunlight."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/34/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 27,
        slug: "effect-spore",
        name: {
          ru: "\u0421\u043F\u043E\u0440\u044B",
          en: "Effect Spore"
        },
        description: {
          ru: "\u041A\u043E\u043D\u0442\u0430\u043A\u0442 \u0441 \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u043E\u043C \u043C\u043E\u0436\u0435\u0442 \u0432\u044B\u0437\u0432\u0430\u0442\u044C \u0441\u043E\u043D, \u043E\u0442\u0440\u0430\u0432\u043B\u0435\u043D\u0438\u0435 \u0438\u043B\u0438 \u043F\u0430\u0440\u0430\u043B\u0438\u0447.",
          en: "Contact with this Pok\xE9mon may cause sleep, poison or paralysis."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/27/",
        descriptionSource: "editorial-summary-of-core-ability"
      }
    ],
    moves: [
      {
        id: 75,
        slug: "razor-leaf",
        name: {
          ru: "\u041E\u0441\u0442\u0440\u044B\u0435 \u043B\u0438\u0441\u0442\u044C\u044F",
          en: "Razor Leaf"
        },
        description: {
          ru: "\u0411\u0440\u043E\u0441\u0430\u0435\u0442 \u043E\u0441\u0442\u0440\u044B\u0435 \u043B\u0438\u0441\u0442\u044C\u044F; \u0448\u0430\u043D\u0441 \u043A\u0440\u0438\u0442\u0438\u0447\u0435\u0441\u043A\u043E\u0433\u043E \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u044F \u0432\u044B\u0448\u0435.",
          en: "Throws sharp leaves with an increased critical-hit chance."
        },
        type: "grass",
        power: 55,
        accuracy: 95,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/75/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 1,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/45/"
        }
      },
      {
        id: 51,
        slug: "acid",
        name: {
          ru: "\u041A\u0438\u0441\u043B\u043E\u0442\u0430",
          en: "Acid"
        },
        description: {
          ru: "\u041E\u0431\u0440\u044B\u0437\u0433\u0438\u0432\u0430\u0435\u0442 \u0446\u0435\u043B\u044C \u043A\u0438\u0441\u043B\u043E\u0442\u043E\u0439; \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443.",
          en: "Sprays acid and may lower the target\u2019s Special Defense."
        },
        type: "poison",
        power: 40,
        accuracy: 100,
        pp: 30,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/51/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 10
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/45/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 43,
          name: {
            ru: "\u041E\u0434\u0434\u0438\u0448",
            en: "Oddish"
          }
        },
        {
          id: 44,
          name: {
            ru: "\u0413\u043B\u0443\u043C",
            en: "Gloom"
          }
        },
        {
          id: 45,
          name: {
            ru: "\u0412\u0430\u0439\u043B\u043F\u043B\u0443\u043C",
            en: "Vileplume"
          }
        },
        {
          id: 182,
          name: {
            ru: "\u0411\u0435\u043B\u043B\u043E\u0441\u0441\u043E\u043C",
            en: "Bellossom"
          }
        }
      ],
      edges: [
        {
          from: 43,
          to: 44,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 21",
            en: "Level 21"
          },
          isDefault: true
        },
        {
          from: 44,
          to: 45,
          condition: {
            ru: "\u041B\u0438\u0441\u0442\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Leaf Stone"
          },
          isDefault: true
        },
        {
          from: 44,
          to: 182,
          condition: {
            ru: "\u0421\u043E\u043B\u043D\u0435\u0447\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Sun Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 50,
    slug: "diglett",
    name: {
      ru: "\u0414\u0438\u0433\u043B\u0435\u0442\u0442",
      en: "Diglett"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043A\u0440\u043E\u0442",
      en: "Mole Pok\xE9mon"
    },
    description: {
      ru: "\u041F\u0440\u043E\u043A\u043B\u0430\u0434\u044B\u0432\u0430\u0435\u0442 \u043D\u0435\u0433\u043B\u0443\u0431\u043E\u043A\u0438\u0435 \u0442\u043E\u043D\u043D\u0435\u043B\u0438. \u0423\u0437\u043D\u0430\u0442\u044C \u0435\u0433\u043E \u043C\u0430\u0440\u0448\u0440\u0443\u0442 \u043C\u043E\u0436\u043D\u043E \u043F\u043E \u043F\u0440\u0438\u043F\u043E\u0434\u043D\u044F\u0442\u043E\u0439 \u0437\u0435\u043C\u043B\u0435 \u043D\u0430 \u043F\u043E\u0432\u0435\u0440\u0445\u043D\u043E\u0441\u0442\u0438.",
      en: "Its shallow tunnels leave raised trails of earth, making its underground route easy to follow."
    },
    habitat: "cave",
    types: [
      "ground"
    ],
    height: 0.2,
    weight: 0.8,
    stats: [
      10,
      55,
      25,
      35,
      45,
      95
    ],
    abilities: [
      {
        id: 8,
        slug: "sand-veil",
        name: {
          ru: "\u041F\u0435\u0441\u0447\u0430\u043D\u0430\u044F \u0437\u0430\u0432\u0435\u0441\u0430",
          en: "Sand Veil"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0443\u043A\u043B\u043E\u043D\u0435\u043D\u0438\u0435 \u0438 \u0437\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u043F\u0435\u0441\u0447\u0430\u043D\u043E\u0439 \u0431\u0443\u0440\u0438.",
          en: "Improves evasion and protects from sandstorm damage."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/8/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 71,
        slug: "arena-trap",
        name: {
          ru: "\u041F\u0435\u0441\u0447\u0430\u043D\u0430\u044F \u043B\u043E\u0432\u0443\u0448\u043A\u0430",
          en: "Arena Trap"
        },
        description: {
          ru: "\u041C\u0435\u0448\u0430\u0435\u0442 \u043D\u0430\u0437\u0435\u043C\u043D\u044B\u043C \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430\u043C \u0441\u0431\u0435\u0436\u0430\u0442\u044C \u0438\u043B\u0438 \u0441\u043C\u0435\u043D\u0438\u0442\u044C\u0441\u044F.",
          en: "Stops grounded opponents from fleeing or switching."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/71/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 159,
        slug: "sand-force",
        name: {
          ru: "\u0421\u0438\u043B\u0430 \u043F\u0435\u0441\u043A\u0430",
          en: "Sand Force"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u043A\u0430\u043C\u0435\u043D\u043D\u044B\u0435, \u0437\u0435\u043C\u043B\u044F\u043D\u044B\u0435 \u0438 \u0441\u0442\u0430\u043B\u044C\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438 \u0432 \u043F\u0435\u0441\u0447\u0430\u043D\u043E\u0439 \u0431\u0443\u0440\u0435.",
          en: "Boosts Rock, Ground and Steel moves in a sandstorm."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/159/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 91,
        slug: "dig",
        name: {
          ru: "\u041F\u043E\u0434\u043A\u043E\u043F",
          en: "Dig"
        },
        description: {
          ru: "\u0421\u043A\u0440\u044B\u0432\u0430\u0435\u0442\u0441\u044F \u043F\u043E\u0434 \u0437\u0435\u043C\u043B\u0451\u0439, \u0437\u0430\u0442\u0435\u043C \u0430\u0442\u0430\u043A\u0443\u0435\u0442 \u043D\u0430 \u0441\u043B\u0435\u0434\u0443\u044E\u0449\u0435\u043C \u0445\u043E\u0434\u0443.",
          en: "Digs underground before attacking on the next turn."
        },
        type: "ground",
        power: 80,
        accuracy: 100,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/91/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/50/"
        }
      },
      {
        id: 89,
        slug: "earthquake",
        name: {
          ru: "\u0417\u0435\u043C\u043B\u0435\u0442\u0440\u044F\u0441\u0435\u043D\u0438\u0435",
          en: "Earthquake"
        },
        description: {
          ru: "\u0421\u043E\u0442\u0440\u044F\u0441\u0430\u0435\u0442 \u0437\u0435\u043C\u043B\u044E \u043C\u043E\u0449\u043D\u043E\u0439 \u0443\u0434\u0430\u0440\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Shakes the ground with a powerful shock wave."
        },
        type: "ground",
        power: 100,
        accuracy: 100,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/89/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/50/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 50,
          name: {
            ru: "\u0414\u0438\u0433\u043B\u0435\u0442\u0442",
            en: "Diglett"
          }
        },
        {
          id: 51,
          name: {
            ru: "\u0414\u0430\u0433\u0442\u0440\u0438\u043E",
            en: "Dugtrio"
          }
        }
      ],
      edges: [
        {
          from: 50,
          to: 51,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 26",
            en: "Level 26"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 51,
    slug: "dugtrio",
    name: {
      ru: "\u0414\u0430\u0433\u0442\u0440\u0438\u043E",
      en: "Dugtrio"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043A\u0440\u043E\u0442",
      en: "Mole Pok\xE9mon"
    },
    description: {
      ru: "\u0422\u0440\u0438 \u0414\u0438\u0433\u043B\u0435\u0442\u0442\u0430 \u0432\u043C\u0435\u0441\u0442\u0435 \u0440\u043E\u044E\u0442 \u0442\u043E\u043D\u043D\u0435\u043B\u0438 \u043D\u0430 \u043E\u0433\u0440\u043E\u043C\u043D\u043E\u0439 \u0433\u043B\u0443\u0431\u0438\u043D\u0435.",
      en: "Three Diglett work together, excavating tunnels far beneath the surface."
    },
    habitat: "cave",
    types: [
      "ground"
    ],
    height: 0.7,
    weight: 33.3,
    stats: [
      35,
      100,
      50,
      50,
      70,
      120
    ],
    abilities: [
      {
        id: 8,
        slug: "sand-veil",
        name: {
          ru: "\u041F\u0435\u0441\u0447\u0430\u043D\u0430\u044F \u0437\u0430\u0432\u0435\u0441\u0430",
          en: "Sand Veil"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0443\u043A\u043B\u043E\u043D\u0435\u043D\u0438\u0435 \u0438 \u0437\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u043F\u0435\u0441\u0447\u0430\u043D\u043E\u0439 \u0431\u0443\u0440\u0438.",
          en: "Improves evasion and protects from sandstorm damage."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/8/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 71,
        slug: "arena-trap",
        name: {
          ru: "\u041F\u0435\u0441\u0447\u0430\u043D\u0430\u044F \u043B\u043E\u0432\u0443\u0448\u043A\u0430",
          en: "Arena Trap"
        },
        description: {
          ru: "\u041C\u0435\u0448\u0430\u0435\u0442 \u043D\u0430\u0437\u0435\u043C\u043D\u044B\u043C \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430\u043C \u0441\u0431\u0435\u0436\u0430\u0442\u044C \u0438\u043B\u0438 \u0441\u043C\u0435\u043D\u0438\u0442\u044C\u0441\u044F.",
          en: "Stops grounded opponents from fleeing or switching."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/71/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 159,
        slug: "sand-force",
        name: {
          ru: "\u0421\u0438\u043B\u0430 \u043F\u0435\u0441\u043A\u0430",
          en: "Sand Force"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u043A\u0430\u043C\u0435\u043D\u043D\u044B\u0435, \u0437\u0435\u043C\u043B\u044F\u043D\u044B\u0435 \u0438 \u0441\u0442\u0430\u043B\u044C\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438 \u0432 \u043F\u0435\u0441\u0447\u0430\u043D\u043E\u0439 \u0431\u0443\u0440\u0435.",
          en: "Boosts Rock, Ground and Steel moves in a sandstorm."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/159/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 89,
        slug: "earthquake",
        name: {
          ru: "\u0417\u0435\u043C\u043B\u0435\u0442\u0440\u044F\u0441\u0435\u043D\u0438\u0435",
          en: "Earthquake"
        },
        description: {
          ru: "\u0421\u043E\u0442\u0440\u044F\u0441\u0430\u0435\u0442 \u0437\u0435\u043C\u043B\u044E \u043C\u043E\u0449\u043D\u043E\u0439 \u0443\u0434\u0430\u0440\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Shakes the ground with a powerful shock wave."
        },
        type: "ground",
        power: 100,
        accuracy: 100,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/89/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/51/"
        }
      },
      {
        id: 91,
        slug: "dig",
        name: {
          ru: "\u041F\u043E\u0434\u043A\u043E\u043F",
          en: "Dig"
        },
        description: {
          ru: "\u0421\u043A\u0440\u044B\u0432\u0430\u0435\u0442\u0441\u044F \u043F\u043E\u0434 \u0437\u0435\u043C\u043B\u0451\u0439, \u0437\u0430\u0442\u0435\u043C \u0430\u0442\u0430\u043A\u0443\u0435\u0442 \u043D\u0430 \u0441\u043B\u0435\u0434\u0443\u044E\u0449\u0435\u043C \u0445\u043E\u0434\u0443.",
          en: "Digs underground before attacking on the next turn."
        },
        type: "ground",
        power: 80,
        accuracy: 100,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/91/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/51/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 50,
          name: {
            ru: "\u0414\u0438\u0433\u043B\u0435\u0442\u0442",
            en: "Diglett"
          }
        },
        {
          id: 51,
          name: {
            ru: "\u0414\u0430\u0433\u0442\u0440\u0438\u043E",
            en: "Dugtrio"
          }
        }
      ],
      edges: [
        {
          from: 50,
          to: 51,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 26",
            en: "Level 26"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 54,
    slug: "psyduck",
    name: {
      ru: "\u041F\u0441\u0430\u0439\u0434\u0430\u043A",
      en: "Psyduck"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0443\u0442\u043A\u0430",
      en: "Duck Pok\xE9mon"
    },
    description: {
      ru: "\u041F\u043E\u0441\u0442\u043E\u044F\u043D\u043D\u043E \u0441\u0442\u0440\u0430\u0434\u0430\u0435\u0442 \u043E\u0442 \u0433\u043E\u043B\u043E\u0432\u043D\u043E\u0439 \u0431\u043E\u043B\u0438. \u041A\u043E\u0433\u0434\u0430 \u0431\u043E\u043B\u044C \u0443\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442\u0441\u044F, \u0441\u043A\u0440\u044B\u0442\u0430\u044F \u043F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0441\u0438\u043B\u0430 \u043C\u043E\u0436\u0435\u0442 \u043D\u0435\u043E\u0436\u0438\u0434\u0430\u043D\u043D\u043E \u0432\u044B\u0440\u0432\u0430\u0442\u044C\u0441\u044F \u043D\u0430\u0440\u0443\u0436\u0443.",
      en: "Persistent headaches can trigger sudden bursts of Psyduck\u2019s hidden psychic power."
    },
    habitat: "water",
    types: [
      "water"
    ],
    height: 0.8,
    weight: 19.6,
    stats: [
      50,
      52,
      48,
      65,
      50,
      55
    ],
    abilities: [
      {
        id: 6,
        slug: "damp",
        name: {
          ru: "\u0412\u043B\u0430\u0436\u043D\u043E\u0441\u0442\u044C",
          en: "Damp"
        },
        description: {
          ru: "\u041F\u0440\u0435\u0434\u043E\u0442\u0432\u0440\u0430\u0449\u0430\u0435\u0442 \u0441\u0430\u043C\u043E\u0443\u043D\u0438\u0447\u0442\u043E\u0436\u0435\u043D\u0438\u0435 \u0438 \u0432\u0437\u0440\u044B\u0432\u043D\u044B\u0435 \u044D\u0444\u0444\u0435\u043A\u0442\u044B.",
          en: "Prevents self-destructing moves and explosive effects."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/6/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 13,
        slug: "cloud-nine",
        name: {
          ru: "\u0411\u0435\u0437\u043E\u0431\u043B\u0430\u0447\u043D\u043E\u0441\u0442\u044C",
          en: "Cloud Nine"
        },
        description: {
          ru: "\u041D\u0435\u0439\u0442\u0440\u0430\u043B\u0438\u0437\u0443\u0435\u0442 \u0432\u043B\u0438\u044F\u043D\u0438\u0435 \u043F\u043E\u0433\u043E\u0434\u044B \u043D\u0430 \u0431\u043E\u0439.",
          en: "Suppresses the effects of weather in battle."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/13/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 33,
        slug: "swift-swim",
        name: {
          ru: "\u0411\u044B\u0441\u0442\u0440\u043E\u0435 \u043F\u043B\u0430\u0432\u0430\u043D\u0438\u0435",
          en: "Swift Swim"
        },
        description: {
          ru: "\u0423\u0434\u0432\u0430\u0438\u0432\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u043E\u0434 \u0434\u043E\u0436\u0434\u0451\u043C.",
          en: "Doubles Speed in rain."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/33/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 93,
        slug: "confusion",
        name: {
          ru: "\u0417\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u043E",
          en: "Confusion"
        },
        description: {
          ru: "\u041F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0430\u0442\u0430\u043A\u0430, \u043A\u043E\u0442\u043E\u0440\u0430\u044F \u043C\u043E\u0436\u0435\u0442 \u0437\u0430\u043F\u0443\u0442\u0430\u0442\u044C \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "A psychic strike that may confuse the target."
        },
        type: "psychic",
        power: 50,
        accuracy: 100,
        pp: 25,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/93/",
        meta: {
          ailment: {
            name: "confusion"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: 2,
          max_turns: 5,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/54/"
        }
      },
      {
        id: 55,
        slug: "water-gun",
        name: {
          ru: "\u0412\u043E\u0434\u044F\u043D\u0430\u044F \u043F\u0443\u0448\u043A\u0430",
          en: "Water Gun"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u043D\u0430\u043F\u0440\u0430\u0432\u043B\u0435\u043D\u043D\u0443\u044E \u0441\u0442\u0440\u0443\u044E \u0432\u043E\u0434\u044B.",
          en: "Fires a focused jet of water."
        },
        type: "water",
        power: 40,
        accuracy: 100,
        pp: 25,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/55/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/54/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 54,
          name: {
            ru: "\u041F\u0441\u0430\u0439\u0434\u0430\u043A",
            en: "Psyduck"
          }
        },
        {
          id: 55,
          name: {
            ru: "\u0413\u043E\u043B\u0434\u0430\u043A",
            en: "Golduck"
          }
        }
      ],
      edges: [
        {
          from: 54,
          to: 55,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 33",
            en: "Level 33"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 55,
    slug: "golduck",
    name: {
      ru: "\u0413\u043E\u043B\u0434\u0430\u043A",
      en: "Golduck"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0443\u0442\u043A\u0430",
      en: "Duck Pok\xE9mon"
    },
    description: {
      ru: "\u0421\u0438\u043B\u044C\u043D\u043E\u0435 \u0442\u0435\u043B\u043E \u0438 \u043F\u0435\u0440\u0435\u043F\u043E\u043D\u043A\u0438 \u043F\u043E\u043C\u043E\u0433\u0430\u044E\u0442 \u0443\u0432\u0435\u0440\u0435\u043D\u043D\u043E \u043F\u043B\u0430\u0432\u0430\u0442\u044C \u0434\u0430\u0436\u0435 \u0441\u0440\u0435\u0434\u0438 \u0431\u043E\u043B\u044C\u0448\u0438\u0445 \u0432\u043E\u043B\u043D.",
      en: "A strong body and webbed limbs let Golduck swim through rough seas."
    },
    habitat: "water",
    types: [
      "water"
    ],
    height: 1.7,
    weight: 76.6,
    stats: [
      80,
      82,
      78,
      95,
      80,
      85
    ],
    abilities: [
      {
        id: 6,
        slug: "damp",
        name: {
          ru: "\u0412\u043B\u0430\u0436\u043D\u043E\u0441\u0442\u044C",
          en: "Damp"
        },
        description: {
          ru: "\u041F\u0440\u0435\u0434\u043E\u0442\u0432\u0440\u0430\u0449\u0430\u0435\u0442 \u0441\u0430\u043C\u043E\u0443\u043D\u0438\u0447\u0442\u043E\u0436\u0435\u043D\u0438\u0435 \u0438 \u0432\u0437\u0440\u044B\u0432\u043D\u044B\u0435 \u044D\u0444\u0444\u0435\u043A\u0442\u044B.",
          en: "Prevents self-destructing moves and explosive effects."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/6/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 13,
        slug: "cloud-nine",
        name: {
          ru: "\u0411\u0435\u0437\u043E\u0431\u043B\u0430\u0447\u043D\u043E\u0441\u0442\u044C",
          en: "Cloud Nine"
        },
        description: {
          ru: "\u041D\u0435\u0439\u0442\u0440\u0430\u043B\u0438\u0437\u0443\u0435\u0442 \u0432\u043B\u0438\u044F\u043D\u0438\u0435 \u043F\u043E\u0433\u043E\u0434\u044B \u043D\u0430 \u0431\u043E\u0439.",
          en: "Suppresses the effects of weather in battle."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/13/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 33,
        slug: "swift-swim",
        name: {
          ru: "\u0411\u044B\u0441\u0442\u0440\u043E\u0435 \u043F\u043B\u0430\u0432\u0430\u043D\u0438\u0435",
          en: "Swift Swim"
        },
        description: {
          ru: "\u0423\u0434\u0432\u0430\u0438\u0432\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u043E\u0434 \u0434\u043E\u0436\u0434\u0451\u043C.",
          en: "Doubles Speed in rain."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/33/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 57,
        slug: "surf",
        name: {
          ru: "\u0421\u0451\u0440\u0444\u0438\u043D\u0433",
          en: "Surf"
        },
        description: {
          ru: "\u041D\u0430\u043A\u0440\u044B\u0432\u0430\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u0431\u043E\u043B\u044C\u0448\u043E\u0439 \u0432\u043E\u0434\u044F\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Sweeps over opponents with a large wave of water."
        },
        type: "water",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/57/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/55/"
        }
      },
      {
        id: 352,
        slug: "water-pulse",
        name: {
          ru: "\u0412\u043E\u0434\u043D\u044B\u0439 \u0438\u043C\u043F\u0443\u043B\u044C\u0441",
          en: "Water Pulse"
        },
        description: {
          ru: "\u0412\u043E\u0434\u044F\u043D\u0430\u044F \u0432\u043E\u043B\u043D\u0430 \u043C\u043E\u0436\u0435\u0442 \u043F\u0440\u0438\u0432\u0435\u0441\u0442\u0438 \u0446\u0435\u043B\u044C \u0432 \u0437\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u043E.",
          en: "A pulsing wave of water may confuse the target."
        },
        type: "water",
        power: 60,
        accuracy: 100,
        pp: 20,
        damageClass: "special",
        priority: 0,
        effectChance: 20,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/352/",
        meta: {
          ailment: {
            name: "confusion"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: 2,
          max_turns: 5,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 20,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/55/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 54,
          name: {
            ru: "\u041F\u0441\u0430\u0439\u0434\u0430\u043A",
            en: "Psyduck"
          }
        },
        {
          id: 55,
          name: {
            ru: "\u0413\u043E\u043B\u0434\u0430\u043A",
            en: "Golduck"
          }
        }
      ],
      edges: [
        {
          from: 54,
          to: 55,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 33",
            en: "Level 33"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 58,
    slug: "growlithe",
    name: {
      ru: "\u0413\u0440\u043E\u0443\u043B\u0438\u0442",
      en: "Growlithe"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0449\u0435\u043D\u043E\u043A",
      en: "Puppy Pok\xE9mon"
    },
    description: {
      ru: "\u041F\u0430\u0442\u0440\u0443\u043B\u0438\u0440\u0443\u0435\u0442 \u0441\u0432\u043E\u044E \u0442\u0435\u0440\u0440\u0438\u0442\u043E\u0440\u0438\u044E \u0432\u043C\u0435\u0441\u0442\u0435 \u0441 \u0441\u043E\u0440\u043E\u0434\u0438\u0447\u0435\u043C. \u0412 \u0435\u0433\u043E \u0448\u0435\u0440\u0441\u0442\u0438 \u0432\u0441\u0442\u0440\u0435\u0447\u0430\u044E\u0442\u0441\u044F \u043A\u043E\u043C\u043F\u043E\u043D\u0435\u043D\u0442\u044B \u0432\u0443\u043B\u043A\u0430\u043D\u0438\u0447\u0435\u0441\u043A\u0438\u0445 \u043F\u043E\u0440\u043E\u0434.",
      en: "Growlithe patrols its territory in pairs. Its fur contains material associated with volcanic rock."
    },
    habitat: "grassland",
    types: [
      "fire"
    ],
    height: 0.7,
    weight: 19,
    stats: [
      55,
      70,
      45,
      70,
      50,
      60
    ],
    abilities: [
      {
        id: 22,
        slug: "intimidate",
        name: {
          ru: "\u0423\u0441\u0442\u0440\u0430\u0448\u0435\u043D\u0438\u0435",
          en: "Intimidate"
        },
        description: {
          ru: "\u041F\u0440\u0438 \u0432\u044B\u0445\u043E\u0434\u0435 \u0432 \u0431\u043E\u0439 \u0441\u043D\u0438\u0436\u0430\u0435\u0442 \u0441\u0438\u043B\u0443 \u0430\u0442\u0430\u043A\u0438 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u043E\u0432.",
          en: "Lowers opponents\u2019 Attack on entering battle."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/22/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 18,
        slug: "flash-fire",
        name: {
          ru: "\u0412\u0441\u043F\u044B\u0448\u043A\u0430 \u043E\u0433\u043D\u044F",
          en: "Flash Fire"
        },
        description: {
          ru: "\u041F\u043E\u0433\u043B\u043E\u0449\u0430\u0435\u0442 \u043E\u0433\u043D\u0435\u043D\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438 \u0438 \u0443\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0439 \u043E\u0433\u043E\u043D\u044C.",
          en: "Absorbs Fire moves and boosts its own Fire attacks."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/18/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 154,
        slug: "justified",
        name: {
          ru: "\u0421\u043F\u0440\u0430\u0432\u0435\u0434\u043B\u0438\u0432\u043E\u0441\u0442\u044C",
          en: "Justified"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0441\u0438\u043B\u0443 \u0430\u0442\u0430\u043A\u0438 \u043F\u043E\u0441\u043B\u0435 \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u044F \u0442\u0451\u043C\u043D\u043E\u0439 \u0430\u0442\u0430\u043A\u043E\u0439.",
          en: "Raises Attack after being hit by a Dark move."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/154/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 52,
        slug: "ember",
        name: {
          ru: "\u0418\u0441\u043A\u0440\u044B",
          en: "Ember"
        },
        description: {
          ru: "\u041F\u043E\u0442\u043E\u043A \u043C\u0430\u043B\u0435\u043D\u044C\u043A\u0438\u0445 \u044F\u0437\u044B\u043A\u043E\u0432 \u043F\u043B\u0430\u043C\u0435\u043D\u0438 \u043C\u043E\u0436\u0435\u0442 \u0432\u044B\u0437\u0432\u0430\u0442\u044C \u043E\u0436\u043E\u0433.",
          en: "A burst of small flames may burn the target."
        },
        type: "fire",
        power: 40,
        accuracy: 100,
        pp: 25,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/52/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/58/"
        }
      },
      {
        id: 172,
        slug: "flame-wheel",
        name: {
          ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u043E\u0435 \u043A\u043E\u043B\u0435\u0441\u043E",
          en: "Flame Wheel"
        },
        description: {
          ru: "\u041E\u043A\u0440\u0443\u0436\u0430\u0435\u0442 \u0441\u0435\u0431\u044F \u043F\u043B\u0430\u043C\u0435\u043D\u0435\u043C \u0438 \u0430\u0442\u0430\u043A\u0443\u0435\u0442; \u043C\u043E\u0436\u0435\u0442 \u043E\u0431\u0436\u0435\u0447\u044C \u0446\u0435\u043B\u044C.",
          en: "Charges within a ring of fire and may burn the target."
        },
        type: "fire",
        power: 60,
        accuracy: 100,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/172/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/58/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 58,
          name: {
            ru: "\u0413\u0440\u043E\u0443\u043B\u0438\u0442",
            en: "Growlithe"
          }
        },
        {
          id: 59,
          name: {
            ru: "\u0410\u0440\u043A\u0430\u043D\u0430\u0439\u043D",
            en: "Arcanine"
          }
        }
      ],
      edges: [
        {
          from: 58,
          to: 59,
          condition: {
            ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Fire Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 59,
    slug: "arcanine",
    name: {
      ru: "\u0410\u0440\u043A\u0430\u043D\u0430\u0439\u043D",
      en: "Arcanine"
    },
    genus: {
      ru: "\u041B\u0435\u0433\u0435\u043D\u0434\u0430\u0440\u043D\u044B\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Legendary Pok\xE9mon"
    },
    description: {
      ru: "\u0412 \u0431\u043E\u044E \u043B\u043E\u0432\u043A\u043E \u043C\u0435\u043D\u044F\u0435\u0442 \u043D\u0430\u043F\u0440\u0430\u0432\u043B\u0435\u043D\u0438\u0435 \u0438 \u0430\u0442\u0430\u043A\u0443\u0435\u0442 \u043A\u043B\u044B\u043A\u0430\u043C\u0438, \u043E\u043A\u0443\u0442\u0430\u043D\u043D\u044B\u043C\u0438 \u043F\u043B\u0430\u043C\u0435\u043D\u0435\u043C.",
      en: "Despite its size, Arcanine moves nimbly and attacks with flame-covered fangs."
    },
    habitat: "grassland",
    types: [
      "fire"
    ],
    height: 1.9,
    weight: 155,
    stats: [
      90,
      110,
      80,
      100,
      80,
      95
    ],
    abilities: [
      {
        id: 22,
        slug: "intimidate",
        name: {
          ru: "\u0423\u0441\u0442\u0440\u0430\u0448\u0435\u043D\u0438\u0435",
          en: "Intimidate"
        },
        description: {
          ru: "\u041F\u0440\u0438 \u0432\u044B\u0445\u043E\u0434\u0435 \u0432 \u0431\u043E\u0439 \u0441\u043D\u0438\u0436\u0430\u0435\u0442 \u0441\u0438\u043B\u0443 \u0430\u0442\u0430\u043A\u0438 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u043E\u0432.",
          en: "Lowers opponents\u2019 Attack on entering battle."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/22/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 18,
        slug: "flash-fire",
        name: {
          ru: "\u0412\u0441\u043F\u044B\u0448\u043A\u0430 \u043E\u0433\u043D\u044F",
          en: "Flash Fire"
        },
        description: {
          ru: "\u041F\u043E\u0433\u043B\u043E\u0449\u0430\u0435\u0442 \u043E\u0433\u043D\u0435\u043D\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438 \u0438 \u0443\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0439 \u043E\u0433\u043E\u043D\u044C.",
          en: "Absorbs Fire moves and boosts its own Fire attacks."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/18/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 154,
        slug: "justified",
        name: {
          ru: "\u0421\u043F\u0440\u0430\u0432\u0435\u0434\u043B\u0438\u0432\u043E\u0441\u0442\u044C",
          en: "Justified"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0441\u0438\u043B\u0443 \u0430\u0442\u0430\u043A\u0438 \u043F\u043E\u0441\u043B\u0435 \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u044F \u0442\u0451\u043C\u043D\u043E\u0439 \u0430\u0442\u0430\u043A\u043E\u0439.",
          en: "Raises Attack after being hit by a Dark move."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/154/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 53,
        slug: "flamethrower",
        name: {
          ru: "\u041E\u0433\u043D\u0435\u043C\u0451\u0442",
          en: "Flamethrower"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u0441\u0438\u043B\u044C\u043D\u0443\u044E \u0441\u0442\u0440\u0443\u044E \u043F\u043B\u0430\u043C\u0435\u043D\u0438; \u043C\u043E\u0436\u0435\u0442 \u0432\u044B\u0437\u0432\u0430\u0442\u044C \u043E\u0436\u043E\u0433.",
          en: "Unleashes a powerful stream of fire that may cause a burn."
        },
        type: "fire",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/53/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/59/"
        }
      },
      {
        id: 172,
        slug: "flame-wheel",
        name: {
          ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u043E\u0435 \u043A\u043E\u043B\u0435\u0441\u043E",
          en: "Flame Wheel"
        },
        description: {
          ru: "\u041E\u043A\u0440\u0443\u0436\u0430\u0435\u0442 \u0441\u0435\u0431\u044F \u043F\u043B\u0430\u043C\u0435\u043D\u0435\u043C \u0438 \u0430\u0442\u0430\u043A\u0443\u0435\u0442; \u043C\u043E\u0436\u0435\u0442 \u043E\u0431\u0436\u0435\u0447\u044C \u0446\u0435\u043B\u044C.",
          en: "Charges within a ring of fire and may burn the target."
        },
        type: "fire",
        power: 60,
        accuracy: 100,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/172/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/59/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 58,
          name: {
            ru: "\u0413\u0440\u043E\u0443\u043B\u0438\u0442",
            en: "Growlithe"
          }
        },
        {
          id: 59,
          name: {
            ru: "\u0410\u0440\u043A\u0430\u043D\u0430\u0439\u043D",
            en: "Arcanine"
          }
        }
      ],
      edges: [
        {
          from: 58,
          to: 59,
          condition: {
            ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Fire Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 63,
    slug: "abra",
    name: {
      ru: "\u0410\u0431\u0440\u0430",
      en: "Abra"
    },
    genus: {
      ru: "\u041F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0438\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Psi Pok\xE9mon"
    },
    description: {
      ru: "\u0421\u043F\u0438\u0442 \u0431\u043E\u043B\u044C\u0448\u0443\u044E \u0447\u0430\u0441\u0442\u044C \u0441\u0443\u0442\u043E\u043A. \u0414\u0430\u0436\u0435 \u0432\u043E \u0441\u043D\u0435 \u0441\u043E\u0445\u0440\u0430\u043D\u044F\u0435\u0442 \u043A\u043E\u043D\u0442\u0440\u043E\u043B\u044C \u043D\u0430\u0434 \u043F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u043E\u0439 \u0441\u0438\u043B\u043E\u0439 \u0438 \u0442\u0435\u043B\u0435\u043F\u043E\u0440\u0442\u0438\u0440\u0443\u0435\u0442\u0441\u044F \u043F\u0440\u0438 \u043E\u043F\u0430\u0441\u043D\u043E\u0441\u0442\u0438.",
      en: "Abra sleeps for much of the day, but can still use psychic power to teleport away from danger."
    },
    habitat: "urban",
    types: [
      "psychic"
    ],
    height: 0.9,
    weight: 19.5,
    stats: [
      25,
      20,
      15,
      105,
      55,
      90
    ],
    abilities: [
      {
        id: 28,
        slug: "synchronize",
        name: {
          ru: "\u0421\u0438\u043D\u0445\u0440\u043E\u043D\u0438\u0437\u0430\u0446\u0438\u044F",
          en: "Synchronize"
        },
        description: {
          ru: "\u041F\u0435\u0440\u0435\u0434\u0430\u0451\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0443 \u043F\u043E\u043B\u0443\u0447\u0435\u043D\u043D\u044B\u0435 \u043E\u0436\u043E\u0433, \u043E\u0442\u0440\u0430\u0432\u043B\u0435\u043D\u0438\u0435 \u0438\u043B\u0438 \u043F\u0430\u0440\u0430\u043B\u0438\u0447.",
          en: "Passes burns, poison or paralysis back to the opponent."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/28/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 39,
        slug: "inner-focus",
        name: {
          ru: "\u0421\u043E\u0441\u0440\u0435\u0434\u043E\u0442\u043E\u0447\u0435\u043D\u043D\u043E\u0441\u0442\u044C",
          en: "Inner Focus"
        },
        description: {
          ru: "\u041D\u0435 \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0438\u0441\u043F\u0443\u0433\u0430\u0442\u044C\u0441\u044F \u0438 \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Prevents flinching."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/39/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 98,
        slug: "magic-guard",
        name: {
          ru: "\u041C\u0430\u0433\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0437\u0430\u0449\u0438\u0442\u0430",
          en: "Magic Guard"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u043A\u043E\u0441\u0432\u0435\u043D\u043D\u043E\u0433\u043E \u0443\u0440\u043E\u043D\u0430, \u043D\u0430\u043F\u0440\u0438\u043C\u0435\u0440 \u043E\u0442 \u043F\u043E\u0433\u043E\u0434\u044B.",
          en: "Prevents indirect damage, such as weather damage."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/98/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 94,
        slug: "psychic",
        name: {
          ru: "\u041F\u0441\u0438\u0445\u043E\u043A\u0438\u043D\u0435\u0437",
          en: "Psychic"
        },
        description: {
          ru: "\u041F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0441\u0438\u043B\u0430 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443 \u0446\u0435\u043B\u0438.",
          en: "Psychic force may lower the target\u2019s Special Defense."
        },
        type: "psychic",
        power: 90,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/94/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 10
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/63/"
        }
      },
      {
        id: 247,
        slug: "shadow-ball",
        name: {
          ru: "\u0422\u0435\u043D\u0435\u0432\u043E\u0439 \u0448\u0430\u0440",
          en: "Shadow Ball"
        },
        description: {
          ru: "\u0421\u0433\u0443\u0441\u0442\u043E\u043A \u0442\u0451\u043C\u043D\u043E\u0439 \u044D\u043D\u0435\u0440\u0433\u0438\u0438 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443.",
          en: "A sphere of shadow energy may lower Special Defense."
        },
        type: "ghost",
        power: 80,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 20,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/247/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 20
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/63/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 63,
          name: {
            ru: "\u0410\u0431\u0440\u0430",
            en: "Abra"
          }
        },
        {
          id: 64,
          name: {
            ru: "\u041A\u0430\u0434\u0430\u0431\u0440\u0430",
            en: "Kadabra"
          }
        },
        {
          id: 65,
          name: {
            ru: "\u0410\u043B\u0430\u043A\u0430\u0437\u0430\u043C",
            en: "Alakazam"
          }
        }
      ],
      edges: [
        {
          from: 63,
          to: 64,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 16",
            en: "Level 16"
          },
          isDefault: true
        },
        {
          from: 64,
          to: 65,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D",
            en: "Trade"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 64,
    slug: "kadabra",
    name: {
      ru: "\u041A\u0430\u0434\u0430\u0431\u0440\u0430",
      en: "Kadabra"
    },
    genus: {
      ru: "\u041F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0438\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Psi Pok\xE9mon"
    },
    description: {
      ru: "\u0414\u0435\u0440\u0436\u0438\u0442 \u043B\u043E\u0436\u043A\u0443, \u043A\u043E\u0442\u043E\u0440\u0430\u044F, \u043F\u043E \u043F\u0440\u0435\u0434\u043F\u043E\u043B\u043E\u0436\u0435\u043D\u0438\u044E \u0438\u0441\u0441\u043B\u0435\u0434\u043E\u0432\u0430\u0442\u0435\u043B\u0435\u0439, \u0443\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0435\u0433\u043E \u043C\u043E\u0437\u0433\u043E\u0432\u044B\u0435 \u0432\u043E\u043B\u043D\u044B.",
      en: "Researchers suspect its spoon helps amplify the psychic waves it produces."
    },
    habitat: "urban",
    types: [
      "psychic"
    ],
    height: 1.3,
    weight: 56.5,
    stats: [
      40,
      35,
      30,
      120,
      70,
      105
    ],
    abilities: [
      {
        id: 28,
        slug: "synchronize",
        name: {
          ru: "\u0421\u0438\u043D\u0445\u0440\u043E\u043D\u0438\u0437\u0430\u0446\u0438\u044F",
          en: "Synchronize"
        },
        description: {
          ru: "\u041F\u0435\u0440\u0435\u0434\u0430\u0451\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0443 \u043F\u043E\u043B\u0443\u0447\u0435\u043D\u043D\u044B\u0435 \u043E\u0436\u043E\u0433, \u043E\u0442\u0440\u0430\u0432\u043B\u0435\u043D\u0438\u0435 \u0438\u043B\u0438 \u043F\u0430\u0440\u0430\u043B\u0438\u0447.",
          en: "Passes burns, poison or paralysis back to the opponent."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/28/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 39,
        slug: "inner-focus",
        name: {
          ru: "\u0421\u043E\u0441\u0440\u0435\u0434\u043E\u0442\u043E\u0447\u0435\u043D\u043D\u043E\u0441\u0442\u044C",
          en: "Inner Focus"
        },
        description: {
          ru: "\u041D\u0435 \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0438\u0441\u043F\u0443\u0433\u0430\u0442\u044C\u0441\u044F \u0438 \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Prevents flinching."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/39/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 98,
        slug: "magic-guard",
        name: {
          ru: "\u041C\u0430\u0433\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0437\u0430\u0449\u0438\u0442\u0430",
          en: "Magic Guard"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u043A\u043E\u0441\u0432\u0435\u043D\u043D\u043E\u0433\u043E \u0443\u0440\u043E\u043D\u0430, \u043D\u0430\u043F\u0440\u0438\u043C\u0435\u0440 \u043E\u0442 \u043F\u043E\u0433\u043E\u0434\u044B.",
          en: "Prevents indirect damage, such as weather damage."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/98/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 94,
        slug: "psychic",
        name: {
          ru: "\u041F\u0441\u0438\u0445\u043E\u043A\u0438\u043D\u0435\u0437",
          en: "Psychic"
        },
        description: {
          ru: "\u041F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0441\u0438\u043B\u0430 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443 \u0446\u0435\u043B\u0438.",
          en: "Psychic force may lower the target\u2019s Special Defense."
        },
        type: "psychic",
        power: 90,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/94/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 10
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/64/"
        }
      },
      {
        id: 93,
        slug: "confusion",
        name: {
          ru: "\u0417\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u043E",
          en: "Confusion"
        },
        description: {
          ru: "\u041F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0430\u0442\u0430\u043A\u0430, \u043A\u043E\u0442\u043E\u0440\u0430\u044F \u043C\u043E\u0436\u0435\u0442 \u0437\u0430\u043F\u0443\u0442\u0430\u0442\u044C \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "A psychic strike that may confuse the target."
        },
        type: "psychic",
        power: 50,
        accuracy: 100,
        pp: 25,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/93/",
        meta: {
          ailment: {
            name: "confusion"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: 2,
          max_turns: 5,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/64/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 63,
          name: {
            ru: "\u0410\u0431\u0440\u0430",
            en: "Abra"
          }
        },
        {
          id: 64,
          name: {
            ru: "\u041A\u0430\u0434\u0430\u0431\u0440\u0430",
            en: "Kadabra"
          }
        },
        {
          id: 65,
          name: {
            ru: "\u0410\u043B\u0430\u043A\u0430\u0437\u0430\u043C",
            en: "Alakazam"
          }
        }
      ],
      edges: [
        {
          from: 63,
          to: 64,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 16",
            en: "Level 16"
          },
          isDefault: true
        },
        {
          from: 64,
          to: 65,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D",
            en: "Trade"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 65,
    slug: "alakazam",
    name: {
      ru: "\u0410\u043B\u0430\u043A\u0430\u0437\u0430\u043C",
      en: "Alakazam"
    },
    genus: {
      ru: "\u041F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0438\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Psi Pok\xE9mon"
    },
    description: {
      ru: "\u0421 \u0432\u043E\u0437\u0440\u0430\u0441\u0442\u043E\u043C \u0433\u043E\u043B\u043E\u0432\u0430 \u0441\u0442\u0430\u043D\u043E\u0432\u0438\u0442\u0441\u044F \u0442\u044F\u0436\u0435\u043B\u0435\u0435, \u0430 \u043F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0441\u0438\u043B\u0430 \u0432\u043E\u0437\u0440\u0430\u0441\u0442\u0430\u0435\u0442.",
      en: "Its head grows larger with age, accompanied by increasing psychic strength."
    },
    habitat: "urban",
    types: [
      "psychic"
    ],
    height: 1.5,
    weight: 48,
    stats: [
      55,
      50,
      45,
      135,
      95,
      120
    ],
    abilities: [
      {
        id: 28,
        slug: "synchronize",
        name: {
          ru: "\u0421\u0438\u043D\u0445\u0440\u043E\u043D\u0438\u0437\u0430\u0446\u0438\u044F",
          en: "Synchronize"
        },
        description: {
          ru: "\u041F\u0435\u0440\u0435\u0434\u0430\u0451\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0443 \u043F\u043E\u043B\u0443\u0447\u0435\u043D\u043D\u044B\u0435 \u043E\u0436\u043E\u0433, \u043E\u0442\u0440\u0430\u0432\u043B\u0435\u043D\u0438\u0435 \u0438\u043B\u0438 \u043F\u0430\u0440\u0430\u043B\u0438\u0447.",
          en: "Passes burns, poison or paralysis back to the opponent."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/28/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 39,
        slug: "inner-focus",
        name: {
          ru: "\u0421\u043E\u0441\u0440\u0435\u0434\u043E\u0442\u043E\u0447\u0435\u043D\u043D\u043E\u0441\u0442\u044C",
          en: "Inner Focus"
        },
        description: {
          ru: "\u041D\u0435 \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0438\u0441\u043F\u0443\u0433\u0430\u0442\u044C\u0441\u044F \u0438 \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Prevents flinching."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/39/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 98,
        slug: "magic-guard",
        name: {
          ru: "\u041C\u0430\u0433\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0437\u0430\u0449\u0438\u0442\u0430",
          en: "Magic Guard"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u043A\u043E\u0441\u0432\u0435\u043D\u043D\u043E\u0433\u043E \u0443\u0440\u043E\u043D\u0430, \u043D\u0430\u043F\u0440\u0438\u043C\u0435\u0440 \u043E\u0442 \u043F\u043E\u0433\u043E\u0434\u044B.",
          en: "Prevents indirect damage, such as weather damage."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/98/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 94,
        slug: "psychic",
        name: {
          ru: "\u041F\u0441\u0438\u0445\u043E\u043A\u0438\u043D\u0435\u0437",
          en: "Psychic"
        },
        description: {
          ru: "\u041F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0441\u0438\u043B\u0430 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443 \u0446\u0435\u043B\u0438.",
          en: "Psychic force may lower the target\u2019s Special Defense."
        },
        type: "psychic",
        power: 90,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/94/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 10
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/65/"
        }
      },
      {
        id: 93,
        slug: "confusion",
        name: {
          ru: "\u0417\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u043E",
          en: "Confusion"
        },
        description: {
          ru: "\u041F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0430\u0442\u0430\u043A\u0430, \u043A\u043E\u0442\u043E\u0440\u0430\u044F \u043C\u043E\u0436\u0435\u0442 \u0437\u0430\u043F\u0443\u0442\u0430\u0442\u044C \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "A psychic strike that may confuse the target."
        },
        type: "psychic",
        power: 50,
        accuracy: 100,
        pp: 25,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/93/",
        meta: {
          ailment: {
            name: "confusion"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: 2,
          max_turns: 5,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/65/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 63,
          name: {
            ru: "\u0410\u0431\u0440\u0430",
            en: "Abra"
          }
        },
        {
          id: 64,
          name: {
            ru: "\u041A\u0430\u0434\u0430\u0431\u0440\u0430",
            en: "Kadabra"
          }
        },
        {
          id: 65,
          name: {
            ru: "\u0410\u043B\u0430\u043A\u0430\u0437\u0430\u043C",
            en: "Alakazam"
          }
        }
      ],
      edges: [
        {
          from: 63,
          to: 64,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 16",
            en: "Level 16"
          },
          isDefault: true
        },
        {
          from: 64,
          to: 65,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D",
            en: "Trade"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 66,
    slug: "machop",
    name: {
      ru: "\u041C\u0430\u0447\u043E\u043F",
      en: "Machop"
    },
    genus: {
      ru: "\u0421\u0438\u043B\u044C\u043D\u044B\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Superpower Pok\xE9mon"
    },
    description: {
      ru: "\u041D\u0435\u0441\u043C\u043E\u0442\u0440\u044F \u043D\u0430 \u043D\u0435\u0431\u043E\u043B\u044C\u0448\u043E\u0439 \u0440\u043E\u0441\u0442, \u043E\u0431\u043B\u0430\u0434\u0430\u0435\u0442 \u043E\u0433\u0440\u043E\u043C\u043D\u043E\u0439 \u0441\u0438\u043B\u043E\u0439. \u0422\u0440\u0435\u043D\u0438\u0440\u0443\u0435\u0442\u0441\u044F, \u043F\u0435\u0440\u0435\u043D\u043E\u0441\u044F \u0442\u044F\u0436\u0451\u043B\u044B\u0435 \u043F\u0440\u0435\u0434\u043C\u0435\u0442\u044B \u0438 \u0434\u0430\u0436\u0435 \u0434\u0440\u0443\u0433\u0438\u0445 \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u043E\u0432.",
      en: "Small in stature but remarkably strong, Machop trains by carrying heavy objects and other Pok\xE9mon."
    },
    habitat: "mountain",
    types: [
      "fighting"
    ],
    height: 0.8,
    weight: 19.5,
    stats: [
      70,
      80,
      50,
      35,
      35,
      35
    ],
    abilities: [
      {
        id: 62,
        slug: "guts",
        name: {
          ru: "\u0423\u043F\u043E\u0440\u0441\u0442\u0432\u043E",
          en: "Guts"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0441\u0438\u043B\u0443 \u0430\u0442\u0430\u043A\u0438 \u043F\u0440\u0438 \u043F\u0440\u043E\u0431\u043B\u0435\u043C\u0430\u0445 \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u044F.",
          en: "Boosts Attack while affected by a status condition."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/62/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 99,
        slug: "no-guard",
        name: {
          ru: "\u0411\u0435\u0437 \u0437\u0430\u0449\u0438\u0442\u044B",
          en: "No Guard"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0438 \u0441\u0430\u043C\u043E\u0433\u043E \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u0430 \u0438 \u0430\u0442\u0430\u043A\u0438 \u043F\u043E \u043D\u0435\u043C\u0443 \u043D\u0435 \u043F\u0440\u043E\u043C\u0430\u0445\u0438\u0432\u0430\u044E\u0442\u0441\u044F.",
          en: "Moves used by or against the Pok\xE9mon do not miss."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/99/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 80,
        slug: "steadfast",
        name: {
          ru: "\u0421\u0442\u043E\u0439\u043A\u043E\u0441\u0442\u044C",
          en: "Steadfast"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u043E\u0441\u043B\u0435 \u0438\u0441\u043F\u0443\u0433\u0430.",
          en: "Raises Speed after flinching."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/80/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 2,
        slug: "karate-chop",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043A\u0430\u0440\u0430\u0442\u0435",
          en: "Karate Chop"
        },
        description: {
          ru: "\u0420\u0435\u0437\u043A\u0438\u0439 \u0443\u0434\u0430\u0440 \u0441 \u043F\u043E\u0432\u044B\u0448\u0435\u043D\u043D\u044B\u043C \u0448\u0430\u043D\u0441\u043E\u043C \u043A\u0440\u0438\u0442\u0438\u0447\u0435\u0441\u043A\u043E\u0433\u043E \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u044F.",
          en: "A sharp chop with an increased critical-hit chance."
        },
        type: "fighting",
        power: 50,
        accuracy: 100,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/2/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 1,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/66/"
        }
      },
      {
        id: 67,
        slug: "low-kick",
        name: {
          ru: "\u041F\u043E\u0434\u0441\u0435\u0447\u043A\u0430",
          en: "Low Kick"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0443\u0435\u0442 \u043D\u043E\u0433\u0438; \u043F\u0440\u043E\u0442\u0438\u0432 \u0442\u044F\u0436\u0451\u043B\u043E\u0439 \u0446\u0435\u043B\u0438 \u0443\u0434\u0430\u0440 \u0441\u0438\u043B\u044C\u043D\u0435\u0435.",
          en: "Sweeps the target\u2019s legs, dealing more damage to heavier foes."
        },
        type: "fighting",
        power: null,
        accuracy: 100,
        pp: 20,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/67/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/66/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 66,
          name: {
            ru: "\u041C\u0430\u0447\u043E\u043F",
            en: "Machop"
          }
        },
        {
          id: 67,
          name: {
            ru: "\u041C\u0430\u0447\u043E\u043A",
            en: "Machoke"
          }
        },
        {
          id: 68,
          name: {
            ru: "\u041C\u0430\u0447\u0430\u043C\u043F",
            en: "Machamp"
          }
        }
      ],
      edges: [
        {
          from: 66,
          to: 67,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 28",
            en: "Level 28"
          },
          isDefault: true
        },
        {
          from: 67,
          to: 68,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D",
            en: "Trade"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 67,
    slug: "machoke",
    name: {
      ru: "\u041C\u0430\u0447\u043E\u043A",
      en: "Machoke"
    },
    genus: {
      ru: "\u0421\u0438\u043B\u044C\u043D\u044B\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Superpower Pok\xE9mon"
    },
    description: {
      ru: "\u041E\u0431\u043B\u0430\u0434\u0430\u0435\u0442 \u043A\u0440\u0435\u043F\u043A\u0438\u043C \u0442\u0435\u043B\u043E\u043C \u0438 \u0431\u043E\u043B\u044C\u0448\u043E\u0439 \u0432\u044B\u043D\u043E\u0441\u043B\u0438\u0432\u043E\u0441\u0442\u044C\u044E. \u041B\u044E\u0431\u0438\u0442 \u0442\u0440\u0435\u043D\u0438\u0440\u043E\u0432\u043A\u0438 \u0438 \u043F\u043E\u043C\u043E\u0433\u0430\u0435\u0442 \u043D\u0430 \u0441\u0442\u0440\u043E\u0439\u043A\u0430\u0445.",
      en: "Strong and tireless, Machoke enjoys training and willingly helps with construction work."
    },
    habitat: "mountain",
    types: [
      "fighting"
    ],
    height: 1.5,
    weight: 70.5,
    stats: [
      80,
      100,
      70,
      50,
      60,
      45
    ],
    abilities: [
      {
        id: 62,
        slug: "guts",
        name: {
          ru: "\u0423\u043F\u043E\u0440\u0441\u0442\u0432\u043E",
          en: "Guts"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0441\u0438\u043B\u0443 \u0430\u0442\u0430\u043A\u0438 \u043F\u0440\u0438 \u043F\u0440\u043E\u0431\u043B\u0435\u043C\u0430\u0445 \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u044F.",
          en: "Boosts Attack while affected by a status condition."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/62/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 99,
        slug: "no-guard",
        name: {
          ru: "\u0411\u0435\u0437 \u0437\u0430\u0449\u0438\u0442\u044B",
          en: "No Guard"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0438 \u0441\u0430\u043C\u043E\u0433\u043E \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u0430 \u0438 \u0430\u0442\u0430\u043A\u0438 \u043F\u043E \u043D\u0435\u043C\u0443 \u043D\u0435 \u043F\u0440\u043E\u043C\u0430\u0445\u0438\u0432\u0430\u044E\u0442\u0441\u044F.",
          en: "Moves used by or against the Pok\xE9mon do not miss."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/99/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 80,
        slug: "steadfast",
        name: {
          ru: "\u0421\u0442\u043E\u0439\u043A\u043E\u0441\u0442\u044C",
          en: "Steadfast"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u043E\u0441\u043B\u0435 \u0438\u0441\u043F\u0443\u0433\u0430.",
          en: "Raises Speed after flinching."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/80/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 2,
        slug: "karate-chop",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043A\u0430\u0440\u0430\u0442\u0435",
          en: "Karate Chop"
        },
        description: {
          ru: "\u0420\u0435\u0437\u043A\u0438\u0439 \u0443\u0434\u0430\u0440 \u0441 \u043F\u043E\u0432\u044B\u0448\u0435\u043D\u043D\u044B\u043C \u0448\u0430\u043D\u0441\u043E\u043C \u043A\u0440\u0438\u0442\u0438\u0447\u0435\u0441\u043A\u043E\u0433\u043E \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u044F.",
          en: "A sharp chop with an increased critical-hit chance."
        },
        type: "fighting",
        power: 50,
        accuracy: 100,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/2/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 1,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/67/"
        }
      },
      {
        id: 67,
        slug: "low-kick",
        name: {
          ru: "\u041F\u043E\u0434\u0441\u0435\u0447\u043A\u0430",
          en: "Low Kick"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0443\u0435\u0442 \u043D\u043E\u0433\u0438; \u043F\u0440\u043E\u0442\u0438\u0432 \u0442\u044F\u0436\u0451\u043B\u043E\u0439 \u0446\u0435\u043B\u0438 \u0443\u0434\u0430\u0440 \u0441\u0438\u043B\u044C\u043D\u0435\u0435.",
          en: "Sweeps the target\u2019s legs, dealing more damage to heavier foes."
        },
        type: "fighting",
        power: null,
        accuracy: 100,
        pp: 20,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/67/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/67/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 66,
          name: {
            ru: "\u041C\u0430\u0447\u043E\u043F",
            en: "Machop"
          }
        },
        {
          id: 67,
          name: {
            ru: "\u041C\u0430\u0447\u043E\u043A",
            en: "Machoke"
          }
        },
        {
          id: 68,
          name: {
            ru: "\u041C\u0430\u0447\u0430\u043C\u043F",
            en: "Machamp"
          }
        }
      ],
      edges: [
        {
          from: 66,
          to: 67,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 28",
            en: "Level 28"
          },
          isDefault: true
        },
        {
          from: 67,
          to: 68,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D",
            en: "Trade"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 68,
    slug: "machamp",
    name: {
      ru: "\u041C\u0430\u0447\u0430\u043C\u043F",
      en: "Machamp"
    },
    genus: {
      ru: "\u0421\u0438\u043B\u044C\u043D\u044B\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Superpower Pok\xE9mon"
    },
    description: {
      ru: "\u0427\u0435\u0442\u044B\u0440\u0435 \u0440\u0443\u043A\u0438 \u043E\u0431\u0435\u0441\u043F\u0435\u0447\u0438\u0432\u0430\u044E\u0442 \u043F\u0440\u0435\u0438\u043C\u0443\u0449\u0435\u0441\u0442\u0432\u043E \u0432 \u0431\u043B\u0438\u0436\u043D\u0435\u043C \u0431\u043E\u044E \u0438 \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u044E\u0442 \u043D\u0430\u043D\u043E\u0441\u0438\u0442\u044C \u043C\u043D\u043E\u0436\u0435\u0441\u0442\u0432\u043E \u0443\u0434\u0430\u0440\u043E\u0432.",
      en: "Four arms let Machamp defend and unleash a rapid barrage of punches in close combat."
    },
    habitat: "mountain",
    types: [
      "fighting"
    ],
    height: 1.6,
    weight: 130,
    stats: [
      90,
      130,
      80,
      65,
      85,
      55
    ],
    abilities: [
      {
        id: 62,
        slug: "guts",
        name: {
          ru: "\u0423\u043F\u043E\u0440\u0441\u0442\u0432\u043E",
          en: "Guts"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0441\u0438\u043B\u0443 \u0430\u0442\u0430\u043A\u0438 \u043F\u0440\u0438 \u043F\u0440\u043E\u0431\u043B\u0435\u043C\u0430\u0445 \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u044F.",
          en: "Boosts Attack while affected by a status condition."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/62/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 99,
        slug: "no-guard",
        name: {
          ru: "\u0411\u0435\u0437 \u0437\u0430\u0449\u0438\u0442\u044B",
          en: "No Guard"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0438 \u0441\u0430\u043C\u043E\u0433\u043E \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u0430 \u0438 \u0430\u0442\u0430\u043A\u0438 \u043F\u043E \u043D\u0435\u043C\u0443 \u043D\u0435 \u043F\u0440\u043E\u043C\u0430\u0445\u0438\u0432\u0430\u044E\u0442\u0441\u044F.",
          en: "Moves used by or against the Pok\xE9mon do not miss."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/99/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 80,
        slug: "steadfast",
        name: {
          ru: "\u0421\u0442\u043E\u0439\u043A\u043E\u0441\u0442\u044C",
          en: "Steadfast"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u043E\u0441\u043B\u0435 \u0438\u0441\u043F\u0443\u0433\u0430.",
          en: "Raises Speed after flinching."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/80/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 2,
        slug: "karate-chop",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043A\u0430\u0440\u0430\u0442\u0435",
          en: "Karate Chop"
        },
        description: {
          ru: "\u0420\u0435\u0437\u043A\u0438\u0439 \u0443\u0434\u0430\u0440 \u0441 \u043F\u043E\u0432\u044B\u0448\u0435\u043D\u043D\u044B\u043C \u0448\u0430\u043D\u0441\u043E\u043C \u043A\u0440\u0438\u0442\u0438\u0447\u0435\u0441\u043A\u043E\u0433\u043E \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u044F.",
          en: "A sharp chop with an increased critical-hit chance."
        },
        type: "fighting",
        power: 50,
        accuracy: 100,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/2/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 1,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/68/"
        }
      },
      {
        id: 67,
        slug: "low-kick",
        name: {
          ru: "\u041F\u043E\u0434\u0441\u0435\u0447\u043A\u0430",
          en: "Low Kick"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0443\u0435\u0442 \u043D\u043E\u0433\u0438; \u043F\u0440\u043E\u0442\u0438\u0432 \u0442\u044F\u0436\u0451\u043B\u043E\u0439 \u0446\u0435\u043B\u0438 \u0443\u0434\u0430\u0440 \u0441\u0438\u043B\u044C\u043D\u0435\u0435.",
          en: "Sweeps the target\u2019s legs, dealing more damage to heavier foes."
        },
        type: "fighting",
        power: null,
        accuracy: 100,
        pp: 20,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/67/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/68/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 66,
          name: {
            ru: "\u041C\u0430\u0447\u043E\u043F",
            en: "Machop"
          }
        },
        {
          id: 67,
          name: {
            ru: "\u041C\u0430\u0447\u043E\u043A",
            en: "Machoke"
          }
        },
        {
          id: 68,
          name: {
            ru: "\u041C\u0430\u0447\u0430\u043C\u043F",
            en: "Machamp"
          }
        }
      ],
      edges: [
        {
          from: 66,
          to: 67,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 28",
            en: "Level 28"
          },
          isDefault: true
        },
        {
          from: 67,
          to: 68,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D",
            en: "Trade"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 74,
    slug: "geodude",
    name: {
      ru: "\u0413\u0435\u043E\u0434\u0443\u0434",
      en: "Geodude"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043A\u0430\u043C\u0435\u043D\u044C",
      en: "Rock Pok\xE9mon"
    },
    description: {
      ru: "\u0416\u0438\u0432\u0451\u0442 \u0441\u0440\u0435\u0434\u0438 \u0433\u043E\u0440\u043D\u044B\u0445 \u0441\u043A\u0430\u043B \u0438 \u043A\u0430\u0440\u0430\u0431\u043A\u0430\u0435\u0442\u0441\u044F \u043F\u043E \u0442\u0440\u043E\u043F\u0430\u043C \u0441 \u043F\u043E\u043C\u043E\u0449\u044C\u044E \u0440\u0443\u043A. \u041D\u0435\u043E\u0441\u0442\u043E\u0440\u043E\u0436\u043D\u044B\u0439 \u0442\u043E\u043B\u0447\u043E\u043A \u043C\u043E\u0436\u0435\u0442 \u0441\u0438\u043B\u044C\u043D\u043E \u0435\u0433\u043E \u0440\u0430\u0437\u043E\u0437\u043B\u0438\u0442\u044C.",
      en: "Geodude climbs rough mountain paths with its arms. A careless kick can provoke it."
    },
    habitat: "mountain",
    types: [
      "rock",
      "ground"
    ],
    height: 0.4,
    weight: 20,
    stats: [
      40,
      80,
      100,
      30,
      30,
      20
    ],
    abilities: [
      {
        id: 69,
        slug: "rock-head",
        name: {
          ru: "\u041A\u0430\u043C\u0435\u043D\u043D\u0430\u044F \u0433\u043E\u043B\u043E\u0432\u0430",
          en: "Rock Head"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u0443\u0440\u043E\u043D\u0430 \u043E\u0442\u0434\u0430\u0447\u0438 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0445 \u0430\u0442\u0430\u043A.",
          en: "Prevents recoil damage from its own moves."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/69/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 5,
        slug: "sturdy",
        name: {
          ru: "\u041F\u0440\u043E\u0447\u043D\u043E\u0441\u0442\u044C",
          en: "Sturdy"
        },
        description: {
          ru: "\u041F\u0440\u0438 \u043F\u043E\u043B\u043D\u043E\u043C \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043F\u0435\u0440\u0435\u0436\u0438\u0432\u0430\u0435\u0442 \u0443\u0434\u0430\u0440, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u0438\u043D\u0430\u0447\u0435 \u0441\u0442\u0430\u043B \u0431\u044B \u043D\u043E\u043A\u0430\u0443\u0442\u043E\u043C.",
          en: "At full HP, survives a hit that would otherwise knock it out."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/5/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 8,
        slug: "sand-veil",
        name: {
          ru: "\u041F\u0435\u0441\u0447\u0430\u043D\u0430\u044F \u0437\u0430\u0432\u0435\u0441\u0430",
          en: "Sand Veil"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0443\u043A\u043B\u043E\u043D\u0435\u043D\u0438\u0435 \u0438 \u0437\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u043F\u0435\u0441\u0447\u0430\u043D\u043E\u0439 \u0431\u0443\u0440\u0438.",
          en: "Improves evasion and protects from sandstorm damage."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/8/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 88,
        slug: "rock-throw",
        name: {
          ru: "\u0411\u0440\u043E\u0441\u043E\u043A \u043A\u0430\u043C\u043D\u044F",
          en: "Rock Throw"
        },
        description: {
          ru: "\u041C\u0435\u0442\u043A\u043E \u0431\u0440\u043E\u0441\u0430\u0435\u0442 \u0432 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u043A\u0430\u043C\u0435\u043D\u044C.",
          en: "Hurls a rock at the target."
        },
        type: "rock",
        power: 50,
        accuracy: 90,
        pp: 15,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/88/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/74/"
        }
      },
      {
        id: 157,
        slug: "rock-slide",
        name: {
          ru: "\u041A\u0430\u043C\u043D\u0435\u043F\u0430\u0434",
          en: "Rock Slide"
        },
        description: {
          ru: "\u041E\u0431\u0440\u0443\u0448\u0438\u0432\u0430\u0435\u0442 \u043A\u0430\u043C\u043D\u0438; \u043C\u043E\u0436\u0435\u0442 \u0437\u0430\u0441\u0442\u0430\u0432\u0438\u0442\u044C \u0446\u0435\u043B\u044C \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Drops rocks onto the target and may cause flinching."
        },
        type: "rock",
        power: 75,
        accuracy: 90,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: 30,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/157/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 30,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/74/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 74,
          name: {
            ru: "\u0413\u0435\u043E\u0434\u0443\u0434",
            en: "Geodude"
          }
        },
        {
          id: 75,
          name: {
            ru: "\u0413\u0440\u0430\u0432\u0435\u043B\u0435\u0440",
            en: "Graveler"
          }
        },
        {
          id: 76,
          name: {
            ru: "\u0413\u043E\u043B\u0435\u043C",
            en: "Golem"
          }
        }
      ],
      edges: [
        {
          from: 74,
          to: 75,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 25",
            en: "Level 25"
          },
          isDefault: true
        },
        {
          from: 75,
          to: 76,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D",
            en: "Trade"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 75,
    slug: "graveler",
    name: {
      ru: "\u0413\u0440\u0430\u0432\u0435\u043B\u0435\u0440",
      en: "Graveler"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043A\u0430\u043C\u0435\u043D\u044C",
      en: "Rock Pok\xE9mon"
    },
    description: {
      ru: "\u0416\u0438\u0432\u0451\u0442 \u0432 \u043E\u0442\u0432\u0435\u0440\u0441\u0442\u0438\u044F\u0445 \u043E\u0442\u0432\u0435\u0441\u043D\u044B\u0445 \u0441\u043A\u0430\u043B \u0438 \u043B\u044E\u0431\u0438\u0442 \u0441\u043A\u0430\u0442\u044B\u0432\u0430\u0442\u044C\u0441\u044F \u043F\u043E \u0441\u043A\u043B\u043E\u043D\u0430\u043C, \u0441\u043B\u043E\u0432\u043D\u043E \u0432\u0430\u043B\u0443\u043D.",
      en: "It nests in sheer rock walls and enjoys rolling downhill like a falling boulder."
    },
    habitat: "mountain",
    types: [
      "rock",
      "ground"
    ],
    height: 1,
    weight: 105,
    stats: [
      55,
      95,
      115,
      45,
      45,
      35
    ],
    abilities: [
      {
        id: 69,
        slug: "rock-head",
        name: {
          ru: "\u041A\u0430\u043C\u0435\u043D\u043D\u0430\u044F \u0433\u043E\u043B\u043E\u0432\u0430",
          en: "Rock Head"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u0443\u0440\u043E\u043D\u0430 \u043E\u0442\u0434\u0430\u0447\u0438 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0445 \u0430\u0442\u0430\u043A.",
          en: "Prevents recoil damage from its own moves."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/69/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 5,
        slug: "sturdy",
        name: {
          ru: "\u041F\u0440\u043E\u0447\u043D\u043E\u0441\u0442\u044C",
          en: "Sturdy"
        },
        description: {
          ru: "\u041F\u0440\u0438 \u043F\u043E\u043B\u043D\u043E\u043C \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043F\u0435\u0440\u0435\u0436\u0438\u0432\u0430\u0435\u0442 \u0443\u0434\u0430\u0440, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u0438\u043D\u0430\u0447\u0435 \u0441\u0442\u0430\u043B \u0431\u044B \u043D\u043E\u043A\u0430\u0443\u0442\u043E\u043C.",
          en: "At full HP, survives a hit that would otherwise knock it out."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/5/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 8,
        slug: "sand-veil",
        name: {
          ru: "\u041F\u0435\u0441\u0447\u0430\u043D\u0430\u044F \u0437\u0430\u0432\u0435\u0441\u0430",
          en: "Sand Veil"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0443\u043A\u043B\u043E\u043D\u0435\u043D\u0438\u0435 \u0438 \u0437\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u043F\u0435\u0441\u0447\u0430\u043D\u043E\u0439 \u0431\u0443\u0440\u0438.",
          en: "Improves evasion and protects from sandstorm damage."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/8/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 157,
        slug: "rock-slide",
        name: {
          ru: "\u041A\u0430\u043C\u043D\u0435\u043F\u0430\u0434",
          en: "Rock Slide"
        },
        description: {
          ru: "\u041E\u0431\u0440\u0443\u0448\u0438\u0432\u0430\u0435\u0442 \u043A\u0430\u043C\u043D\u0438; \u043C\u043E\u0436\u0435\u0442 \u0437\u0430\u0441\u0442\u0430\u0432\u0438\u0442\u044C \u0446\u0435\u043B\u044C \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Drops rocks onto the target and may cause flinching."
        },
        type: "rock",
        power: 75,
        accuracy: 90,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: 30,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/157/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 30,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/75/"
        }
      },
      {
        id: 89,
        slug: "earthquake",
        name: {
          ru: "\u0417\u0435\u043C\u043B\u0435\u0442\u0440\u044F\u0441\u0435\u043D\u0438\u0435",
          en: "Earthquake"
        },
        description: {
          ru: "\u0421\u043E\u0442\u0440\u044F\u0441\u0430\u0435\u0442 \u0437\u0435\u043C\u043B\u044E \u043C\u043E\u0449\u043D\u043E\u0439 \u0443\u0434\u0430\u0440\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Shakes the ground with a powerful shock wave."
        },
        type: "ground",
        power: 100,
        accuracy: 100,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/89/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/75/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 74,
          name: {
            ru: "\u0413\u0435\u043E\u0434\u0443\u0434",
            en: "Geodude"
          }
        },
        {
          id: 75,
          name: {
            ru: "\u0413\u0440\u0430\u0432\u0435\u043B\u0435\u0440",
            en: "Graveler"
          }
        },
        {
          id: 76,
          name: {
            ru: "\u0413\u043E\u043B\u0435\u043C",
            en: "Golem"
          }
        }
      ],
      edges: [
        {
          from: 74,
          to: 75,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 25",
            en: "Level 25"
          },
          isDefault: true
        },
        {
          from: 75,
          to: 76,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D",
            en: "Trade"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 76,
    slug: "golem",
    name: {
      ru: "\u0413\u043E\u043B\u0435\u043C",
      en: "Golem"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043C\u0435\u0433\u0430\u0442\u043E\u043D\u043D\u0430",
      en: "Megaton Pok\xE9mon"
    },
    description: {
      ru: "\u0415\u0436\u0435\u0433\u043E\u0434\u043D\u043E \u0441\u0431\u0440\u0430\u0441\u044B\u0432\u0430\u0435\u0442 \u043A\u0430\u043C\u0435\u043D\u043D\u044B\u0439 \u043F\u0430\u043D\u0446\u0438\u0440\u044C. \u041E\u0431\u043B\u043E\u043C\u043A\u0438 \u043F\u043E\u0441\u0442\u0435\u043F\u0435\u043D\u043D\u043E \u043F\u0440\u0435\u0432\u0440\u0430\u0449\u0430\u044E\u0442\u0441\u044F \u0432 \u043F\u043B\u043E\u0434\u043E\u0440\u043E\u0434\u043D\u0443\u044E \u043F\u043E\u0447\u0432\u0443.",
      en: "Its annually shed rocky shell breaks down into soil that can nourish fields."
    },
    habitat: "mountain",
    types: [
      "rock",
      "ground"
    ],
    height: 1.4,
    weight: 300,
    stats: [
      80,
      120,
      130,
      55,
      65,
      45
    ],
    abilities: [
      {
        id: 69,
        slug: "rock-head",
        name: {
          ru: "\u041A\u0430\u043C\u0435\u043D\u043D\u0430\u044F \u0433\u043E\u043B\u043E\u0432\u0430",
          en: "Rock Head"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u0443\u0440\u043E\u043D\u0430 \u043E\u0442\u0434\u0430\u0447\u0438 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0445 \u0430\u0442\u0430\u043A.",
          en: "Prevents recoil damage from its own moves."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/69/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 5,
        slug: "sturdy",
        name: {
          ru: "\u041F\u0440\u043E\u0447\u043D\u043E\u0441\u0442\u044C",
          en: "Sturdy"
        },
        description: {
          ru: "\u041F\u0440\u0438 \u043F\u043E\u043B\u043D\u043E\u043C \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043F\u0435\u0440\u0435\u0436\u0438\u0432\u0430\u0435\u0442 \u0443\u0434\u0430\u0440, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u0438\u043D\u0430\u0447\u0435 \u0441\u0442\u0430\u043B \u0431\u044B \u043D\u043E\u043A\u0430\u0443\u0442\u043E\u043C.",
          en: "At full HP, survives a hit that would otherwise knock it out."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/5/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 8,
        slug: "sand-veil",
        name: {
          ru: "\u041F\u0435\u0441\u0447\u0430\u043D\u0430\u044F \u0437\u0430\u0432\u0435\u0441\u0430",
          en: "Sand Veil"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0443\u043A\u043B\u043E\u043D\u0435\u043D\u0438\u0435 \u0438 \u0437\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u043F\u0435\u0441\u0447\u0430\u043D\u043E\u0439 \u0431\u0443\u0440\u0438.",
          en: "Improves evasion and protects from sandstorm damage."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/8/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 157,
        slug: "rock-slide",
        name: {
          ru: "\u041A\u0430\u043C\u043D\u0435\u043F\u0430\u0434",
          en: "Rock Slide"
        },
        description: {
          ru: "\u041E\u0431\u0440\u0443\u0448\u0438\u0432\u0430\u0435\u0442 \u043A\u0430\u043C\u043D\u0438; \u043C\u043E\u0436\u0435\u0442 \u0437\u0430\u0441\u0442\u0430\u0432\u0438\u0442\u044C \u0446\u0435\u043B\u044C \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Drops rocks onto the target and may cause flinching."
        },
        type: "rock",
        power: 75,
        accuracy: 90,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: 30,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/157/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 30,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/76/"
        }
      },
      {
        id: 89,
        slug: "earthquake",
        name: {
          ru: "\u0417\u0435\u043C\u043B\u0435\u0442\u0440\u044F\u0441\u0435\u043D\u0438\u0435",
          en: "Earthquake"
        },
        description: {
          ru: "\u0421\u043E\u0442\u0440\u044F\u0441\u0430\u0435\u0442 \u0437\u0435\u043C\u043B\u044E \u043C\u043E\u0449\u043D\u043E\u0439 \u0443\u0434\u0430\u0440\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Shakes the ground with a powerful shock wave."
        },
        type: "ground",
        power: 100,
        accuracy: 100,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/89/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/76/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 74,
          name: {
            ru: "\u0413\u0435\u043E\u0434\u0443\u0434",
            en: "Geodude"
          }
        },
        {
          id: 75,
          name: {
            ru: "\u0413\u0440\u0430\u0432\u0435\u043B\u0435\u0440",
            en: "Graveler"
          }
        },
        {
          id: 76,
          name: {
            ru: "\u0413\u043E\u043B\u0435\u043C",
            en: "Golem"
          }
        }
      ],
      edges: [
        {
          from: 74,
          to: 75,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 25",
            en: "Level 25"
          },
          isDefault: true
        },
        {
          from: 75,
          to: 76,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D",
            en: "Trade"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 77,
    slug: "ponyta",
    name: {
      ru: "\u041F\u043E\u043D\u0438\u0442\u0430",
      en: "Ponyta"
    },
    genus: {
      ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u0430\u044F \u043B\u043E\u0448\u0430\u0434\u044C",
      en: "Fire Horse Pok\xE9mon"
    },
    description: {
      ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u044B\u0435 \u043B\u043E\u0448\u0430\u0434\u043A\u0438 \u0436\u0438\u0432\u0443\u0442 \u0441\u0442\u0430\u0434\u0430\u043C\u0438 \u043D\u0430 \u043B\u0443\u0433\u0430\u0445. \u0423 \u043D\u043E\u0432\u043E\u0440\u043E\u0436\u0434\u0451\u043D\u043D\u043E\u0433\u043E \u0436\u0435\u0440\u0435\u0431\u0451\u043D\u043A\u0430 \u043F\u043B\u0430\u043C\u0435\u043D\u043D\u0430\u044F \u0433\u0440\u0438\u0432\u0430 \u043F\u043E\u044F\u0432\u043B\u044F\u0435\u0442\u0441\u044F \u0432\u0441\u043A\u043E\u0440\u0435 \u043F\u043E\u0441\u043B\u0435 \u0440\u043E\u0436\u0434\u0435\u043D\u0438\u044F.",
      en: "These fire horses live in grassland herds. A newborn develops its fiery mane soon after birth."
    },
    habitat: "grassland",
    types: [
      "fire"
    ],
    height: 1,
    weight: 30,
    stats: [
      50,
      85,
      55,
      65,
      65,
      90
    ],
    abilities: [
      {
        id: 50,
        slug: "run-away",
        name: {
          ru: "\u041F\u043E\u0431\u0435\u0433",
          en: "Run Away"
        },
        description: {
          ru: "\u041F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0443\u0441\u043F\u0435\u0448\u043D\u043E \u0443\u0431\u0435\u0436\u0430\u0442\u044C \u043E\u0442 \u0434\u0438\u043A\u043E\u0433\u043E \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u0430.",
          en: "Ensures escape from wild Pok\xE9mon battles."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/50/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 18,
        slug: "flash-fire",
        name: {
          ru: "\u0412\u0441\u043F\u044B\u0448\u043A\u0430 \u043E\u0433\u043D\u044F",
          en: "Flash Fire"
        },
        description: {
          ru: "\u041F\u043E\u0433\u043B\u043E\u0449\u0430\u0435\u0442 \u043E\u0433\u043D\u0435\u043D\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438 \u0438 \u0443\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0439 \u043E\u0433\u043E\u043D\u044C.",
          en: "Absorbs Fire moves and boosts its own Fire attacks."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/18/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 49,
        slug: "flame-body",
        name: {
          ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u043E\u0435 \u0442\u0435\u043B\u043E",
          en: "Flame Body"
        },
        description: {
          ru: "\u041A\u043E\u043D\u0442\u0430\u043A\u0442 \u0441 \u0442\u0435\u043B\u043E\u043C \u043C\u043E\u0436\u0435\u0442 \u043E\u0431\u0436\u0435\u0447\u044C \u0430\u0442\u0430\u043A\u0443\u044E\u0449\u0435\u0433\u043E.",
          en: "Contact with the Pok\xE9mon may burn the attacker."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/49/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 52,
        slug: "ember",
        name: {
          ru: "\u0418\u0441\u043A\u0440\u044B",
          en: "Ember"
        },
        description: {
          ru: "\u041F\u043E\u0442\u043E\u043A \u043C\u0430\u043B\u0435\u043D\u044C\u043A\u0438\u0445 \u044F\u0437\u044B\u043A\u043E\u0432 \u043F\u043B\u0430\u043C\u0435\u043D\u0438 \u043C\u043E\u0436\u0435\u0442 \u0432\u044B\u0437\u0432\u0430\u0442\u044C \u043E\u0436\u043E\u0433.",
          en: "A burst of small flames may burn the target."
        },
        type: "fire",
        power: 40,
        accuracy: 100,
        pp: 25,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/52/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/77/"
        }
      },
      {
        id: 172,
        slug: "flame-wheel",
        name: {
          ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u043E\u0435 \u043A\u043E\u043B\u0435\u0441\u043E",
          en: "Flame Wheel"
        },
        description: {
          ru: "\u041E\u043A\u0440\u0443\u0436\u0430\u0435\u0442 \u0441\u0435\u0431\u044F \u043F\u043B\u0430\u043C\u0435\u043D\u0435\u043C \u0438 \u0430\u0442\u0430\u043A\u0443\u0435\u0442; \u043C\u043E\u0436\u0435\u0442 \u043E\u0431\u0436\u0435\u0447\u044C \u0446\u0435\u043B\u044C.",
          en: "Charges within a ring of fire and may burn the target."
        },
        type: "fire",
        power: 60,
        accuracy: 100,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/172/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/77/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 77,
          name: {
            ru: "\u041F\u043E\u043D\u0438\u0442\u0430",
            en: "Ponyta"
          }
        },
        {
          id: 78,
          name: {
            ru: "\u0420\u0430\u043F\u0438\u0434\u0430\u0448",
            en: "Rapidash"
          }
        }
      ],
      edges: [
        {
          from: 77,
          to: 78,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 40",
            en: "Level 40"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 78,
    slug: "rapidash",
    name: {
      ru: "\u0420\u0430\u043F\u0438\u0434\u0430\u0448",
      en: "Rapidash"
    },
    genus: {
      ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u0430\u044F \u043B\u043E\u0448\u0430\u0434\u044C",
      en: "Fire Horse Pok\xE9mon"
    },
    description: {
      ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u0430\u044F \u0433\u0440\u0438\u0432\u0430 \u0441\u0432\u0435\u0442\u0438\u0442\u0441\u044F, \u043A\u043E\u0433\u0434\u0430 \u043E\u043D \u0441 \u043E\u0433\u0440\u043E\u043C\u043D\u043E\u0439 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C\u044E \u043C\u0447\u0438\u0442\u0441\u044F \u043F\u043E \u0437\u0435\u043C\u043B\u0435.",
      en: "A glowing mane trails behind Rapidash as it races swiftly across the land."
    },
    habitat: "grassland",
    types: [
      "fire"
    ],
    height: 1.7,
    weight: 95,
    stats: [
      65,
      100,
      70,
      80,
      80,
      105
    ],
    abilities: [
      {
        id: 50,
        slug: "run-away",
        name: {
          ru: "\u041F\u043E\u0431\u0435\u0433",
          en: "Run Away"
        },
        description: {
          ru: "\u041F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0443\u0441\u043F\u0435\u0448\u043D\u043E \u0443\u0431\u0435\u0436\u0430\u0442\u044C \u043E\u0442 \u0434\u0438\u043A\u043E\u0433\u043E \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u0430.",
          en: "Ensures escape from wild Pok\xE9mon battles."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/50/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 18,
        slug: "flash-fire",
        name: {
          ru: "\u0412\u0441\u043F\u044B\u0448\u043A\u0430 \u043E\u0433\u043D\u044F",
          en: "Flash Fire"
        },
        description: {
          ru: "\u041F\u043E\u0433\u043B\u043E\u0449\u0430\u0435\u0442 \u043E\u0433\u043D\u0435\u043D\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438 \u0438 \u0443\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0439 \u043E\u0433\u043E\u043D\u044C.",
          en: "Absorbs Fire moves and boosts its own Fire attacks."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/18/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 49,
        slug: "flame-body",
        name: {
          ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u043E\u0435 \u0442\u0435\u043B\u043E",
          en: "Flame Body"
        },
        description: {
          ru: "\u041A\u043E\u043D\u0442\u0430\u043A\u0442 \u0441 \u0442\u0435\u043B\u043E\u043C \u043C\u043E\u0436\u0435\u0442 \u043E\u0431\u0436\u0435\u0447\u044C \u0430\u0442\u0430\u043A\u0443\u044E\u0449\u0435\u0433\u043E.",
          en: "Contact with the Pok\xE9mon may burn the attacker."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/49/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 53,
        slug: "flamethrower",
        name: {
          ru: "\u041E\u0433\u043D\u0435\u043C\u0451\u0442",
          en: "Flamethrower"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u0441\u0438\u043B\u044C\u043D\u0443\u044E \u0441\u0442\u0440\u0443\u044E \u043F\u043B\u0430\u043C\u0435\u043D\u0438; \u043C\u043E\u0436\u0435\u0442 \u0432\u044B\u0437\u0432\u0430\u0442\u044C \u043E\u0436\u043E\u0433.",
          en: "Unleashes a powerful stream of fire that may cause a burn."
        },
        type: "fire",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/53/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/78/"
        }
      },
      {
        id: 172,
        slug: "flame-wheel",
        name: {
          ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u043E\u0435 \u043A\u043E\u043B\u0435\u0441\u043E",
          en: "Flame Wheel"
        },
        description: {
          ru: "\u041E\u043A\u0440\u0443\u0436\u0430\u0435\u0442 \u0441\u0435\u0431\u044F \u043F\u043B\u0430\u043C\u0435\u043D\u0435\u043C \u0438 \u0430\u0442\u0430\u043A\u0443\u0435\u0442; \u043C\u043E\u0436\u0435\u0442 \u043E\u0431\u0436\u0435\u0447\u044C \u0446\u0435\u043B\u044C.",
          en: "Charges within a ring of fire and may burn the target."
        },
        type: "fire",
        power: 60,
        accuracy: 100,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/172/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/78/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 77,
          name: {
            ru: "\u041F\u043E\u043D\u0438\u0442\u0430",
            en: "Ponyta"
          }
        },
        {
          id: 78,
          name: {
            ru: "\u0420\u0430\u043F\u0438\u0434\u0430\u0448",
            en: "Rapidash"
          }
        }
      ],
      edges: [
        {
          from: 77,
          to: 78,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 40",
            en: "Level 40"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 79,
    slug: "slowpoke",
    name: {
      ru: "\u0421\u043B\u043E\u0443\u043F\u043E\u043A",
      en: "Slowpoke"
    },
    genus: {
      ru: "\u041D\u0435\u0442\u043E\u0440\u043E\u043F\u043B\u0438\u0432\u044B\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Dopey Pok\xE9mon"
    },
    description: {
      ru: "\u041E\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u0445\u0432\u043E\u0441\u0442 \u0432 \u0432\u043E\u0434\u0443 \u0438 \u043F\u0440\u0438\u043C\u0430\u043D\u0438\u0432\u0430\u0435\u0442 \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u043E\u0432 \u0432\u044B\u0434\u0435\u043B\u044F\u044E\u0449\u0438\u043C\u0441\u044F \u0441\u043B\u0430\u0434\u043A\u0438\u043C \u0432\u0435\u0449\u0435\u0441\u0442\u0432\u043E\u043C. \u0412\u044B\u0433\u043B\u044F\u0434\u0438\u0442 \u0441\u043F\u043E\u043A\u043E\u0439\u043D\u044B\u043C \u0434\u0430\u0436\u0435 \u0432\u043E \u0432\u0440\u0435\u043C\u044F \u0440\u044B\u0431\u0430\u043B\u043A\u0438.",
      en: "A sweet substance seeps from its submerged tail, helping Slowpoke attract Pok\xE9mon while fishing."
    },
    habitat: "water",
    types: [
      "water",
      "psychic"
    ],
    height: 1.2,
    weight: 36,
    stats: [
      90,
      65,
      65,
      40,
      40,
      15
    ],
    abilities: [
      {
        id: 12,
        slug: "oblivious",
        name: {
          ru: "\u041D\u0435\u0432\u043E\u0437\u043C\u0443\u0442\u0438\u043C\u043E\u0441\u0442\u044C",
          en: "Oblivious"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u0432\u043B\u044E\u0431\u043B\u0451\u043D\u043D\u043E\u0441\u0442\u0438.",
          en: "Prevents infatuation."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/12/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 20,
        slug: "own-tempo",
        name: {
          ru: "\u0421\u0432\u043E\u0439 \u0442\u0435\u043C\u043F",
          en: "Own Tempo"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u0437\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u0430.",
          en: "Prevents confusion."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/20/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 144,
        slug: "regenerator",
        name: {
          ru: "\u0420\u0435\u0433\u0435\u043D\u0435\u0440\u0430\u0446\u0438\u044F",
          en: "Regenerator"
        },
        description: {
          ru: "\u0412\u043E\u0441\u0441\u0442\u0430\u043D\u0430\u0432\u043B\u0438\u0432\u0430\u0435\u0442 \u0447\u0430\u0441\u0442\u044C \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u044F \u043F\u0440\u0438 \u0441\u043C\u0435\u043D\u0435 \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u0430.",
          en: "Restores some HP when the Pok\xE9mon switches out."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/144/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 55,
        slug: "water-gun",
        name: {
          ru: "\u0412\u043E\u0434\u044F\u043D\u0430\u044F \u043F\u0443\u0448\u043A\u0430",
          en: "Water Gun"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u043D\u0430\u043F\u0440\u0430\u0432\u043B\u0435\u043D\u043D\u0443\u044E \u0441\u0442\u0440\u0443\u044E \u0432\u043E\u0434\u044B.",
          en: "Fires a focused jet of water."
        },
        type: "water",
        power: 40,
        accuracy: 100,
        pp: 25,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/55/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/79/"
        }
      },
      {
        id: 93,
        slug: "confusion",
        name: {
          ru: "\u0417\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u043E",
          en: "Confusion"
        },
        description: {
          ru: "\u041F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0430\u0442\u0430\u043A\u0430, \u043A\u043E\u0442\u043E\u0440\u0430\u044F \u043C\u043E\u0436\u0435\u0442 \u0437\u0430\u043F\u0443\u0442\u0430\u0442\u044C \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "A psychic strike that may confuse the target."
        },
        type: "psychic",
        power: 50,
        accuracy: 100,
        pp: 25,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/93/",
        meta: {
          ailment: {
            name: "confusion"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: 2,
          max_turns: 5,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/79/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 79,
          name: {
            ru: "\u0421\u043B\u043E\u0443\u043F\u043E\u043A",
            en: "Slowpoke"
          }
        },
        {
          id: 80,
          name: {
            ru: "\u0421\u043B\u043E\u0443\u0431\u0440\u043E",
            en: "Slowbro"
          }
        },
        {
          id: 199,
          name: {
            ru: "\u0421\u043B\u043E\u0443\u043A\u0438\u043D\u0433",
            en: "Slowking"
          }
        }
      ],
      edges: [
        {
          from: 79,
          to: 80,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 37",
            en: "Level 37"
          },
          isDefault: true
        },
        {
          from: 79,
          to: 199,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D \xB7 \u0441 \u043F\u0440\u0435\u0434\u043C\u0435\u0442\u043E\u043C \xAB\u041A\u043E\u0440\u043E\u043B\u0435\u0432\u0441\u043A\u0438\u0439 \u043A\u0430\u043C\u0435\u043D\u044C\xBB",
            en: "Trade \xB7 holding King\u2019s Rock"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 80,
    slug: "slowbro",
    name: {
      ru: "\u0421\u043B\u043E\u0443\u0431\u0440\u043E",
      en: "Slowbro"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043E\u0442\u0448\u0435\u043B\u044C\u043D\u0438\u043A",
      en: "Hermit Crab Pok\xE9mon"
    },
    description: {
      ru: "\u0423\u043A\u0443\u0441 \u0428\u0435\u043B\u043B\u0434\u0435\u0440\u0430 \u0437\u0430\u0441\u0442\u0430\u0432\u0438\u043B \u0435\u0433\u043E \u0432\u0441\u0442\u0430\u0442\u044C \u043D\u0430 \u0437\u0430\u0434\u043D\u0438\u0435 \u043B\u0430\u043F\u044B. \u0415\u0441\u043B\u0438 \u0442\u043E\u0442 \u043E\u0442\u0446\u0435\u043F\u0438\u0442\u0441\u044F, \u0444\u043E\u0440\u043C\u0430 \u043C\u043E\u0436\u0435\u0442 \u0438\u0437\u043C\u0435\u043D\u0438\u0442\u044C\u0441\u044F.",
      en: "A Shellder bite made it stand upright; losing that partner may reverse the change."
    },
    habitat: "water",
    types: [
      "water",
      "psychic"
    ],
    height: 1.6,
    weight: 78.5,
    stats: [
      95,
      75,
      110,
      100,
      80,
      30
    ],
    abilities: [
      {
        id: 12,
        slug: "oblivious",
        name: {
          ru: "\u041D\u0435\u0432\u043E\u0437\u043C\u0443\u0442\u0438\u043C\u043E\u0441\u0442\u044C",
          en: "Oblivious"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u0432\u043B\u044E\u0431\u043B\u0451\u043D\u043D\u043E\u0441\u0442\u0438.",
          en: "Prevents infatuation."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/12/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 20,
        slug: "own-tempo",
        name: {
          ru: "\u0421\u0432\u043E\u0439 \u0442\u0435\u043C\u043F",
          en: "Own Tempo"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u0437\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u0430.",
          en: "Prevents confusion."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/20/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 144,
        slug: "regenerator",
        name: {
          ru: "\u0420\u0435\u0433\u0435\u043D\u0435\u0440\u0430\u0446\u0438\u044F",
          en: "Regenerator"
        },
        description: {
          ru: "\u0412\u043E\u0441\u0441\u0442\u0430\u043D\u0430\u0432\u043B\u0438\u0432\u0430\u0435\u0442 \u0447\u0430\u0441\u0442\u044C \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u044F \u043F\u0440\u0438 \u0441\u043C\u0435\u043D\u0435 \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u0430.",
          en: "Restores some HP when the Pok\xE9mon switches out."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/144/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 57,
        slug: "surf",
        name: {
          ru: "\u0421\u0451\u0440\u0444\u0438\u043D\u0433",
          en: "Surf"
        },
        description: {
          ru: "\u041D\u0430\u043A\u0440\u044B\u0432\u0430\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u0431\u043E\u043B\u044C\u0448\u043E\u0439 \u0432\u043E\u0434\u044F\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Sweeps over opponents with a large wave of water."
        },
        type: "water",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/57/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/80/"
        }
      },
      {
        id: 94,
        slug: "psychic",
        name: {
          ru: "\u041F\u0441\u0438\u0445\u043E\u043A\u0438\u043D\u0435\u0437",
          en: "Psychic"
        },
        description: {
          ru: "\u041F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0441\u0438\u043B\u0430 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443 \u0446\u0435\u043B\u0438.",
          en: "Psychic force may lower the target\u2019s Special Defense."
        },
        type: "psychic",
        power: 90,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/94/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 10
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/80/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 79,
          name: {
            ru: "\u0421\u043B\u043E\u0443\u043F\u043E\u043A",
            en: "Slowpoke"
          }
        },
        {
          id: 80,
          name: {
            ru: "\u0421\u043B\u043E\u0443\u0431\u0440\u043E",
            en: "Slowbro"
          }
        },
        {
          id: 199,
          name: {
            ru: "\u0421\u043B\u043E\u0443\u043A\u0438\u043D\u0433",
            en: "Slowking"
          }
        }
      ],
      edges: [
        {
          from: 79,
          to: 80,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 37",
            en: "Level 37"
          },
          isDefault: true
        },
        {
          from: 79,
          to: 199,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D \xB7 \u0441 \u043F\u0440\u0435\u0434\u043C\u0435\u0442\u043E\u043C \xAB\u041A\u043E\u0440\u043E\u043B\u0435\u0432\u0441\u043A\u0438\u0439 \u043A\u0430\u043C\u0435\u043D\u044C\xBB",
            en: "Trade \xB7 holding King\u2019s Rock"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 81,
    slug: "magnemite",
    name: {
      ru: "\u041C\u0430\u0433\u043D\u0435\u043C\u0430\u0439\u0442",
      en: "Magnemite"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043C\u0430\u0433\u043D\u0438\u0442",
      en: "Magnet Pok\xE9mon"
    },
    description: {
      ru: "\u041F\u043E\u0445\u043E\u0436 \u043D\u0430 \u0436\u0435\u043B\u0435\u0437\u043D\u044B\u0439 \u0448\u0430\u0440 \u0441 \u043E\u0434\u043D\u0438\u043C \u0433\u043B\u0430\u0437\u043E\u043C. \u041C\u0430\u0433\u043D\u0435\u0442\u0438\u0437\u043C \u0435\u0433\u043E \u0440\u0443\u043A \u043F\u043E\u043C\u043E\u0433\u0430\u0435\u0442 \u0435\u043C\u0443 \u043F\u0430\u0440\u0438\u0442\u044C \u043D\u0430\u0434 \u0437\u0435\u043C\u043B\u0451\u0439.",
      en: "This one-eyed metal sphere floats using the magnetism of its horseshoe-shaped arms."
    },
    habitat: "mountain",
    types: [
      "electric",
      "steel"
    ],
    height: 0.3,
    weight: 6,
    stats: [
      25,
      35,
      70,
      95,
      55,
      45
    ],
    abilities: [
      {
        id: 42,
        slug: "magnet-pull",
        name: {
          ru: "\u041C\u0430\u0433\u043D\u0438\u0442\u043D\u043E\u0435 \u043F\u0440\u0438\u0442\u044F\u0436\u0435\u043D\u0438\u0435",
          en: "Magnet Pull"
        },
        description: {
          ru: "\u041D\u0435 \u0434\u0430\u0451\u0442 \u0441\u0442\u0430\u043B\u044C\u043D\u044B\u043C \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430\u043C \u0441\u043C\u0435\u043D\u0438\u0442\u044C\u0441\u044F \u0438\u043B\u0438 \u0441\u0431\u0435\u0436\u0430\u0442\u044C.",
          en: "Traps opposing Steel Pok\xE9mon."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/42/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 5,
        slug: "sturdy",
        name: {
          ru: "\u041F\u0440\u043E\u0447\u043D\u043E\u0441\u0442\u044C",
          en: "Sturdy"
        },
        description: {
          ru: "\u041F\u0440\u0438 \u043F\u043E\u043B\u043D\u043E\u043C \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043F\u0435\u0440\u0435\u0436\u0438\u0432\u0430\u0435\u0442 \u0443\u0434\u0430\u0440, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u0438\u043D\u0430\u0447\u0435 \u0441\u0442\u0430\u043B \u0431\u044B \u043D\u043E\u043A\u0430\u0443\u0442\u043E\u043C.",
          en: "At full HP, survives a hit that would otherwise knock it out."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/5/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 148,
        slug: "analytic",
        name: {
          ru: "\u0410\u043D\u0430\u043B\u0438\u0442\u0438\u043A",
          en: "Analytic"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0430\u0442\u0430\u043A\u0438, \u043A\u043E\u0433\u0434\u0430 \u043F\u043E\u043A\u0435\u043C\u043E\u043D \u0445\u043E\u0434\u0438\u0442 \u043F\u043E\u0441\u043B\u0435\u0434\u043D\u0438\u043C.",
          en: "Boosts moves when the Pok\xE9mon acts last."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/148/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 84,
        slug: "thunder-shock",
        name: {
          ru: "\u042D\u043B\u0435\u043A\u0442\u0440\u043E\u0448\u043E\u043A",
          en: "Thunder Shock"
        },
        description: {
          ru: "\u041D\u0435\u0431\u043E\u043B\u044C\u0448\u043E\u0439 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0439 \u0440\u0430\u0437\u0440\u044F\u0434 \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C.",
          en: "A small electric discharge may cause paralysis."
        },
        type: "electric",
        power: 40,
        accuracy: 100,
        pp: 30,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/84/",
        meta: {
          ailment: {
            name: "paralysis"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/81/"
        }
      },
      {
        id: 430,
        slug: "flash-cannon",
        name: {
          ru: "\u0421\u0432\u0435\u0442\u043E\u0432\u0430\u044F \u043F\u0443\u0448\u043A\u0430",
          en: "Flash Cannon"
        },
        description: {
          ru: "\u041B\u0443\u0447 \u043D\u0430\u043A\u043E\u043F\u043B\u0435\u043D\u043D\u043E\u0439 \u044D\u043D\u0435\u0440\u0433\u0438\u0438 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443.",
          en: "Fires stored energy and may lower Special Defense."
        },
        type: "steel",
        power: 80,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/430/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 10
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/81/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 81,
          name: {
            ru: "\u041C\u0430\u0433\u043D\u0435\u043C\u0430\u0439\u0442",
            en: "Magnemite"
          }
        },
        {
          id: 82,
          name: {
            ru: "\u041C\u0430\u0433\u043D\u0435\u0442\u043E\u043D",
            en: "Magneton"
          }
        },
        {
          id: 462,
          name: {
            ru: "\u041C\u0430\u0433\u043D\u0435\u0437\u043E\u043D",
            en: "Magnezone"
          }
        }
      ],
      edges: [
        {
          from: 81,
          to: 82,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 30",
            en: "Level 30"
          },
          isDefault: true
        },
        {
          from: 82,
          to: 462,
          condition: {
            ru: "\u0413\u0440\u043E\u043C\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Thunder Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 82,
    slug: "magneton",
    name: {
      ru: "\u041C\u0430\u0433\u043D\u0435\u0442\u043E\u043D",
      en: "Magneton"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043C\u0430\u0433\u043D\u0438\u0442",
      en: "Magnet Pok\xE9mon"
    },
    description: {
      ru: "\u041E\u0431\u0440\u0430\u0437\u0443\u0435\u0442\u0441\u044F \u0438\u0437 \u0442\u0440\u0451\u0445 \u041C\u0430\u0433\u043D\u0435\u043C\u0430\u0439\u0442\u043E\u0432. \u0421\u0438\u043B\u044C\u043D\u043E\u0435 \u043C\u0430\u0433\u043D\u0438\u0442\u043D\u043E\u0435 \u043F\u043E\u043B\u0435 \u0441\u043F\u043E\u0441\u043E\u0431\u043D\u043E \u043F\u043E\u0432\u0440\u0435\u0434\u0438\u0442\u044C \u043E\u0431\u043E\u0440\u0443\u0434\u043E\u0432\u0430\u043D\u0438\u0435.",
      en: "Three Magnemite join together, producing magnetism powerful enough to disrupt equipment."
    },
    habitat: "mountain",
    types: [
      "electric",
      "steel"
    ],
    height: 1,
    weight: 60,
    stats: [
      50,
      60,
      95,
      120,
      70,
      70
    ],
    abilities: [
      {
        id: 42,
        slug: "magnet-pull",
        name: {
          ru: "\u041C\u0430\u0433\u043D\u0438\u0442\u043D\u043E\u0435 \u043F\u0440\u0438\u0442\u044F\u0436\u0435\u043D\u0438\u0435",
          en: "Magnet Pull"
        },
        description: {
          ru: "\u041D\u0435 \u0434\u0430\u0451\u0442 \u0441\u0442\u0430\u043B\u044C\u043D\u044B\u043C \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430\u043C \u0441\u043C\u0435\u043D\u0438\u0442\u044C\u0441\u044F \u0438\u043B\u0438 \u0441\u0431\u0435\u0436\u0430\u0442\u044C.",
          en: "Traps opposing Steel Pok\xE9mon."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/42/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 5,
        slug: "sturdy",
        name: {
          ru: "\u041F\u0440\u043E\u0447\u043D\u043E\u0441\u0442\u044C",
          en: "Sturdy"
        },
        description: {
          ru: "\u041F\u0440\u0438 \u043F\u043E\u043B\u043D\u043E\u043C \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043F\u0435\u0440\u0435\u0436\u0438\u0432\u0430\u0435\u0442 \u0443\u0434\u0430\u0440, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u0438\u043D\u0430\u0447\u0435 \u0441\u0442\u0430\u043B \u0431\u044B \u043D\u043E\u043A\u0430\u0443\u0442\u043E\u043C.",
          en: "At full HP, survives a hit that would otherwise knock it out."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/5/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 148,
        slug: "analytic",
        name: {
          ru: "\u0410\u043D\u0430\u043B\u0438\u0442\u0438\u043A",
          en: "Analytic"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0430\u0442\u0430\u043A\u0438, \u043A\u043E\u0433\u0434\u0430 \u043F\u043E\u043A\u0435\u043C\u043E\u043D \u0445\u043E\u0434\u0438\u0442 \u043F\u043E\u0441\u043B\u0435\u0434\u043D\u0438\u043C.",
          en: "Boosts moves when the Pok\xE9mon acts last."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/148/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 85,
        slug: "thunderbolt",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043C\u043E\u043B\u043D\u0438\u0438",
          en: "Thunderbolt"
        },
        description: {
          ru: "\u041C\u043E\u0449\u043D\u044B\u0439 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0439 \u0440\u0430\u0437\u0440\u044F\u0434 \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C \u0446\u0435\u043B\u044C.",
          en: "A strong electric bolt may paralyze the target."
        },
        type: "electric",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/85/",
        meta: {
          ailment: {
            name: "paralysis"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/82/"
        }
      },
      {
        id: 430,
        slug: "flash-cannon",
        name: {
          ru: "\u0421\u0432\u0435\u0442\u043E\u0432\u0430\u044F \u043F\u0443\u0448\u043A\u0430",
          en: "Flash Cannon"
        },
        description: {
          ru: "\u041B\u0443\u0447 \u043D\u0430\u043A\u043E\u043F\u043B\u0435\u043D\u043D\u043E\u0439 \u044D\u043D\u0435\u0440\u0433\u0438\u0438 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443.",
          en: "Fires stored energy and may lower Special Defense."
        },
        type: "steel",
        power: 80,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/430/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 10
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/82/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 81,
          name: {
            ru: "\u041C\u0430\u0433\u043D\u0435\u043C\u0430\u0439\u0442",
            en: "Magnemite"
          }
        },
        {
          id: 82,
          name: {
            ru: "\u041C\u0430\u0433\u043D\u0435\u0442\u043E\u043D",
            en: "Magneton"
          }
        },
        {
          id: 462,
          name: {
            ru: "\u041C\u0430\u0433\u043D\u0435\u0437\u043E\u043D",
            en: "Magnezone"
          }
        }
      ],
      edges: [
        {
          from: 81,
          to: 82,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 30",
            en: "Level 30"
          },
          isDefault: true
        },
        {
          from: 82,
          to: 462,
          condition: {
            ru: "\u0413\u0440\u043E\u043C\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Thunder Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 92,
    slug: "gastly",
    name: {
      ru: "\u0413\u0430\u0441\u0442\u043B\u0438",
      en: "Gastly"
    },
    genus: {
      ru: "\u0413\u0430\u0437\u043E\u0432\u044B\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Gas Pok\xE9mon"
    },
    description: {
      ru: "\u0415\u0433\u043E \u0442\u0435\u043B\u043E \u043F\u043E\u0447\u0442\u0438 \u0446\u0435\u043B\u0438\u043A\u043E\u043C \u0441\u043E\u0441\u0442\u043E\u0438\u0442 \u0438\u0437 \u0433\u0430\u0437\u0430. \u041A\u043B\u0443\u0431\u044B \u044F\u0434\u043E\u0432\u0438\u0442\u043E\u0433\u043E \u0442\u0443\u043C\u0430\u043D\u0430 \u0434\u0435\u043B\u0430\u044E\u0442 \u0432\u0441\u0442\u0440\u0435\u0447\u0443 \u0441 \u043D\u0438\u043C \u043E\u043F\u0430\u0441\u043D\u043E\u0439.",
      en: "Gastly\u2019s nearly intangible body is made of gas. Its poisonous cloud makes close encounters dangerous."
    },
    habitat: "cave",
    types: [
      "ghost",
      "poison"
    ],
    height: 1.3,
    weight: 0.1,
    stats: [
      30,
      35,
      30,
      100,
      35,
      80
    ],
    abilities: [
      {
        id: 26,
        slug: "levitate",
        name: {
          ru: "\u041B\u0435\u0432\u0438\u0442\u0430\u0446\u0438\u044F",
          en: "Levitate"
        },
        description: {
          ru: "\u041F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0438\u0437\u0431\u0435\u0433\u0430\u0442\u044C \u0437\u0435\u043C\u043B\u044F\u043D\u044B\u0445 \u0430\u0442\u0430\u043A.",
          en: "Provides immunity to Ground moves."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/26/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 122,
        slug: "lick",
        name: {
          ru: "\u041E\u0431\u043B\u0438\u0437\u044B\u0432\u0430\u043D\u0438\u0435",
          en: "Lick"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0443\u0435\u0442 \u0434\u043B\u0438\u043D\u043D\u044B\u043C \u044F\u0437\u044B\u043A\u043E\u043C; \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C \u0446\u0435\u043B\u044C.",
          en: "Strikes with a long tongue and may cause paralysis."
        },
        type: "ghost",
        power: 30,
        accuracy: 100,
        pp: 30,
        damageClass: "physical",
        priority: 0,
        effectChance: 30,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/122/",
        meta: {
          ailment: {
            name: "paralysis"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 30,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/92/"
        }
      },
      {
        id: 247,
        slug: "shadow-ball",
        name: {
          ru: "\u0422\u0435\u043D\u0435\u0432\u043E\u0439 \u0448\u0430\u0440",
          en: "Shadow Ball"
        },
        description: {
          ru: "\u0421\u0433\u0443\u0441\u0442\u043E\u043A \u0442\u0451\u043C\u043D\u043E\u0439 \u044D\u043D\u0435\u0440\u0433\u0438\u0438 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443.",
          en: "A sphere of shadow energy may lower Special Defense."
        },
        type: "ghost",
        power: 80,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 20,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/247/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 20
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/92/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 92,
          name: {
            ru: "\u0413\u0430\u0441\u0442\u043B\u0438",
            en: "Gastly"
          }
        },
        {
          id: 93,
          name: {
            ru: "\u0425\u043E\u043D\u0442\u0435\u0440",
            en: "Haunter"
          }
        },
        {
          id: 94,
          name: {
            ru: "\u0413\u0435\u043D\u0433\u0430\u0440",
            en: "Gengar"
          }
        }
      ],
      edges: [
        {
          from: 92,
          to: 93,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 25",
            en: "Level 25"
          },
          isDefault: true
        },
        {
          from: 93,
          to: 94,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D",
            en: "Trade"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 93,
    slug: "haunter",
    name: {
      ru: "\u0425\u043E\u043D\u0442\u0435\u0440",
      en: "Haunter"
    },
    genus: {
      ru: "\u0413\u0430\u0437\u043E\u0432\u044B\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Gas Pok\xE9mon"
    },
    description: {
      ru: "\u0421\u0432\u043E\u0431\u043E\u0434\u043D\u043E \u043F\u0440\u043E\u0445\u043E\u0434\u0438\u0442 \u0441\u043A\u0432\u043E\u0437\u044C \u0441\u0442\u0435\u043D\u044B. \u0415\u0433\u043E \u043F\u043E\u044F\u0432\u043B\u0435\u043D\u0438\u044F \u0438 \u043F\u0440\u0438\u043A\u043E\u0441\u043D\u043E\u0432\u0435\u043D\u0438\u044F \u043E\u043A\u0440\u0443\u0436\u0435\u043D\u044B \u043C\u0440\u0430\u0447\u043D\u044B\u043C\u0438 \u0441\u043B\u0443\u0445\u0430\u043C\u0438.",
      en: "Haunter passes through walls freely, inspiring ominous tales about encounters with it."
    },
    habitat: "cave",
    types: [
      "ghost",
      "poison"
    ],
    height: 1.6,
    weight: 0.1,
    stats: [
      45,
      50,
      45,
      115,
      55,
      95
    ],
    abilities: [
      {
        id: 26,
        slug: "levitate",
        name: {
          ru: "\u041B\u0435\u0432\u0438\u0442\u0430\u0446\u0438\u044F",
          en: "Levitate"
        },
        description: {
          ru: "\u041F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0438\u0437\u0431\u0435\u0433\u0430\u0442\u044C \u0437\u0435\u043C\u043B\u044F\u043D\u044B\u0445 \u0430\u0442\u0430\u043A.",
          en: "Provides immunity to Ground moves."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/26/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 247,
        slug: "shadow-ball",
        name: {
          ru: "\u0422\u0435\u043D\u0435\u0432\u043E\u0439 \u0448\u0430\u0440",
          en: "Shadow Ball"
        },
        description: {
          ru: "\u0421\u0433\u0443\u0441\u0442\u043E\u043A \u0442\u0451\u043C\u043D\u043E\u0439 \u044D\u043D\u0435\u0440\u0433\u0438\u0438 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443.",
          en: "A sphere of shadow energy may lower Special Defense."
        },
        type: "ghost",
        power: 80,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 20,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/247/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 20
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/93/"
        }
      },
      {
        id: 122,
        slug: "lick",
        name: {
          ru: "\u041E\u0431\u043B\u0438\u0437\u044B\u0432\u0430\u043D\u0438\u0435",
          en: "Lick"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0443\u0435\u0442 \u0434\u043B\u0438\u043D\u043D\u044B\u043C \u044F\u0437\u044B\u043A\u043E\u043C; \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C \u0446\u0435\u043B\u044C.",
          en: "Strikes with a long tongue and may cause paralysis."
        },
        type: "ghost",
        power: 30,
        accuracy: 100,
        pp: 30,
        damageClass: "physical",
        priority: 0,
        effectChance: 30,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/122/",
        meta: {
          ailment: {
            name: "paralysis"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 30,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/93/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 92,
          name: {
            ru: "\u0413\u0430\u0441\u0442\u043B\u0438",
            en: "Gastly"
          }
        },
        {
          id: 93,
          name: {
            ru: "\u0425\u043E\u043D\u0442\u0435\u0440",
            en: "Haunter"
          }
        },
        {
          id: 94,
          name: {
            ru: "\u0413\u0435\u043D\u0433\u0430\u0440",
            en: "Gengar"
          }
        }
      ],
      edges: [
        {
          from: 92,
          to: 93,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 25",
            en: "Level 25"
          },
          isDefault: true
        },
        {
          from: 93,
          to: 94,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D",
            en: "Trade"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 94,
    slug: "gengar",
    name: {
      ru: "\u0413\u0435\u043D\u0433\u0430\u0440",
      en: "Gengar"
    },
    genus: {
      ru: "\u0422\u0435\u043D\u0435\u0432\u043E\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Shadow Pok\xE9mon"
    },
    description: {
      ru: "\u041F\u0440\u044F\u0447\u0435\u0442\u0441\u044F \u0432 \u0442\u0435\u043D\u044F\u0445 \u0438 \u043F\u044B\u0442\u0430\u0435\u0442\u0441\u044F \u0437\u0430\u0432\u043B\u0430\u0434\u0435\u0442\u044C \u0436\u0438\u0437\u043D\u0435\u043D\u043D\u043E\u0439 \u0441\u0438\u043B\u043E\u0439 \u0441\u0432\u043E\u0435\u0439 \u0436\u0435\u0440\u0442\u0432\u044B.",
      en: "It lurks in shadows while seeking to steal a victim's life force."
    },
    habitat: "cave",
    types: [
      "ghost",
      "poison"
    ],
    height: 1.5,
    weight: 40.5,
    stats: [
      60,
      65,
      60,
      130,
      75,
      110
    ],
    abilities: [
      {
        id: 130,
        slug: "cursed-body",
        name: {
          ru: "\u041F\u0440\u043E\u043A\u043B\u044F\u0442\u043E\u0435 \u0442\u0435\u043B\u043E",
          en: "Cursed Body"
        },
        description: {
          ru: "\u041F\u043E\u043B\u0443\u0447\u0435\u043D\u043D\u0430\u044F \u0430\u0442\u0430\u043A\u0430 \u043C\u043E\u0436\u0435\u0442 \u0432\u0440\u0435\u043C\u0435\u043D\u043D\u043E \u0441\u0442\u0430\u0442\u044C \u043D\u0435\u0434\u043E\u0441\u0442\u0443\u043F\u043D\u043E\u0439 \u0435\u0451 \u0432\u043B\u0430\u0434\u0435\u043B\u044C\u0446\u0443.",
          en: "A move that hits this Pok\xE9mon may temporarily be disabled."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/130/",
        descriptionSource: "editorial-summary-of-core-ability"
      }
    ],
    moves: [
      {
        id: 247,
        slug: "shadow-ball",
        name: {
          ru: "\u0422\u0435\u043D\u0435\u0432\u043E\u0439 \u0448\u0430\u0440",
          en: "Shadow Ball"
        },
        description: {
          ru: "\u0421\u0433\u0443\u0441\u0442\u043E\u043A \u0442\u0451\u043C\u043D\u043E\u0439 \u044D\u043D\u0435\u0440\u0433\u0438\u0438 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443.",
          en: "A sphere of shadow energy may lower Special Defense."
        },
        type: "ghost",
        power: 80,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 20,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/247/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 20
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/94/"
        }
      },
      {
        id: 122,
        slug: "lick",
        name: {
          ru: "\u041E\u0431\u043B\u0438\u0437\u044B\u0432\u0430\u043D\u0438\u0435",
          en: "Lick"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0443\u0435\u0442 \u0434\u043B\u0438\u043D\u043D\u044B\u043C \u044F\u0437\u044B\u043A\u043E\u043C; \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C \u0446\u0435\u043B\u044C.",
          en: "Strikes with a long tongue and may cause paralysis."
        },
        type: "ghost",
        power: 30,
        accuracy: 100,
        pp: 30,
        damageClass: "physical",
        priority: 0,
        effectChance: 30,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/122/",
        meta: {
          ailment: {
            name: "paralysis"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 30,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/94/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 92,
          name: {
            ru: "\u0413\u0430\u0441\u0442\u043B\u0438",
            en: "Gastly"
          }
        },
        {
          id: 93,
          name: {
            ru: "\u0425\u043E\u043D\u0442\u0435\u0440",
            en: "Haunter"
          }
        },
        {
          id: 94,
          name: {
            ru: "\u0413\u0435\u043D\u0433\u0430\u0440",
            en: "Gengar"
          }
        }
      ],
      edges: [
        {
          from: 92,
          to: 93,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 25",
            en: "Level 25"
          },
          isDefault: true
        },
        {
          from: 93,
          to: 94,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D",
            en: "Trade"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 95,
    slug: "onix",
    name: {
      ru: "\u041E\u043D\u0438\u043A\u0441",
      en: "Onix"
    },
    genus: {
      ru: "\u041A\u0430\u043C\u0435\u043D\u043D\u0430\u044F \u0437\u043C\u0435\u044F",
      en: "Rock Snake Pok\xE9mon"
    },
    description: {
      ru: "\u041E\u0433\u0440\u043E\u043C\u043D\u0430\u044F \u043A\u0430\u043C\u0435\u043D\u043D\u0430\u044F \u0437\u043C\u0435\u044F \u043F\u0440\u043E\u043A\u043B\u0430\u0434\u044B\u0432\u0430\u0435\u0442 \u0442\u043E\u043D\u043D\u0435\u043B\u0438 \u0433\u043B\u0443\u0431\u043E\u043A\u043E \u043F\u043E\u0434 \u0437\u0435\u043C\u043B\u0451\u0439. \u041F\u0438\u0442\u0430\u0435\u0442\u0441\u044F \u0432\u0430\u043B\u0443\u043D\u0430\u043C\u0438, \u0430 \u0435\u0451 \u0434\u0432\u0438\u0436\u0435\u043D\u0438\u0435 \u0432\u044B\u0437\u044B\u0432\u0430\u0435\u0442 \u0442\u043E\u043B\u0447\u043A\u0438.",
      en: "A giant chain of rocks burrows deep underground, feeding on boulders and shaking the earth above."
    },
    habitat: "cave",
    types: [
      "rock",
      "ground"
    ],
    height: 8.8,
    weight: 210,
    stats: [
      35,
      45,
      160,
      30,
      45,
      70
    ],
    abilities: [
      {
        id: 69,
        slug: "rock-head",
        name: {
          ru: "\u041A\u0430\u043C\u0435\u043D\u043D\u0430\u044F \u0433\u043E\u043B\u043E\u0432\u0430",
          en: "Rock Head"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u0443\u0440\u043E\u043D\u0430 \u043E\u0442\u0434\u0430\u0447\u0438 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0445 \u0430\u0442\u0430\u043A.",
          en: "Prevents recoil damage from its own moves."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/69/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 5,
        slug: "sturdy",
        name: {
          ru: "\u041F\u0440\u043E\u0447\u043D\u043E\u0441\u0442\u044C",
          en: "Sturdy"
        },
        description: {
          ru: "\u041F\u0440\u0438 \u043F\u043E\u043B\u043D\u043E\u043C \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043F\u0435\u0440\u0435\u0436\u0438\u0432\u0430\u0435\u0442 \u0443\u0434\u0430\u0440, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u0438\u043D\u0430\u0447\u0435 \u0441\u0442\u0430\u043B \u0431\u044B \u043D\u043E\u043A\u0430\u0443\u0442\u043E\u043C.",
          en: "At full HP, survives a hit that would otherwise knock it out."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/5/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 133,
        slug: "weak-armor",
        name: {
          ru: "\u0421\u043B\u0430\u0431\u0430\u044F \u0431\u0440\u043E\u043D\u044F",
          en: "Weak Armor"
        },
        description: {
          ru: "\u0424\u0438\u0437\u0438\u0447\u0435\u0441\u043A\u043E\u0435 \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u0435 \u043F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C, \u043D\u043E \u0441\u043D\u0438\u0436\u0430\u0435\u0442 \u0437\u0430\u0449\u0438\u0442\u0443.",
          en: "Physical hits raise Speed but lower Defense."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/133/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 88,
        slug: "rock-throw",
        name: {
          ru: "\u0411\u0440\u043E\u0441\u043E\u043A \u043A\u0430\u043C\u043D\u044F",
          en: "Rock Throw"
        },
        description: {
          ru: "\u041C\u0435\u0442\u043A\u043E \u0431\u0440\u043E\u0441\u0430\u0435\u0442 \u0432 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u043A\u0430\u043C\u0435\u043D\u044C.",
          en: "Hurls a rock at the target."
        },
        type: "rock",
        power: 50,
        accuracy: 90,
        pp: 15,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/88/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/95/"
        }
      },
      {
        id: 157,
        slug: "rock-slide",
        name: {
          ru: "\u041A\u0430\u043C\u043D\u0435\u043F\u0430\u0434",
          en: "Rock Slide"
        },
        description: {
          ru: "\u041E\u0431\u0440\u0443\u0448\u0438\u0432\u0430\u0435\u0442 \u043A\u0430\u043C\u043D\u0438; \u043C\u043E\u0436\u0435\u0442 \u0437\u0430\u0441\u0442\u0430\u0432\u0438\u0442\u044C \u0446\u0435\u043B\u044C \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Drops rocks onto the target and may cause flinching."
        },
        type: "rock",
        power: 75,
        accuracy: 90,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: 30,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/157/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 30,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/95/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 95,
          name: {
            ru: "\u041E\u043D\u0438\u043A\u0441",
            en: "Onix"
          }
        },
        {
          id: 208,
          name: {
            ru: "\u0421\u0442\u0438\u043B\u0438\u043A\u0441",
            en: "Steelix"
          }
        }
      ],
      edges: [
        {
          from: 95,
          to: 208,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D \xB7 \u0441 \u043F\u0440\u0435\u0434\u043C\u0435\u0442\u043E\u043C \xAB\u041C\u0435\u0442\u0430\u043B\u043B\u0438\u0447\u0435\u0441\u043A\u043E\u0435 \u043F\u043E\u043A\u0440\u044B\u0442\u0438\u0435\xBB",
            en: "Trade \xB7 holding Metal Coat"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 104,
    slug: "cubone",
    name: {
      ru: "\u041A\u044C\u044E\u0431\u043E\u043D",
      en: "Cubone"
    },
    genus: {
      ru: "\u041E\u0434\u0438\u043D\u043E\u043A\u0438\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Lonely Pok\xE9mon"
    },
    description: {
      ru: "\u041D\u043E\u0441\u0438\u0442 \u043D\u0430 \u0433\u043E\u043B\u043E\u0432\u0435 \u0447\u0435\u0440\u0435\u043F \u0441\u0432\u043E\u0435\u0439 \u043C\u0430\u0442\u0435\u0440\u0438. \u041F\u0435\u0440\u0435\u0436\u0438\u0442\u0430\u044F \u043F\u0435\u0447\u0430\u043B\u044C \u043F\u043E\u0441\u0442\u0435\u043F\u0435\u043D\u043D\u043E \u0434\u0435\u043B\u0430\u0435\u0442 \u044D\u0442\u043E\u0433\u043E \u043E\u0434\u0438\u043D\u043E\u043A\u043E\u0433\u043E \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u0430 \u0441\u0438\u043B\u044C\u043D\u0435\u0435.",
      en: "Cubone wears its mother\u2019s skull. Its lonely grief gradually gives it strength."
    },
    habitat: "mountain",
    types: [
      "ground"
    ],
    height: 0.4,
    weight: 6.5,
    stats: [
      50,
      50,
      95,
      40,
      50,
      35
    ],
    abilities: [
      {
        id: 69,
        slug: "rock-head",
        name: {
          ru: "\u041A\u0430\u043C\u0435\u043D\u043D\u0430\u044F \u0433\u043E\u043B\u043E\u0432\u0430",
          en: "Rock Head"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u0443\u0440\u043E\u043D\u0430 \u043E\u0442\u0434\u0430\u0447\u0438 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0445 \u0430\u0442\u0430\u043A.",
          en: "Prevents recoil damage from its own moves."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/69/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 31,
        slug: "lightning-rod",
        name: {
          ru: "\u0413\u0440\u043E\u043C\u043E\u043E\u0442\u0432\u043E\u0434",
          en: "Lightning Rod"
        },
        description: {
          ru: "\u041F\u0440\u0438\u0442\u044F\u0433\u0438\u0432\u0430\u0435\u0442 \u0438 \u043F\u043E\u0433\u043B\u043E\u0449\u0430\u0435\u0442 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0435 \u0430\u0442\u0430\u043A\u0438, \u043F\u043E\u0432\u044B\u0448\u0430\u044F \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443.",
          en: "Draws in and absorbs Electric moves to raise Special Attack."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/31/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 4,
        slug: "battle-armor",
        name: {
          ru: "\u0411\u043E\u0435\u0432\u0430\u044F \u0431\u0440\u043E\u043D\u044F",
          en: "Battle Armor"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u043A\u0440\u0438\u0442\u0438\u0447\u0435\u0441\u043A\u0438\u0445 \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u0439.",
          en: "Protects against critical hits."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/4/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 125,
        slug: "bone-club",
        name: {
          ru: "\u041A\u043E\u0441\u0442\u044F\u043D\u0430\u044F \u0434\u0443\u0431\u0438\u043D\u0430",
          en: "Bone Club"
        },
        description: {
          ru: "\u0411\u044C\u0451\u0442 \u043A\u043E\u0441\u0442\u044C\u044E; \u043C\u043E\u0436\u0435\u0442 \u0437\u0430\u0441\u0442\u0430\u0432\u0438\u0442\u044C \u0446\u0435\u043B\u044C \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Strikes with a bone and may cause flinching."
        },
        type: "ground",
        power: 65,
        accuracy: 85,
        pp: 20,
        damageClass: "physical",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/125/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 10,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/104/"
        }
      },
      {
        id: 155,
        slug: "bonemerang",
        name: {
          ru: "\u041A\u043E\u0441\u0442\u044F\u043D\u043E\u0439 \u0431\u0443\u043C\u0435\u0440\u0430\u043D\u0433",
          en: "Bonemerang"
        },
        description: {
          ru: "\u0411\u0440\u043E\u0448\u0435\u043D\u043D\u0430\u044F \u043A\u043E\u0441\u0442\u044C \u043D\u0430\u043D\u043E\u0441\u0438\u0442 \u0443\u0434\u0430\u0440 \u043F\u0440\u0438 \u043F\u043E\u043B\u0451\u0442\u0435 \u0438 \u0432\u043E\u0437\u0432\u0440\u0430\u0449\u0435\u043D\u0438\u0438.",
          en: "A thrown bone hits on the way out and back."
        },
        type: "ground",
        power: 50,
        accuracy: 90,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/155/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: 2,
          max_hits: 2,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/104/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 104,
          name: {
            ru: "\u041A\u044C\u044E\u0431\u043E\u043D",
            en: "Cubone"
          }
        },
        {
          id: 105,
          name: {
            ru: "\u041C\u0430\u0440\u043E\u0432\u0430\u043A",
            en: "Marowak"
          }
        }
      ],
      edges: [
        {
          from: 104,
          to: 105,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 28",
            en: "Level 28"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 105,
    slug: "marowak",
    name: {
      ru: "\u041C\u0430\u0440\u043E\u0432\u0430\u043A",
      en: "Marowak"
    },
    genus: {
      ru: "\u0425\u0440\u0430\u043D\u0438\u0442\u0435\u043B\u044C \u043A\u043E\u0441\u0442\u0435\u0439",
      en: "Bone Keeper Pok\xE9mon"
    },
    description: {
      ru: "\u041C\u0430\u0442\u0435\u0440\u0438\u043D\u0441\u043A\u0438\u0439 \u0447\u0435\u0440\u0435\u043F \u0441\u0440\u0430\u0441\u0442\u0430\u0435\u0442\u0441\u044F \u0441 \u0433\u043E\u043B\u043E\u0432\u043E\u0439 \u043F\u0440\u0438 \u044D\u0432\u043E\u043B\u044E\u0446\u0438\u0438. \u0425\u0430\u0440\u0430\u043A\u0442\u0435\u0440 \u0441\u0442\u0430\u043D\u043E\u0432\u0438\u0442\u0441\u044F \u0441\u0443\u0440\u043E\u0432\u0435\u0435.",
      en: "Evolution fuses its mother's skull to its head and hardens its temperament."
    },
    habitat: "mountain",
    types: [
      "ground"
    ],
    height: 1,
    weight: 45,
    stats: [
      60,
      80,
      110,
      50,
      80,
      45
    ],
    abilities: [
      {
        id: 69,
        slug: "rock-head",
        name: {
          ru: "\u041A\u0430\u043C\u0435\u043D\u043D\u0430\u044F \u0433\u043E\u043B\u043E\u0432\u0430",
          en: "Rock Head"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u0443\u0440\u043E\u043D\u0430 \u043E\u0442\u0434\u0430\u0447\u0438 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0445 \u0430\u0442\u0430\u043A.",
          en: "Prevents recoil damage from its own moves."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/69/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 31,
        slug: "lightning-rod",
        name: {
          ru: "\u0413\u0440\u043E\u043C\u043E\u043E\u0442\u0432\u043E\u0434",
          en: "Lightning Rod"
        },
        description: {
          ru: "\u041F\u0440\u0438\u0442\u044F\u0433\u0438\u0432\u0430\u0435\u0442 \u0438 \u043F\u043E\u0433\u043B\u043E\u0449\u0430\u0435\u0442 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0435 \u0430\u0442\u0430\u043A\u0438, \u043F\u043E\u0432\u044B\u0448\u0430\u044F \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443.",
          en: "Draws in and absorbs Electric moves to raise Special Attack."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/31/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 4,
        slug: "battle-armor",
        name: {
          ru: "\u0411\u043E\u0435\u0432\u0430\u044F \u0431\u0440\u043E\u043D\u044F",
          en: "Battle Armor"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u043A\u0440\u0438\u0442\u0438\u0447\u0435\u0441\u043A\u0438\u0445 \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u0439.",
          en: "Protects against critical hits."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/4/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 89,
        slug: "earthquake",
        name: {
          ru: "\u0417\u0435\u043C\u043B\u0435\u0442\u0440\u044F\u0441\u0435\u043D\u0438\u0435",
          en: "Earthquake"
        },
        description: {
          ru: "\u0421\u043E\u0442\u0440\u044F\u0441\u0430\u0435\u0442 \u0437\u0435\u043C\u043B\u044E \u043C\u043E\u0449\u043D\u043E\u0439 \u0443\u0434\u0430\u0440\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Shakes the ground with a powerful shock wave."
        },
        type: "ground",
        power: 100,
        accuracy: 100,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/89/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/105/"
        }
      },
      {
        id: 91,
        slug: "dig",
        name: {
          ru: "\u041F\u043E\u0434\u043A\u043E\u043F",
          en: "Dig"
        },
        description: {
          ru: "\u0421\u043A\u0440\u044B\u0432\u0430\u0435\u0442\u0441\u044F \u043F\u043E\u0434 \u0437\u0435\u043C\u043B\u0451\u0439, \u0437\u0430\u0442\u0435\u043C \u0430\u0442\u0430\u043A\u0443\u0435\u0442 \u043D\u0430 \u0441\u043B\u0435\u0434\u0443\u044E\u0449\u0435\u043C \u0445\u043E\u0434\u0443.",
          en: "Digs underground before attacking on the next turn."
        },
        type: "ground",
        power: 80,
        accuracy: 100,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/91/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/105/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 104,
          name: {
            ru: "\u041A\u044C\u044E\u0431\u043E\u043D",
            en: "Cubone"
          }
        },
        {
          id: 105,
          name: {
            ru: "\u041C\u0430\u0440\u043E\u0432\u0430\u043A",
            en: "Marowak"
          }
        }
      ],
      edges: [
        {
          from: 104,
          to: 105,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 28",
            en: "Level 28"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 111,
    slug: "rhyhorn",
    name: {
      ru: "\u0420\u0430\u0439\u0445\u043E\u0440\u043D",
      en: "Rhyhorn"
    },
    genus: {
      ru: "\u0428\u0438\u043F\u0430\u0441\u0442\u044B\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Spikes Pok\xE9mon"
    },
    description: {
      ru: "\u041D\u0430\u0441\u0442\u043E\u043B\u044C\u043A\u043E \u0441\u0438\u043B\u0451\u043D, \u0447\u0442\u043E \u0441\u043F\u043E\u0441\u043E\u0431\u0435\u043D \u0440\u0430\u0437\u0440\u0443\u0448\u0430\u0442\u044C \u0441\u043A\u0430\u043B\u044B. \u041A\u043E\u0440\u043E\u0442\u043A\u0438\u0435 \u043D\u043E\u0433\u0438 \u043C\u0435\u0448\u0430\u044E\u0442 \u0435\u043C\u0443 \u0440\u0435\u0437\u043A\u043E \u043F\u043E\u0432\u043E\u0440\u0430\u0447\u0438\u0432\u0430\u0442\u044C \u0438 \u043E\u0441\u0442\u0430\u043D\u0430\u0432\u043B\u0438\u0432\u0430\u0442\u044C\u0441\u044F.",
      en: "Rhyhorn can smash rock with great force, but its short legs make sharp turns and stops difficult."
    },
    habitat: "mountain",
    types: [
      "ground",
      "rock"
    ],
    height: 1,
    weight: 115,
    stats: [
      80,
      85,
      95,
      30,
      30,
      25
    ],
    abilities: [
      {
        id: 31,
        slug: "lightning-rod",
        name: {
          ru: "\u0413\u0440\u043E\u043C\u043E\u043E\u0442\u0432\u043E\u0434",
          en: "Lightning Rod"
        },
        description: {
          ru: "\u041F\u0440\u0438\u0442\u044F\u0433\u0438\u0432\u0430\u0435\u0442 \u0438 \u043F\u043E\u0433\u043B\u043E\u0449\u0430\u0435\u0442 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0435 \u0430\u0442\u0430\u043A\u0438, \u043F\u043E\u0432\u044B\u0448\u0430\u044F \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443.",
          en: "Draws in and absorbs Electric moves to raise Special Attack."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/31/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 69,
        slug: "rock-head",
        name: {
          ru: "\u041A\u0430\u043C\u0435\u043D\u043D\u0430\u044F \u0433\u043E\u043B\u043E\u0432\u0430",
          en: "Rock Head"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u0443\u0440\u043E\u043D\u0430 \u043E\u0442\u0434\u0430\u0447\u0438 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0445 \u0430\u0442\u0430\u043A.",
          en: "Prevents recoil damage from its own moves."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/69/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 120,
        slug: "reckless",
        name: {
          ru: "\u0411\u0435\u0437\u0440\u0430\u0441\u0441\u0443\u0434\u0441\u0442\u0432\u043E",
          en: "Reckless"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0430\u0442\u0430\u043A\u0438 \u0441 \u043E\u0442\u0434\u0430\u0447\u0435\u0439.",
          en: "Boosts moves that cause recoil damage."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/120/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 30,
        slug: "horn-attack",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u0440\u043E\u0433\u043E\u043C",
          en: "Horn Attack"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0443\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u043E\u0441\u0442\u0440\u044B\u043C \u0440\u043E\u0433\u043E\u043C.",
          en: "Strikes the target with a sharp horn."
        },
        type: "normal",
        power: 65,
        accuracy: 100,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/30/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/111/"
        }
      },
      {
        id: 89,
        slug: "earthquake",
        name: {
          ru: "\u0417\u0435\u043C\u043B\u0435\u0442\u0440\u044F\u0441\u0435\u043D\u0438\u0435",
          en: "Earthquake"
        },
        description: {
          ru: "\u0421\u043E\u0442\u0440\u044F\u0441\u0430\u0435\u0442 \u0437\u0435\u043C\u043B\u044E \u043C\u043E\u0449\u043D\u043E\u0439 \u0443\u0434\u0430\u0440\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Shakes the ground with a powerful shock wave."
        },
        type: "ground",
        power: 100,
        accuracy: 100,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/89/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/111/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 111,
          name: {
            ru: "\u0420\u0430\u0439\u0445\u043E\u0440\u043D",
            en: "Rhyhorn"
          }
        },
        {
          id: 112,
          name: {
            ru: "\u0420\u0430\u0439\u0434\u043E\u043D",
            en: "Rhydon"
          }
        },
        {
          id: 464,
          name: {
            ru: "\u0420\u0430\u0439\u043F\u0435\u0440\u0438\u043E\u0440",
            en: "Rhyperior"
          }
        }
      ],
      edges: [
        {
          from: 111,
          to: 112,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 42",
            en: "Level 42"
          },
          isDefault: true
        },
        {
          from: 112,
          to: 464,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D \xB7 \u0441 \u043F\u0440\u0435\u0434\u043C\u0435\u0442\u043E\u043C \xAB\u0417\u0430\u0449\u0438\u0442\u043D\u0438\u043A\xBB",
            en: "Trade \xB7 holding Protector"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 112,
    slug: "rhydon",
    name: {
      ru: "\u0420\u0430\u0439\u0434\u043E\u043D",
      en: "Rhydon"
    },
    genus: {
      ru: "\u0411\u0443\u0440\u044F\u0449\u0438\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Drill Pok\xE9mon"
    },
    description: {
      ru: "\u0412\u0440\u0430\u0449\u0430\u044E\u0449\u0438\u043C\u0441\u044F \u0440\u043E\u0433\u043E\u043C \u0431\u0443\u0440\u0438\u0442 \u0441\u043A\u0430\u043B\u044B. \u041F\u0440\u043E\u0447\u043D\u0430\u044F \u043A\u043E\u0436\u0430 \u0437\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u0432\u0443\u043B\u043A\u0430\u043D\u0438\u0447\u0435\u0441\u043A\u043E\u0433\u043E \u0436\u0430\u0440\u0430.",
      en: "Its spinning horn drills bedrock, while tough skin shields it from volcanic heat."
    },
    habitat: "mountain",
    types: [
      "ground",
      "rock"
    ],
    height: 1.9,
    weight: 120,
    stats: [
      105,
      130,
      120,
      45,
      45,
      40
    ],
    abilities: [
      {
        id: 31,
        slug: "lightning-rod",
        name: {
          ru: "\u0413\u0440\u043E\u043C\u043E\u043E\u0442\u0432\u043E\u0434",
          en: "Lightning Rod"
        },
        description: {
          ru: "\u041F\u0440\u0438\u0442\u044F\u0433\u0438\u0432\u0430\u0435\u0442 \u0438 \u043F\u043E\u0433\u043B\u043E\u0449\u0430\u0435\u0442 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0435 \u0430\u0442\u0430\u043A\u0438, \u043F\u043E\u0432\u044B\u0448\u0430\u044F \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443.",
          en: "Draws in and absorbs Electric moves to raise Special Attack."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/31/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 69,
        slug: "rock-head",
        name: {
          ru: "\u041A\u0430\u043C\u0435\u043D\u043D\u0430\u044F \u0433\u043E\u043B\u043E\u0432\u0430",
          en: "Rock Head"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u0443\u0440\u043E\u043D\u0430 \u043E\u0442\u0434\u0430\u0447\u0438 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0445 \u0430\u0442\u0430\u043A.",
          en: "Prevents recoil damage from its own moves."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/69/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 120,
        slug: "reckless",
        name: {
          ru: "\u0411\u0435\u0437\u0440\u0430\u0441\u0441\u0443\u0434\u0441\u0442\u0432\u043E",
          en: "Reckless"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0430\u0442\u0430\u043A\u0438 \u0441 \u043E\u0442\u0434\u0430\u0447\u0435\u0439.",
          en: "Boosts moves that cause recoil damage."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/120/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 89,
        slug: "earthquake",
        name: {
          ru: "\u0417\u0435\u043C\u043B\u0435\u0442\u0440\u044F\u0441\u0435\u043D\u0438\u0435",
          en: "Earthquake"
        },
        description: {
          ru: "\u0421\u043E\u0442\u0440\u044F\u0441\u0430\u0435\u0442 \u0437\u0435\u043C\u043B\u044E \u043C\u043E\u0449\u043D\u043E\u0439 \u0443\u0434\u0430\u0440\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Shakes the ground with a powerful shock wave."
        },
        type: "ground",
        power: 100,
        accuracy: 100,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/89/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/112/"
        }
      },
      {
        id: 157,
        slug: "rock-slide",
        name: {
          ru: "\u041A\u0430\u043C\u043D\u0435\u043F\u0430\u0434",
          en: "Rock Slide"
        },
        description: {
          ru: "\u041E\u0431\u0440\u0443\u0448\u0438\u0432\u0430\u0435\u0442 \u043A\u0430\u043C\u043D\u0438; \u043C\u043E\u0436\u0435\u0442 \u0437\u0430\u0441\u0442\u0430\u0432\u0438\u0442\u044C \u0446\u0435\u043B\u044C \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Drops rocks onto the target and may cause flinching."
        },
        type: "rock",
        power: 75,
        accuracy: 90,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: 30,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/157/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 30,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/112/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 111,
          name: {
            ru: "\u0420\u0430\u0439\u0445\u043E\u0440\u043D",
            en: "Rhyhorn"
          }
        },
        {
          id: 112,
          name: {
            ru: "\u0420\u0430\u0439\u0434\u043E\u043D",
            en: "Rhydon"
          }
        },
        {
          id: 464,
          name: {
            ru: "\u0420\u0430\u0439\u043F\u0435\u0440\u0438\u043E\u0440",
            en: "Rhyperior"
          }
        }
      ],
      edges: [
        {
          from: 111,
          to: 112,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 42",
            en: "Level 42"
          },
          isDefault: true
        },
        {
          from: 112,
          to: 464,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D \xB7 \u0441 \u043F\u0440\u0435\u0434\u043C\u0435\u0442\u043E\u043C \xAB\u0417\u0430\u0449\u0438\u0442\u043D\u0438\u043A\xBB",
            en: "Trade \xB7 holding Protector"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 116,
    slug: "horsea",
    name: {
      ru: "\u0425\u043E\u0440\u0441\u0438",
      en: "Horsea"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0434\u0440\u0430\u043A\u043E\u043D",
      en: "Dragon Pok\xE9mon"
    },
    description: {
      ru: "\u041F\u043B\u0430\u0432\u0430\u0435\u0442 \u043F\u043B\u0430\u0432\u043D\u044B\u043C\u0438, \u043F\u043E\u0445\u043E\u0436\u0438\u043C\u0438 \u043D\u0430 \u0442\u0430\u043D\u0435\u0446 \u0434\u0432\u0438\u0436\u0435\u043D\u0438\u044F\u043C\u0438. \u0425\u043E\u0440\u0441\u0438 \u0441\u043E\u0440\u0435\u0432\u043D\u0443\u044E\u0442\u0441\u044F, \u0441\u043E\u0437\u0434\u0430\u0432\u0430\u044F \u0432\u043E\u0434\u043E\u0432\u043E\u0440\u043E\u0442\u044B \u0440\u0430\u0437\u043D\u044B\u0445 \u0440\u0430\u0437\u043C\u0435\u0440\u043E\u0432.",
      en: "Horsea swim with dance-like movements and compete to create the largest whirlpool."
    },
    habitat: "water",
    types: [
      "water"
    ],
    height: 0.4,
    weight: 8,
    stats: [
      30,
      40,
      70,
      70,
      25,
      60
    ],
    abilities: [
      {
        id: 33,
        slug: "swift-swim",
        name: {
          ru: "\u0411\u044B\u0441\u0442\u0440\u043E\u0435 \u043F\u043B\u0430\u0432\u0430\u043D\u0438\u0435",
          en: "Swift Swim"
        },
        description: {
          ru: "\u0423\u0434\u0432\u0430\u0438\u0432\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u043E\u0434 \u0434\u043E\u0436\u0434\u0451\u043C.",
          en: "Doubles Speed in rain."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/33/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 97,
        slug: "sniper",
        name: {
          ru: "\u0421\u043D\u0430\u0439\u043F\u0435\u0440",
          en: "Sniper"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0443\u0440\u043E\u043D \u043A\u0440\u0438\u0442\u0438\u0447\u0435\u0441\u043A\u0438\u0445 \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u0439.",
          en: "Increases damage dealt by critical hits."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/97/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 6,
        slug: "damp",
        name: {
          ru: "\u0412\u043B\u0430\u0436\u043D\u043E\u0441\u0442\u044C",
          en: "Damp"
        },
        description: {
          ru: "\u041F\u0440\u0435\u0434\u043E\u0442\u0432\u0440\u0430\u0449\u0430\u0435\u0442 \u0441\u0430\u043C\u043E\u0443\u043D\u0438\u0447\u0442\u043E\u0436\u0435\u043D\u0438\u0435 \u0438 \u0432\u0437\u0440\u044B\u0432\u043D\u044B\u0435 \u044D\u0444\u0444\u0435\u043A\u0442\u044B.",
          en: "Prevents self-destructing moves and explosive effects."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/6/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 145,
        slug: "bubble",
        name: {
          ru: "\u041F\u0443\u0437\u044B\u0440\u0438",
          en: "Bubble"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0443\u0435\u0442 \u043F\u0443\u0437\u044B\u0440\u044F\u043C\u0438; \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u0446\u0435\u043B\u0438.",
          en: "Attacks with bubbles and may lower Speed."
        },
        type: "water",
        power: 40,
        accuracy: 100,
        pp: 30,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/145/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 10
        },
        statChanges: [
          {
            stat: "speed",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/116/"
        }
      },
      {
        id: 55,
        slug: "water-gun",
        name: {
          ru: "\u0412\u043E\u0434\u044F\u043D\u0430\u044F \u043F\u0443\u0448\u043A\u0430",
          en: "Water Gun"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u043D\u0430\u043F\u0440\u0430\u0432\u043B\u0435\u043D\u043D\u0443\u044E \u0441\u0442\u0440\u0443\u044E \u0432\u043E\u0434\u044B.",
          en: "Fires a focused jet of water."
        },
        type: "water",
        power: 40,
        accuracy: 100,
        pp: 25,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/55/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/116/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 116,
          name: {
            ru: "\u0425\u043E\u0440\u0441\u0438",
            en: "Horsea"
          }
        },
        {
          id: 117,
          name: {
            ru: "\u0421\u0438\u0434\u0440\u0430",
            en: "Seadra"
          }
        },
        {
          id: 230,
          name: {
            ru: "\u041A\u0438\u043D\u0433\u0434\u0440\u0430",
            en: "Kingdra"
          }
        }
      ],
      edges: [
        {
          from: 116,
          to: 117,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 32",
            en: "Level 32"
          },
          isDefault: true
        },
        {
          from: 117,
          to: 230,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D \xB7 \u0441 \u043F\u0440\u0435\u0434\u043C\u0435\u0442\u043E\u043C \xAB\u0427\u0435\u0448\u0443\u044F \u0434\u0440\u0430\u043A\u043E\u043D\u0430\xBB",
            en: "Trade \xB7 holding Dragon Scale"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 117,
    slug: "seadra",
    name: {
      ru: "\u0421\u0438\u0434\u0440\u0430",
      en: "Seadra"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0434\u0440\u0430\u043A\u043E\u043D",
      en: "Dragon Pok\xE9mon"
    },
    description: {
      ru: "\u0423\u0437\u043A\u043E\u0435 \u0440\u044B\u043B\u043E \u0441\u043E\u0437\u0434\u0430\u0451\u0442 \u0441\u0438\u043B\u044C\u043D\u043E\u0435 \u0432\u0441\u0430\u0441\u044B\u0432\u0430\u043D\u0438\u0435 \u0438 \u043F\u043E\u043C\u043E\u0433\u0430\u0435\u0442 \u0432\u0442\u044F\u0433\u0438\u0432\u0430\u0442\u044C \u043A\u0440\u0443\u043F\u043D\u0443\u044E \u043F\u0438\u0449\u0443.",
      en: "Its slender mouth generates enough suction to pull in surprisingly large food."
    },
    habitat: "water",
    types: [
      "water"
    ],
    height: 1.2,
    weight: 25,
    stats: [
      55,
      65,
      95,
      95,
      45,
      85
    ],
    abilities: [
      {
        id: 38,
        slug: "poison-point",
        name: {
          ru: "\u042F\u0434\u043E\u0432\u0438\u0442\u0430\u044F \u0442\u043E\u0447\u043A\u0430",
          en: "Poison Point"
        },
        description: {
          ru: "\u041A\u043E\u043D\u0442\u0430\u043A\u0442 \u0441 \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u043E\u043C \u043C\u043E\u0436\u0435\u0442 \u043E\u0442\u0440\u0430\u0432\u0438\u0442\u044C \u0430\u0442\u0430\u043A\u0443\u044E\u0449\u0435\u0433\u043E.",
          en: "Contact with this Pok\xE9mon may poison the attacker."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/38/",
        descriptionSource: "editorial-summary-of-core-ability"
      },
      {
        id: 97,
        slug: "sniper",
        name: {
          ru: "\u0421\u043D\u0430\u0439\u043F\u0435\u0440",
          en: "Sniper"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0443\u0440\u043E\u043D \u043A\u0440\u0438\u0442\u0438\u0447\u0435\u0441\u043A\u0438\u0445 \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u0439.",
          en: "Increases damage dealt by critical hits."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/97/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 6,
        slug: "damp",
        name: {
          ru: "\u0412\u043B\u0430\u0436\u043D\u043E\u0441\u0442\u044C",
          en: "Damp"
        },
        description: {
          ru: "\u041F\u0440\u0435\u0434\u043E\u0442\u0432\u0440\u0430\u0449\u0430\u0435\u0442 \u0441\u0430\u043C\u043E\u0443\u043D\u0438\u0447\u0442\u043E\u0436\u0435\u043D\u0438\u0435 \u0438 \u0432\u0437\u0440\u044B\u0432\u043D\u044B\u0435 \u044D\u0444\u0444\u0435\u043A\u0442\u044B.",
          en: "Prevents self-destructing moves and explosive effects."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/6/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 57,
        slug: "surf",
        name: {
          ru: "\u0421\u0451\u0440\u0444\u0438\u043D\u0433",
          en: "Surf"
        },
        description: {
          ru: "\u041D\u0430\u043A\u0440\u044B\u0432\u0430\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u0431\u043E\u043B\u044C\u0448\u043E\u0439 \u0432\u043E\u0434\u044F\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Sweeps over opponents with a large wave of water."
        },
        type: "water",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/57/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/117/"
        }
      },
      {
        id: 352,
        slug: "water-pulse",
        name: {
          ru: "\u0412\u043E\u0434\u043D\u044B\u0439 \u0438\u043C\u043F\u0443\u043B\u044C\u0441",
          en: "Water Pulse"
        },
        description: {
          ru: "\u0412\u043E\u0434\u044F\u043D\u0430\u044F \u0432\u043E\u043B\u043D\u0430 \u043C\u043E\u0436\u0435\u0442 \u043F\u0440\u0438\u0432\u0435\u0441\u0442\u0438 \u0446\u0435\u043B\u044C \u0432 \u0437\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u043E.",
          en: "A pulsing wave of water may confuse the target."
        },
        type: "water",
        power: 60,
        accuracy: 100,
        pp: 20,
        damageClass: "special",
        priority: 0,
        effectChance: 20,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/352/",
        meta: {
          ailment: {
            name: "confusion"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: 2,
          max_turns: 5,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 20,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/117/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 116,
          name: {
            ru: "\u0425\u043E\u0440\u0441\u0438",
            en: "Horsea"
          }
        },
        {
          id: 117,
          name: {
            ru: "\u0421\u0438\u0434\u0440\u0430",
            en: "Seadra"
          }
        },
        {
          id: 230,
          name: {
            ru: "\u041A\u0438\u043D\u0433\u0434\u0440\u0430",
            en: "Kingdra"
          }
        }
      ],
      edges: [
        {
          from: 116,
          to: 117,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 32",
            en: "Level 32"
          },
          isDefault: true
        },
        {
          from: 117,
          to: 230,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D \xB7 \u0441 \u043F\u0440\u0435\u0434\u043C\u0435\u0442\u043E\u043C \xAB\u0427\u0435\u0448\u0443\u044F \u0434\u0440\u0430\u043A\u043E\u043D\u0430\xBB",
            en: "Trade \xB7 holding Dragon Scale"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 123,
    slug: "scyther",
    name: {
      ru: "\u0421\u043A\u0430\u0439\u0442\u0435\u0440",
      en: "Scyther"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0431\u043E\u0433\u043E\u043C\u043E\u043B",
      en: "Mantis Pok\xE9mon"
    },
    description: {
      ru: "\u041E\u0441\u0442\u0440\u044B\u0435 \u043B\u0435\u0437\u0432\u0438\u044F \u043D\u0430 \u043F\u0435\u0440\u0435\u0434\u043D\u0438\u0445 \u043B\u0430\u043F\u0430\u0445 \u2014 \u0435\u0433\u043E \u0433\u043B\u0430\u0432\u043D\u043E\u0435 \u043E\u0440\u0443\u0436\u0438\u0435. \u0411\u044B\u0441\u0442\u0440\u044B\u0435 \u0438 \u043B\u043E\u0432\u043A\u0438\u0435 \u0434\u0432\u0438\u0436\u0435\u043D\u0438\u044F \u043F\u043E\u043C\u043E\u0433\u0430\u044E\u0442 \u0434\u043E\u0433\u043E\u043D\u044F\u0442\u044C \u0434\u043E\u0431\u044B\u0447\u0443.",
      en: "Sharp forearm blades and agile movements make Scyther a formidable hunter."
    },
    habitat: "grassland",
    types: [
      "bug",
      "flying"
    ],
    height: 1.5,
    weight: 56,
    stats: [
      70,
      110,
      80,
      55,
      80,
      105
    ],
    abilities: [
      {
        id: 68,
        slug: "swarm",
        name: {
          ru: "\u0420\u043E\u0439",
          en: "Swarm"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u043D\u0430\u0441\u0435\u043A\u043E\u043C\u044B\u0435 \u0430\u0442\u0430\u043A\u0438, \u043A\u043E\u0433\u0434\u0430 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043D\u0438\u0437\u043A\u043E\u0435.",
          en: "Boosts Bug moves when HP is low."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/68/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 101,
        slug: "technician",
        name: {
          ru: "\u0422\u0435\u0445\u043D\u0438\u043A",
          en: "Technician"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0430\u0442\u0430\u043A\u0438 \u0441 \u043D\u0435\u0431\u043E\u043B\u044C\u0448\u043E\u0439 \u0431\u0430\u0437\u043E\u0432\u043E\u0439 \u043C\u043E\u0449\u043D\u043E\u0441\u0442\u044C\u044E.",
          en: "Boosts moves with low base power."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/101/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 80,
        slug: "steadfast",
        name: {
          ru: "\u0421\u0442\u043E\u0439\u043A\u043E\u0441\u0442\u044C",
          en: "Steadfast"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u043E\u0441\u043B\u0435 \u0438\u0441\u043F\u0443\u0433\u0430.",
          en: "Raises Speed after flinching."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/80/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 17,
        slug: "wing-attack",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043A\u0440\u044B\u043B\u043E\u043C",
          en: "Wing Attack"
        },
        description: {
          ru: "\u041D\u0430\u043D\u043E\u0441\u0438\u0442 \u0443\u0434\u0430\u0440 \u0448\u0438\u0440\u043E\u043A\u043E \u0440\u0430\u0441\u043A\u0440\u044B\u0442\u044B\u043C\u0438 \u043A\u0440\u044B\u043B\u044C\u044F\u043C\u0438.",
          en: "Strikes the target with outstretched wings."
        },
        type: "flying",
        power: 60,
        accuracy: 100,
        pp: 35,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/17/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/123/"
        }
      },
      {
        id: 404,
        slug: "x-scissor",
        name: {
          ru: "\u041A\u0440\u0435\u0441\u0442-\u043D\u043E\u0436\u043D\u0438\u0446\u044B",
          en: "X-Scissor"
        },
        description: {
          ru: "\u041F\u0435\u0440\u0435\u043A\u0440\u0435\u0449\u0438\u0432\u0430\u0435\u0442 \u043B\u0435\u0437\u0432\u0438\u044F \u0438 \u043D\u0430\u043D\u043E\u0441\u0438\u0442 \u0440\u0435\u0436\u0443\u0449\u0438\u0439 \u0443\u0434\u0430\u0440.",
          en: "Crosses its blades to deliver a slashing strike."
        },
        type: "bug",
        power: 80,
        accuracy: 100,
        pp: 15,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/404/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/123/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 123,
          name: {
            ru: "\u0421\u043A\u0430\u0439\u0442\u0435\u0440",
            en: "Scyther"
          }
        },
        {
          id: 212,
          name: {
            ru: "\u0421\u0438\u0437\u043E\u0440",
            en: "Scizor"
          }
        },
        {
          id: 900,
          name: {
            ru: "\u041A\u043B\u0438\u0432\u043E\u0440",
            en: "Kleavor"
          }
        }
      ],
      edges: [
        {
          from: 123,
          to: 212,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D \xB7 \u0441 \u043F\u0440\u0435\u0434\u043C\u0435\u0442\u043E\u043C \xAB\u041C\u0435\u0442\u0430\u043B\u043B\u0438\u0447\u0435\u0441\u043A\u043E\u0435 \u043F\u043E\u043A\u0440\u044B\u0442\u0438\u0435\xBB",
            en: "Trade \xB7 holding Metal Coat"
          },
          isDefault: true
        },
        {
          from: 123,
          to: 900,
          condition: {
            ru: "\u0427\u0451\u0440\u043D\u044B\u0439 \u0430\u0432\u0433\u0443\u0440\u0438\u0442",
            en: "Black Augurite"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 129,
    slug: "magikarp",
    name: {
      ru: "\u041C\u044D\u0434\u0436\u0438\u043A\u0430\u0440\u043F",
      en: "Magikarp"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0440\u044B\u0431\u0430",
      en: "Fish Pok\xE9mon"
    },
    description: {
      ru: "\u0412 \u0431\u043E\u044E \u0432\u044B\u0433\u043B\u044F\u0434\u0438\u0442 \u0441\u043B\u0430\u0431\u044B\u043C, \u043D\u043E \u043E\u0442\u043B\u0438\u0447\u0430\u0435\u0442\u0441\u044F \u0443\u0434\u0438\u0432\u0438\u0442\u0435\u043B\u044C\u043D\u043E\u0439 \u0432\u044B\u043D\u043E\u0441\u043B\u0438\u0432\u043E\u0441\u0442\u044C\u044E. \u0421\u043F\u043E\u0441\u043E\u0431\u0435\u043D \u0436\u0438\u0442\u044C \u0434\u0430\u0436\u0435 \u0432 \u043C\u0443\u0442\u043D\u043E\u0439 \u0432\u043E\u0434\u0435.",
      en: "Though weak in battle, Magikarp is unusually hardy and can thrive even in murky water."
    },
    habitat: "water",
    types: [
      "water"
    ],
    height: 0.9,
    weight: 10,
    stats: [
      20,
      10,
      55,
      15,
      20,
      80
    ],
    abilities: [
      {
        id: 33,
        slug: "swift-swim",
        name: {
          ru: "\u0411\u044B\u0441\u0442\u0440\u043E\u0435 \u043F\u043B\u0430\u0432\u0430\u043D\u0438\u0435",
          en: "Swift Swim"
        },
        description: {
          ru: "\u0423\u0434\u0432\u0430\u0438\u0432\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u043E\u0434 \u0434\u043E\u0436\u0434\u0451\u043C.",
          en: "Doubles Speed in rain."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/33/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 155,
        slug: "rattled",
        name: {
          ru: "\u0418\u0441\u043F\u0443\u0433",
          en: "Rattled"
        },
        description: {
          ru: "\u041F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u044F \u0442\u0451\u043C\u043D\u044B\u0445, \u043F\u0440\u0438\u0437\u0440\u0430\u0447\u043D\u044B\u0445 \u0438 \u043D\u0430\u0441\u0435\u043A\u043E\u043C\u044B\u0445 \u0430\u0442\u0430\u043A \u043F\u043E\u0432\u044B\u0448\u0430\u044E\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C.",
          en: "Dark, Ghost and Bug hits raise Speed."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/155/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 33,
        slug: "tackle",
        name: {
          ru: "\u0422\u0430\u0440\u0430\u043D",
          en: "Tackle"
        },
        description: {
          ru: "\u0420\u0430\u0437\u0433\u043E\u043D\u044F\u0435\u0442\u0441\u044F \u0438 \u0441\u0442\u0430\u043B\u043A\u0438\u0432\u0430\u0435\u0442\u0441\u044F \u0441 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u043E\u043C \u0432\u0441\u0435\u043C \u0442\u0435\u043B\u043E\u043C.",
          en: "Charges into the target with its whole body."
        },
        type: "normal",
        power: 40,
        accuracy: 100,
        pp: 35,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/33/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/129/"
        }
      },
      {
        id: 175,
        slug: "flail",
        name: {
          ru: "\u0411\u0430\u0440\u0430\u0445\u0442\u0430\u043D\u044C\u0435",
          en: "Flail"
        },
        description: {
          ru: "\u041E\u0442\u0447\u0430\u044F\u043D\u043D\u043E \u0430\u0442\u0430\u043A\u0443\u0435\u0442; \u043C\u043E\u0449\u043D\u043E\u0441\u0442\u044C \u0440\u0430\u0441\u0442\u0451\u0442 \u043F\u043E \u043C\u0435\u0440\u0435 \u043F\u043E\u0442\u0435\u0440\u0438 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u044F.",
          en: "A desperate attack that grows stronger as HP falls."
        },
        type: "normal",
        power: null,
        accuracy: 100,
        pp: 15,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/175/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/129/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 129,
          name: {
            ru: "\u041C\u044D\u0434\u0436\u0438\u043A\u0430\u0440\u043F",
            en: "Magikarp"
          }
        },
        {
          id: 130,
          name: {
            ru: "\u0413\u044C\u044F\u0440\u0430\u0434\u043E\u0441",
            en: "Gyarados"
          }
        }
      ],
      edges: [
        {
          from: 129,
          to: 130,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 20",
            en: "Level 20"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 130,
    slug: "gyarados",
    name: {
      ru: "\u0413\u044C\u044F\u0440\u0430\u0434\u043E\u0441",
      en: "Gyarados"
    },
    genus: {
      ru: "\u0421\u0432\u0438\u0440\u0435\u043F\u044B\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Atrocious Pok\xE9mon"
    },
    description: {
      ru: "\u0414\u0440\u0435\u0432\u043D\u0438\u0435 \u0441\u043A\u0430\u0437\u0430\u043D\u0438\u044F \u043E\u043F\u0438\u0441\u044B\u0432\u0430\u044E\u0442 \u0434\u0440\u0430\u043A\u043E\u043D\u0430, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u0440\u0430\u0437\u0440\u0443\u0448\u0430\u043B \u043F\u043E\u0441\u0435\u043B\u0435\u043D\u0438\u044F \u0440\u0430\u0441\u043A\u0430\u043B\u0451\u043D\u043D\u044B\u043C\u0438 \u043B\u0443\u0447\u0430\u043C\u0438.",
      en: "Ancient accounts describe a dragon laying waste to villages with searing beams."
    },
    habitat: "water",
    types: [
      "water",
      "flying"
    ],
    height: 6.5,
    weight: 235,
    stats: [
      95,
      125,
      79,
      60,
      100,
      81
    ],
    abilities: [
      {
        id: 22,
        slug: "intimidate",
        name: {
          ru: "\u0423\u0441\u0442\u0440\u0430\u0448\u0435\u043D\u0438\u0435",
          en: "Intimidate"
        },
        description: {
          ru: "\u041F\u0440\u0438 \u0432\u044B\u0445\u043E\u0434\u0435 \u0432 \u0431\u043E\u0439 \u0441\u043D\u0438\u0436\u0430\u0435\u0442 \u0441\u0438\u043B\u0443 \u0430\u0442\u0430\u043A\u0438 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u043E\u0432.",
          en: "Lowers opponents\u2019 Attack on entering battle."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/22/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 153,
        slug: "moxie",
        name: {
          ru: "\u0421\u0430\u043C\u043E\u0443\u0432\u0435\u0440\u0435\u043D\u043D\u043E\u0441\u0442\u044C",
          en: "Moxie"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0430\u0442\u0430\u043A\u0443 \u043F\u043E\u0441\u043B\u0435 \u043D\u043E\u043A\u0430\u0443\u0442\u0430 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Raises Attack after knocking out an opponent."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/153/",
        descriptionSource: "editorial-summary-of-core-ability"
      }
    ],
    moves: [
      {
        id: 57,
        slug: "surf",
        name: {
          ru: "\u0421\u0451\u0440\u0444\u0438\u043D\u0433",
          en: "Surf"
        },
        description: {
          ru: "\u041D\u0430\u043A\u0440\u044B\u0432\u0430\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u0431\u043E\u043B\u044C\u0448\u043E\u0439 \u0432\u043E\u0434\u044F\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Sweeps over opponents with a large wave of water."
        },
        type: "water",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/57/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/130/"
        }
      },
      {
        id: 542,
        slug: "hurricane",
        name: {
          ru: "\u0423\u0440\u0430\u0433\u0430\u043D",
          en: "Hurricane"
        },
        description: {
          ru: "\u041C\u043E\u0449\u043D\u044B\u0439 \u0432\u0438\u0445\u0440\u044C \u043C\u043E\u0436\u0435\u0442 \u043F\u0440\u0438\u0432\u0435\u0441\u0442\u0438 \u0446\u0435\u043B\u044C \u0432 \u0437\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u043E.",
          en: "A fierce whirlwind may leave the target confused."
        },
        type: "flying",
        power: 110,
        accuracy: 70,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 30,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/542/",
        meta: {
          ailment: {
            name: "confusion"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: 2,
          max_turns: 5,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 30,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/130/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 129,
          name: {
            ru: "\u041C\u044D\u0434\u0436\u0438\u043A\u0430\u0440\u043F",
            en: "Magikarp"
          }
        },
        {
          id: 130,
          name: {
            ru: "\u0413\u044C\u044F\u0440\u0430\u0434\u043E\u0441",
            en: "Gyarados"
          }
        }
      ],
      edges: [
        {
          from: 129,
          to: 130,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 20",
            en: "Level 20"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 131,
    slug: "lapras",
    name: {
      ru: "\u041B\u0430\u043F\u0440\u0430\u0441",
      en: "Lapras"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043F\u0435\u0440\u0435\u0432\u043E\u0437\u0447\u0438\u043A",
      en: "Transport Pok\xE9mon"
    },
    description: {
      ru: "\u0425\u043E\u043B\u043E\u0434\u043E\u0441\u0442\u043E\u0439\u043A\u0438\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D, \u043A\u043E\u0442\u043E\u0440\u043E\u043C\u0443 \u043D\u0435 \u0441\u0442\u0440\u0430\u0448\u043D\u044B \u043B\u0435\u0434\u044F\u043D\u044B\u0435 \u043C\u043E\u0440\u044F. \u0415\u0433\u043E \u0433\u043B\u0430\u0434\u043A\u0430\u044F \u043A\u043E\u0436\u0430 \u043E\u0441\u0442\u0430\u0451\u0442\u0441\u044F \u043F\u0440\u043E\u0445\u043B\u0430\u0434\u043D\u043E\u0439 \u043D\u0430 \u043E\u0449\u0443\u043F\u044C.",
      en: "Lapras crosses icy seas with ease. Its smooth skin feels cool to the touch."
    },
    habitat: "water",
    types: [
      "water",
      "ice"
    ],
    height: 2.5,
    weight: 220,
    stats: [
      130,
      85,
      80,
      85,
      95,
      60
    ],
    abilities: [
      {
        id: 11,
        slug: "water-absorb",
        name: {
          ru: "\u041F\u043E\u0433\u043B\u043E\u0449\u0435\u043D\u0438\u0435 \u0432\u043E\u0434\u044B",
          en: "Water Absorb"
        },
        description: {
          ru: "\u0412\u043E\u0434\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438 \u0432\u043E\u0441\u0441\u0442\u0430\u043D\u0430\u0432\u043B\u0438\u0432\u0430\u044E\u0442 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u0432\u043C\u0435\u0441\u0442\u043E \u043D\u0430\u043D\u0435\u0441\u0435\u043D\u0438\u044F \u0443\u0440\u043E\u043D\u0430.",
          en: "Water moves restore HP instead of dealing damage."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/11/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 75,
        slug: "shell-armor",
        name: {
          ru: "\u0411\u0440\u043E\u043D\u044F \u043F\u0430\u043D\u0446\u0438\u0440\u044F",
          en: "Shell Armor"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u043A\u0440\u0438\u0442\u0438\u0447\u0435\u0441\u043A\u0438\u0445 \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u0439.",
          en: "Protects against critical hits."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/75/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 93,
        slug: "hydration",
        name: {
          ru: "\u0413\u0438\u0434\u0440\u0430\u0442\u0430\u0446\u0438\u044F",
          en: "Hydration"
        },
        description: {
          ru: "\u041F\u043E\u0434 \u0434\u043E\u0436\u0434\u0451\u043C \u0438\u0437\u0431\u0430\u0432\u043B\u044F\u0435\u0442 \u043E\u0442 \u043F\u0440\u043E\u0431\u043B\u0435\u043C \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u044F.",
          en: "Cures status conditions in rain."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/93/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 58,
        slug: "ice-beam",
        name: {
          ru: "\u041B\u0435\u0434\u044F\u043D\u043E\u0439 \u043B\u0443\u0447",
          en: "Ice Beam"
        },
        description: {
          ru: "\u0425\u043E\u043B\u043E\u0434\u043D\u044B\u0439 \u043B\u0443\u0447 \u043C\u043E\u0436\u0435\u0442 \u0437\u0430\u043C\u043E\u0440\u043E\u0437\u0438\u0442\u044C \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "An icy beam may freeze the target."
        },
        type: "ice",
        power: 90,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/58/",
        meta: {
          ailment: {
            name: "freeze"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/131/"
        }
      },
      {
        id: 57,
        slug: "surf",
        name: {
          ru: "\u0421\u0451\u0440\u0444\u0438\u043D\u0433",
          en: "Surf"
        },
        description: {
          ru: "\u041D\u0430\u043A\u0440\u044B\u0432\u0430\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u0431\u043E\u043B\u044C\u0448\u043E\u0439 \u0432\u043E\u0434\u044F\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Sweeps over opponents with a large wave of water."
        },
        type: "water",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/57/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/131/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 131,
          name: {
            ru: "\u041B\u0430\u043F\u0440\u0430\u0441",
            en: "Lapras"
          }
        }
      ],
      edges: []
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 133,
    slug: "eevee",
    name: {
      ru: "\u0418\u0432\u0438",
      en: "Eevee"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D \u044D\u0432\u043E\u043B\u044E\u0446\u0438\u0438",
      en: "Evolution Pok\xE9mon"
    },
    description: {
      ru: "\u041E\u0431\u043B\u0430\u0434\u0430\u0435\u0442 \u043D\u0435\u043E\u0431\u044B\u0447\u043D\u043E\u0439 \u0441\u043F\u043E\u0441\u043E\u0431\u043D\u043E\u0441\u0442\u044C\u044E \u044D\u0432\u043E\u043B\u044E\u0446\u0438\u043E\u043D\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0432\u043E \u043C\u043D\u043E\u0436\u0435\u0441\u0442\u0432\u043E \u0444\u043E\u0440\u043C. \u0415\u0433\u043E \u0440\u0430\u0437\u0432\u0438\u0442\u0438\u0435 \u0437\u0430\u0432\u0438\u0441\u0438\u0442 \u043E\u0442 \u0443\u0441\u043B\u043E\u0432\u0438\u0439 \u0438 \u043E\u043A\u0440\u0443\u0436\u0430\u044E\u0449\u0435\u0439 \u0441\u0440\u0435\u0434\u044B.",
      en: "Eevee has the potential to evolve into many forms, influenced by conditions and its surroundings."
    },
    habitat: "urban",
    types: [
      "normal"
    ],
    height: 0.3,
    weight: 6.5,
    stats: [
      55,
      55,
      50,
      45,
      65,
      55
    ],
    abilities: [
      {
        id: 50,
        slug: "run-away",
        name: {
          ru: "\u041F\u043E\u0431\u0435\u0433",
          en: "Run Away"
        },
        description: {
          ru: "\u041F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0443\u0441\u043F\u0435\u0448\u043D\u043E \u0443\u0431\u0435\u0436\u0430\u0442\u044C \u043E\u0442 \u0434\u0438\u043A\u043E\u0433\u043E \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u0430.",
          en: "Ensures escape from wild Pok\xE9mon battles."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/50/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 91,
        slug: "adaptability",
        name: {
          ru: "\u0410\u0434\u0430\u043F\u0442\u0430\u0446\u0438\u044F",
          en: "Adaptability"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0431\u043E\u043D\u0443\u0441 \u0430\u0442\u0430\u043A, \u0441\u043E\u0432\u043F\u0430\u0434\u0430\u044E\u0449\u0438\u0445 \u0441 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u043C \u0442\u0438\u043F\u043E\u043C.",
          en: "Boosts the bonus for moves matching the Pok\xE9mon\u2019s own type."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/91/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 107,
        slug: "anticipation",
        name: {
          ru: "\u041F\u0440\u0435\u0434\u0447\u0443\u0432\u0441\u0442\u0432\u0438\u0435",
          en: "Anticipation"
        },
        description: {
          ru: "\u041F\u0440\u0435\u0434\u0443\u043F\u0440\u0435\u0436\u0434\u0430\u0435\u0442 \u043E\u0431 \u043E\u0441\u043E\u0431\u0435\u043D\u043D\u043E \u043E\u043F\u0430\u0441\u043D\u044B\u0445 \u0430\u0442\u0430\u043A\u0430\u0445 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Warns of particularly dangerous opposing moves."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/107/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 98,
        slug: "quick-attack",
        name: {
          ru: "\u0411\u044B\u0441\u0442\u0440\u0430\u044F \u0430\u0442\u0430\u043A\u0430",
          en: "Quick Attack"
        },
        description: {
          ru: "\u0420\u0435\u0437\u043A\u0438\u0439 \u0440\u044B\u0432\u043E\u043A \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0430\u0442\u0430\u043A\u043E\u0432\u0430\u0442\u044C \u0441 \u043F\u043E\u0432\u044B\u0448\u0435\u043D\u043D\u044B\u043C \u043F\u0440\u0438\u043E\u0440\u0438\u0442\u0435\u0442\u043E\u043C.",
          en: "A swift lunge with increased move priority."
        },
        type: "normal",
        power: 40,
        accuracy: 100,
        pp: 30,
        damageClass: "physical",
        priority: 1,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/98/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/133/"
        }
      },
      {
        id: 129,
        slug: "swift",
        name: {
          ru: "\u0417\u0432\u0451\u0437\u0434\u043D\u044B\u0439 \u0443\u0434\u0430\u0440",
          en: "Swift"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u0441\u0432\u0435\u0442\u044F\u0449\u0438\u0435\u0441\u044F \u0437\u0432\u0451\u0437\u0434\u044B, \u043A\u043E\u0442\u043E\u0440\u044B\u0435 \u043D\u0435 \u043F\u0440\u043E\u043C\u0430\u0445\u0438\u0432\u0430\u044E\u0442\u0441\u044F.",
          en: "Fires glowing stars that do not miss."
        },
        type: "normal",
        power: 60,
        accuracy: null,
        pp: 20,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/129/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/133/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 133,
          name: {
            ru: "\u0418\u0432\u0438",
            en: "Eevee"
          }
        },
        {
          id: 134,
          name: {
            ru: "\u0412\u0430\u043F\u043E\u0440\u0435\u043E\u043D",
            en: "Vaporeon"
          }
        },
        {
          id: 135,
          name: {
            ru: "\u0414\u0436\u043E\u043B\u0442\u0435\u043E\u043D",
            en: "Jolteon"
          }
        },
        {
          id: 136,
          name: {
            ru: "\u0424\u043B\u0430\u0440\u0435\u043E\u043D",
            en: "Flareon"
          }
        },
        {
          id: 196,
          name: {
            ru: "\u042D\u0441\u043F\u0435\u043E\u043D",
            en: "Espeon"
          }
        },
        {
          id: 197,
          name: {
            ru: "\u0410\u043C\u0431\u0440\u0435\u043E\u043D",
            en: "Umbreon"
          }
        },
        {
          id: 470,
          name: {
            ru: "\u041B\u0438\u0444\u0435\u043E\u043D",
            en: "Leafeon"
          }
        },
        {
          id: 471,
          name: {
            ru: "\u0413\u043B\u0430\u0441\u0435\u043E\u043D",
            en: "Glaceon"
          }
        },
        {
          id: 700,
          name: {
            ru: "\u0421\u0438\u043B\u044C\u0432\u0435\u043E\u043D",
            en: "Sylveon"
          }
        }
      ],
      edges: [
        {
          from: 133,
          to: 134,
          condition: {
            ru: "\u0412\u043E\u0434\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Water Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 135,
          condition: {
            ru: "\u0413\u0440\u043E\u043C\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Thunder Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 136,
          condition: {
            ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Fire Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 196,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0434\u043D\u0451\u043C",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during day"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 197,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u043D\u043E\u0447\u044C\u044E",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during night"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 470,
          condition: {
            ru: "\u041B\u0438\u0441\u0442\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Leaf Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 471,
          condition: {
            ru: "\u041B\u0435\u0434\u044F\u043D\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Ice Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 700,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0437\u043D\u0430\u0435\u0442 \u0432\u043E\u043B\u0448\u0435\u0431\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443",
            en: "Level up \xB7 friendship \u2265 160 \xB7 knows a Fairy move"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 134,
    slug: "vaporeon",
    name: {
      ru: "\u0412\u0430\u043F\u043E\u0440\u0435\u043E\u043D",
      en: "Vaporeon"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D \u0432\u043E\u0434\u043D\u044B\u0445 \u0441\u0442\u0440\u0443\u0439",
      en: "Bubble Jet Pok\xE9mon"
    },
    description: {
      ru: "\u041A\u043B\u0435\u0442\u043A\u0438 \u043F\u043E\u0445\u043E\u0436\u0438 \u043D\u0430 \u043C\u043E\u043B\u0435\u043A\u0443\u043B\u044B \u0432\u043E\u0434\u044B, \u043F\u043E\u044D\u0442\u043E\u043C\u0443 \u043E\u043D \u0441\u043F\u043E\u0441\u043E\u0431\u0435\u043D \u0441\u043A\u0440\u044B\u0432\u0430\u0442\u044C\u0441\u044F \u043F\u043E\u0434 \u0435\u0451 \u043F\u043E\u0432\u0435\u0440\u0445\u043D\u043E\u0441\u0442\u044C\u044E.",
      en: "Water-like cells help it conceal its form while submerged."
    },
    habitat: "urban",
    types: [
      "water"
    ],
    height: 1,
    weight: 29,
    stats: [
      130,
      65,
      60,
      110,
      95,
      65
    ],
    abilities: [
      {
        id: 11,
        slug: "water-absorb",
        name: {
          ru: "\u041F\u043E\u0433\u043B\u043E\u0449\u0435\u043D\u0438\u0435 \u0432\u043E\u0434\u044B",
          en: "Water Absorb"
        },
        description: {
          ru: "\u0412\u043E\u0434\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438 \u0432\u043E\u0441\u0441\u0442\u0430\u043D\u0430\u0432\u043B\u0438\u0432\u0430\u044E\u0442 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u0432\u043C\u0435\u0441\u0442\u043E \u043D\u0430\u043D\u0435\u0441\u0435\u043D\u0438\u044F \u0443\u0440\u043E\u043D\u0430.",
          en: "Water moves restore HP instead of dealing damage."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/11/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 93,
        slug: "hydration",
        name: {
          ru: "\u0413\u0438\u0434\u0440\u0430\u0442\u0430\u0446\u0438\u044F",
          en: "Hydration"
        },
        description: {
          ru: "\u041F\u043E\u0434 \u0434\u043E\u0436\u0434\u0451\u043C \u0438\u0437\u0431\u0430\u0432\u043B\u044F\u0435\u0442 \u043E\u0442 \u043F\u0440\u043E\u0431\u043B\u0435\u043C \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u044F.",
          en: "Cures status conditions in rain."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/93/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 57,
        slug: "surf",
        name: {
          ru: "\u0421\u0451\u0440\u0444\u0438\u043D\u0433",
          en: "Surf"
        },
        description: {
          ru: "\u041D\u0430\u043A\u0440\u044B\u0432\u0430\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u0431\u043E\u043B\u044C\u0448\u043E\u0439 \u0432\u043E\u0434\u044F\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Sweeps over opponents with a large wave of water."
        },
        type: "water",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/57/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/134/"
        }
      },
      {
        id: 352,
        slug: "water-pulse",
        name: {
          ru: "\u0412\u043E\u0434\u043D\u044B\u0439 \u0438\u043C\u043F\u0443\u043B\u044C\u0441",
          en: "Water Pulse"
        },
        description: {
          ru: "\u0412\u043E\u0434\u044F\u043D\u0430\u044F \u0432\u043E\u043B\u043D\u0430 \u043C\u043E\u0436\u0435\u0442 \u043F\u0440\u0438\u0432\u0435\u0441\u0442\u0438 \u0446\u0435\u043B\u044C \u0432 \u0437\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u043E.",
          en: "A pulsing wave of water may confuse the target."
        },
        type: "water",
        power: 60,
        accuracy: 100,
        pp: 20,
        damageClass: "special",
        priority: 0,
        effectChance: 20,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/352/",
        meta: {
          ailment: {
            name: "confusion"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: 2,
          max_turns: 5,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 20,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/134/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 133,
          name: {
            ru: "\u0418\u0432\u0438",
            en: "Eevee"
          }
        },
        {
          id: 134,
          name: {
            ru: "\u0412\u0430\u043F\u043E\u0440\u0435\u043E\u043D",
            en: "Vaporeon"
          }
        },
        {
          id: 135,
          name: {
            ru: "\u0414\u0436\u043E\u043B\u0442\u0435\u043E\u043D",
            en: "Jolteon"
          }
        },
        {
          id: 136,
          name: {
            ru: "\u0424\u043B\u0430\u0440\u0435\u043E\u043D",
            en: "Flareon"
          }
        },
        {
          id: 196,
          name: {
            ru: "\u042D\u0441\u043F\u0435\u043E\u043D",
            en: "Espeon"
          }
        },
        {
          id: 197,
          name: {
            ru: "\u0410\u043C\u0431\u0440\u0435\u043E\u043D",
            en: "Umbreon"
          }
        },
        {
          id: 470,
          name: {
            ru: "\u041B\u0438\u0444\u0435\u043E\u043D",
            en: "Leafeon"
          }
        },
        {
          id: 471,
          name: {
            ru: "\u0413\u043B\u0430\u0441\u0435\u043E\u043D",
            en: "Glaceon"
          }
        },
        {
          id: 700,
          name: {
            ru: "\u0421\u0438\u043B\u044C\u0432\u0435\u043E\u043D",
            en: "Sylveon"
          }
        }
      ],
      edges: [
        {
          from: 133,
          to: 134,
          condition: {
            ru: "\u0412\u043E\u0434\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Water Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 135,
          condition: {
            ru: "\u0413\u0440\u043E\u043C\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Thunder Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 136,
          condition: {
            ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Fire Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 196,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0434\u043D\u0451\u043C",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during day"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 197,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u043D\u043E\u0447\u044C\u044E",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during night"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 470,
          condition: {
            ru: "\u041B\u0438\u0441\u0442\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Leaf Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 471,
          condition: {
            ru: "\u041B\u0435\u0434\u044F\u043D\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Ice Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 700,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0437\u043D\u0430\u0435\u0442 \u0432\u043E\u043B\u0448\u0435\u0431\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443",
            en: "Level up \xB7 friendship \u2265 160 \xB7 knows a Fairy move"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 135,
    slug: "jolteon",
    name: {
      ru: "\u0414\u0436\u043E\u043B\u0442\u0435\u043E\u043D",
      en: "Jolteon"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u043C\u043E\u043B\u043D\u0438\u044F",
      en: "Lightning Pok\xE9mon"
    },
    description: {
      ru: "\u041A\u043E\u0433\u0434\u0430 \u0441\u0435\u0440\u0434\u0438\u0442\u0441\u044F, \u0448\u0435\u0440\u0441\u0442\u044C \u0432\u0441\u0442\u0430\u0451\u0442 \u043E\u0441\u0442\u0440\u044B\u043C\u0438 \u0438\u0433\u043B\u0430\u043C\u0438, \u0430 \u0434\u044B\u0445\u0430\u043D\u0438\u0435 \u043F\u043E\u0442\u0440\u0435\u0441\u043A\u0438\u0432\u0430\u0435\u0442 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u0442\u0432\u043E\u043C.",
      en: "Anger turns its fur into sharp bristles and makes electricity crackle in its breath."
    },
    habitat: "urban",
    types: [
      "electric"
    ],
    height: 0.8,
    weight: 24.5,
    stats: [
      65,
      65,
      60,
      110,
      95,
      130
    ],
    abilities: [
      {
        id: 10,
        slug: "volt-absorb",
        name: {
          ru: "\u0412\u043E\u043B\u044C\u0442-\u043F\u043E\u0433\u043B\u043E\u0449\u0435\u043D\u0438\u0435",
          en: "Volt Absorb"
        },
        description: {
          ru: "\u042D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0435 \u0430\u0442\u0430\u043A\u0438 \u0432\u043E\u0441\u0441\u0442\u0430\u043D\u0430\u0432\u043B\u0438\u0432\u0430\u044E\u0442 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u0432\u043C\u0435\u0441\u0442\u043E \u043D\u0430\u043D\u0435\u0441\u0435\u043D\u0438\u044F \u0443\u0440\u043E\u043D\u0430.",
          en: "Electric attacks restore HP instead of dealing damage."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/10/",
        descriptionSource: "editorial-summary-of-core-ability"
      },
      {
        id: 95,
        slug: "quick-feet",
        name: {
          ru: "\u0411\u044B\u0441\u0442\u0440\u044B\u0435 \u043D\u043E\u0433\u0438",
          en: "Quick Feet"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u0440\u0438 \u043F\u0440\u043E\u0431\u043B\u0435\u043C\u0430\u0445 \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u044F.",
          en: "Boosts Speed while affected by a status condition."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/95/",
        descriptionSource: "editorial-summary-of-core-ability"
      }
    ],
    moves: [
      {
        id: 85,
        slug: "thunderbolt",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043C\u043E\u043B\u043D\u0438\u0438",
          en: "Thunderbolt"
        },
        description: {
          ru: "\u041C\u043E\u0449\u043D\u044B\u0439 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0439 \u0440\u0430\u0437\u0440\u044F\u0434 \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C \u0446\u0435\u043B\u044C.",
          en: "A strong electric bolt may paralyze the target."
        },
        type: "electric",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/85/",
        meta: {
          ailment: {
            name: "paralysis"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/135/"
        }
      },
      {
        id: 84,
        slug: "thunder-shock",
        name: {
          ru: "\u042D\u043B\u0435\u043A\u0442\u0440\u043E\u0448\u043E\u043A",
          en: "Thunder Shock"
        },
        description: {
          ru: "\u041D\u0435\u0431\u043E\u043B\u044C\u0448\u043E\u0439 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0439 \u0440\u0430\u0437\u0440\u044F\u0434 \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C.",
          en: "A small electric discharge may cause paralysis."
        },
        type: "electric",
        power: 40,
        accuracy: 100,
        pp: 30,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/84/",
        meta: {
          ailment: {
            name: "paralysis"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/135/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 133,
          name: {
            ru: "\u0418\u0432\u0438",
            en: "Eevee"
          }
        },
        {
          id: 134,
          name: {
            ru: "\u0412\u0430\u043F\u043E\u0440\u0435\u043E\u043D",
            en: "Vaporeon"
          }
        },
        {
          id: 135,
          name: {
            ru: "\u0414\u0436\u043E\u043B\u0442\u0435\u043E\u043D",
            en: "Jolteon"
          }
        },
        {
          id: 136,
          name: {
            ru: "\u0424\u043B\u0430\u0440\u0435\u043E\u043D",
            en: "Flareon"
          }
        },
        {
          id: 196,
          name: {
            ru: "\u042D\u0441\u043F\u0435\u043E\u043D",
            en: "Espeon"
          }
        },
        {
          id: 197,
          name: {
            ru: "\u0410\u043C\u0431\u0440\u0435\u043E\u043D",
            en: "Umbreon"
          }
        },
        {
          id: 470,
          name: {
            ru: "\u041B\u0438\u0444\u0435\u043E\u043D",
            en: "Leafeon"
          }
        },
        {
          id: 471,
          name: {
            ru: "\u0413\u043B\u0430\u0441\u0435\u043E\u043D",
            en: "Glaceon"
          }
        },
        {
          id: 700,
          name: {
            ru: "\u0421\u0438\u043B\u044C\u0432\u0435\u043E\u043D",
            en: "Sylveon"
          }
        }
      ],
      edges: [
        {
          from: 133,
          to: 134,
          condition: {
            ru: "\u0412\u043E\u0434\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Water Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 135,
          condition: {
            ru: "\u0413\u0440\u043E\u043C\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Thunder Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 136,
          condition: {
            ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Fire Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 196,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0434\u043D\u0451\u043C",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during day"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 197,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u043D\u043E\u0447\u044C\u044E",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during night"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 470,
          condition: {
            ru: "\u041B\u0438\u0441\u0442\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Leaf Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 471,
          condition: {
            ru: "\u041B\u0435\u0434\u044F\u043D\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Ice Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 700,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0437\u043D\u0430\u0435\u0442 \u0432\u043E\u043B\u0448\u0435\u0431\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443",
            en: "Level up \xB7 friendship \u2265 160 \xB7 knows a Fairy move"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 136,
    slug: "flareon",
    name: {
      ru: "\u0424\u043B\u0430\u0440\u0435\u043E\u043D",
      en: "Flareon"
    },
    genus: {
      ru: "\u041F\u043B\u0430\u043C\u0435\u043D\u043D\u044B\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Flame Pok\xE9mon"
    },
    description: {
      ru: "\u041F\u043B\u0430\u043C\u044F \u0433\u043E\u0440\u0438\u0442 \u0432 \u043E\u0441\u043E\u0431\u043E\u043C \u043E\u0440\u0433\u0430\u043D\u0435. \u041F\u0440\u0438 \u0432\u0434\u043E\u0445\u0435 \u043E\u043D\u043E \u0440\u0430\u0437\u0433\u043E\u0440\u0430\u0435\u0442\u0441\u044F \u0435\u0449\u0451 \u0441\u0438\u043B\u044C\u043D\u0435\u0435.",
      en: "Fire burns inside a specialized organ and intensifies when Flareon inhales."
    },
    habitat: "urban",
    types: [
      "fire"
    ],
    height: 0.9,
    weight: 25,
    stats: [
      65,
      130,
      60,
      95,
      110,
      65
    ],
    abilities: [
      {
        id: 18,
        slug: "flash-fire",
        name: {
          ru: "\u0412\u0441\u043F\u044B\u0448\u043A\u0430 \u043E\u0433\u043D\u044F",
          en: "Flash Fire"
        },
        description: {
          ru: "\u041F\u043E\u0433\u043B\u043E\u0449\u0430\u0435\u0442 \u043E\u0433\u043D\u0435\u043D\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438 \u0438 \u0443\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0439 \u043E\u0433\u043E\u043D\u044C.",
          en: "Absorbs Fire moves and boosts its own Fire attacks."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/18/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 62,
        slug: "guts",
        name: {
          ru: "\u0423\u043F\u043E\u0440\u0441\u0442\u0432\u043E",
          en: "Guts"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0441\u0438\u043B\u0443 \u0430\u0442\u0430\u043A\u0438 \u043F\u0440\u0438 \u043F\u0440\u043E\u0431\u043B\u0435\u043C\u0430\u0445 \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u044F.",
          en: "Boosts Attack while affected by a status condition."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/62/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 53,
        slug: "flamethrower",
        name: {
          ru: "\u041E\u0433\u043D\u0435\u043C\u0451\u0442",
          en: "Flamethrower"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u0441\u0438\u043B\u044C\u043D\u0443\u044E \u0441\u0442\u0440\u0443\u044E \u043F\u043B\u0430\u043C\u0435\u043D\u0438; \u043C\u043E\u0436\u0435\u0442 \u0432\u044B\u0437\u0432\u0430\u0442\u044C \u043E\u0436\u043E\u0433.",
          en: "Unleashes a powerful stream of fire that may cause a burn."
        },
        type: "fire",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/53/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/136/"
        }
      },
      {
        id: 52,
        slug: "ember",
        name: {
          ru: "\u0418\u0441\u043A\u0440\u044B",
          en: "Ember"
        },
        description: {
          ru: "\u041F\u043E\u0442\u043E\u043A \u043C\u0430\u043B\u0435\u043D\u044C\u043A\u0438\u0445 \u044F\u0437\u044B\u043A\u043E\u0432 \u043F\u043B\u0430\u043C\u0435\u043D\u0438 \u043C\u043E\u0436\u0435\u0442 \u0432\u044B\u0437\u0432\u0430\u0442\u044C \u043E\u0436\u043E\u0433.",
          en: "A burst of small flames may burn the target."
        },
        type: "fire",
        power: 40,
        accuracy: 100,
        pp: 25,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/52/",
        meta: {
          ailment: {
            name: "burn"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/136/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 133,
          name: {
            ru: "\u0418\u0432\u0438",
            en: "Eevee"
          }
        },
        {
          id: 134,
          name: {
            ru: "\u0412\u0430\u043F\u043E\u0440\u0435\u043E\u043D",
            en: "Vaporeon"
          }
        },
        {
          id: 135,
          name: {
            ru: "\u0414\u0436\u043E\u043B\u0442\u0435\u043E\u043D",
            en: "Jolteon"
          }
        },
        {
          id: 136,
          name: {
            ru: "\u0424\u043B\u0430\u0440\u0435\u043E\u043D",
            en: "Flareon"
          }
        },
        {
          id: 196,
          name: {
            ru: "\u042D\u0441\u043F\u0435\u043E\u043D",
            en: "Espeon"
          }
        },
        {
          id: 197,
          name: {
            ru: "\u0410\u043C\u0431\u0440\u0435\u043E\u043D",
            en: "Umbreon"
          }
        },
        {
          id: 470,
          name: {
            ru: "\u041B\u0438\u0444\u0435\u043E\u043D",
            en: "Leafeon"
          }
        },
        {
          id: 471,
          name: {
            ru: "\u0413\u043B\u0430\u0441\u0435\u043E\u043D",
            en: "Glaceon"
          }
        },
        {
          id: 700,
          name: {
            ru: "\u0421\u0438\u043B\u044C\u0432\u0435\u043E\u043D",
            en: "Sylveon"
          }
        }
      ],
      edges: [
        {
          from: 133,
          to: 134,
          condition: {
            ru: "\u0412\u043E\u0434\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Water Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 135,
          condition: {
            ru: "\u0413\u0440\u043E\u043C\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Thunder Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 136,
          condition: {
            ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Fire Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 196,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0434\u043D\u0451\u043C",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during day"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 197,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u043D\u043E\u0447\u044C\u044E",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during night"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 470,
          condition: {
            ru: "\u041B\u0438\u0441\u0442\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Leaf Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 471,
          condition: {
            ru: "\u041B\u0435\u0434\u044F\u043D\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Ice Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 700,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0437\u043D\u0430\u0435\u0442 \u0432\u043E\u043B\u0448\u0435\u0431\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443",
            en: "Level up \xB7 friendship \u2265 160 \xB7 knows a Fairy move"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 143,
    slug: "snorlax",
    name: {
      ru: "\u0421\u043D\u043E\u0440\u043B\u0430\u043A\u0441",
      en: "Snorlax"
    },
    genus: {
      ru: "\u0421\u043F\u044F\u0449\u0438\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Sleeping Pok\xE9mon"
    },
    description: {
      ru: "\u041E\u0431\u043E\u0436\u0430\u0435\u0442 \u0435\u0434\u0443 \u0438 \u043E\u0442\u0434\u044B\u0445. \u041E\u0433\u0440\u043E\u043C\u043D\u044B\u0439 \u0430\u043F\u043F\u0435\u0442\u0438\u0442 \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0435\u043C\u0443 \u043E\u043F\u0443\u0441\u0442\u043E\u0448\u0438\u0442\u044C \u0446\u0435\u043B\u044B\u0435 \u0437\u0430\u043F\u0430\u0441\u044B \u043F\u0438\u0449\u0438.",
      en: "Snorlax loves food and rest. Its tremendous appetite can empty an entire food store."
    },
    habitat: "mountain",
    types: [
      "normal"
    ],
    height: 2.1,
    weight: 460,
    stats: [
      160,
      110,
      65,
      65,
      110,
      30
    ],
    abilities: [
      {
        id: 17,
        slug: "immunity",
        name: {
          ru: "\u0418\u043C\u043C\u0443\u043D\u0438\u0442\u0435\u0442",
          en: "Immunity"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u043E\u0442\u0440\u0430\u0432\u043B\u0435\u043D\u0438\u044F.",
          en: "Prevents poisoning."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/17/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 47,
        slug: "thick-fat",
        name: {
          ru: "\u041F\u043B\u043E\u0442\u043D\u044B\u0439 \u0436\u0438\u0440",
          en: "Thick Fat"
        },
        description: {
          ru: "\u0423\u043C\u0435\u043D\u044C\u0448\u0430\u0435\u0442 \u0443\u0440\u043E\u043D \u043E\u0433\u043D\u0435\u043D\u043D\u044B\u0445 \u0438 \u043B\u0435\u0434\u044F\u043D\u044B\u0445 \u0430\u0442\u0430\u043A.",
          en: "Reduces damage from Fire and Ice moves."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/47/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 82,
        slug: "gluttony",
        name: {
          ru: "\u041E\u0431\u0436\u043E\u0440\u0441\u0442\u0432\u043E",
          en: "Gluttony"
        },
        description: {
          ru: "\u041F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0440\u0430\u043D\u044C\u0448\u0435 \u0441\u044A\u0435\u0441\u0442\u044C \u0443\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u043C\u0443\u044E \u043B\u0435\u0447\u0435\u0431\u043D\u0443\u044E \u044F\u0433\u043E\u0434\u0443.",
          en: "Makes the Pok\xE9mon eat its held HP-triggered berry earlier."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/82/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 34,
        slug: "body-slam",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u0442\u0435\u043B\u043E\u043C",
          en: "Body Slam"
        },
        description: {
          ru: "\u041E\u0431\u0440\u0443\u0448\u0438\u0432\u0430\u0435\u0442\u0441\u044F \u043D\u0430 \u0446\u0435\u043B\u044C \u0432\u0441\u0435\u043C \u0442\u0435\u043B\u043E\u043C; \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C.",
          en: "Slams into the target and may cause paralysis."
        },
        type: "normal",
        power: 85,
        accuracy: 100,
        pp: 15,
        damageClass: "physical",
        priority: 0,
        effectChance: 30,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/34/",
        meta: {
          ailment: {
            name: "paralysis"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 30,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/143/"
        }
      },
      {
        id: 242,
        slug: "crunch",
        name: {
          ru: "\u0425\u0440\u0443\u0441\u0442",
          en: "Crunch"
        },
        description: {
          ru: "\u0421\u0438\u043B\u044C\u043D\u044B\u0439 \u0443\u043A\u0443\u0441, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0437\u0430\u0449\u0438\u0442\u0443 \u0446\u0435\u043B\u0438.",
          en: "A strong bite that may lower Defense."
        },
        type: "dark",
        power: 80,
        accuracy: 100,
        pp: 15,
        damageClass: "physical",
        priority: 0,
        effectChance: 20,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/242/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 20
        },
        statChanges: [
          {
            stat: "defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/143/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 446,
          name: {
            ru: "\u041C\u0430\u043D\u0447\u043B\u0430\u043A\u0441",
            en: "Munchlax"
          }
        },
        {
          id: 143,
          name: {
            ru: "\u0421\u043D\u043E\u0440\u043B\u0430\u043A\u0441",
            en: "Snorlax"
          }
        }
      ],
      edges: [
        {
          from: 446,
          to: 143,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160",
            en: "Level up \xB7 friendship \u2265 160"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 144,
    slug: "articuno",
    name: {
      ru: "\u0410\u0440\u0442\u0438\u043A\u0443\u043D\u043E",
      en: "Articuno"
    },
    genus: {
      ru: "\u041B\u0435\u0434\u044F\u043D\u043E\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Freeze Pok\xE9mon"
    },
    description: {
      ru: "\u041B\u0435\u0433\u0435\u043D\u0434\u0430\u0440\u043D\u0430\u044F \u043F\u0442\u0438\u0446\u0430, \u0443\u043F\u0440\u0430\u0432\u043B\u044F\u044E\u0449\u0430\u044F \u043B\u044C\u0434\u043E\u043C. \u041F\u0440\u0435\u0434\u0430\u043D\u0438\u044F \u0441\u0432\u044F\u0437\u044B\u0432\u0430\u044E\u0442 \u0435\u0451 \u0441 \u0437\u0430\u0441\u043D\u0435\u0436\u0435\u043D\u043D\u044B\u043C\u0438 \u0433\u043E\u0440\u0430\u043C\u0438 \u0438 \u0432\u0435\u0447\u043D\u043E\u0439 \u043C\u0435\u0440\u0437\u043B\u043E\u0442\u043E\u0439.",
      en: "A legendary bird that commands ice, said to live among snowy mountains and permafrost."
    },
    habitat: "unknown",
    types: [
      "ice",
      "flying"
    ],
    height: 1.7,
    weight: 55.4,
    stats: [
      90,
      85,
      100,
      95,
      125,
      85
    ],
    abilities: [
      {
        id: 46,
        slug: "pressure",
        name: {
          ru: "\u0414\u0430\u0432\u043B\u0435\u043D\u0438\u0435",
          en: "Pressure"
        },
        description: {
          ru: "\u041F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A \u0442\u0440\u0430\u0442\u0438\u0442 \u0431\u043E\u043B\u044C\u0448\u0435 \u043E\u0447\u043A\u043E\u0432 PP \u043D\u0430 \u0430\u0442\u0430\u043A\u0438 \u043F\u043E \u044D\u0442\u043E\u043C\u0443 \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u0443.",
          en: "Opponents spend extra PP on moves targeting this Pok\xE9mon."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/46/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 81,
        slug: "snow-cloak",
        name: {
          ru: "\u0421\u043D\u0435\u0436\u043D\u0430\u044F \u0437\u0430\u0432\u0435\u0441\u0430",
          en: "Snow Cloak"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0443\u043A\u043B\u043E\u043D\u0435\u043D\u0438\u0435 \u043F\u0440\u0438 \u0433\u0440\u0430\u0434\u0435.",
          en: "Improves evasion in hail."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/81/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 58,
        slug: "ice-beam",
        name: {
          ru: "\u041B\u0435\u0434\u044F\u043D\u043E\u0439 \u043B\u0443\u0447",
          en: "Ice Beam"
        },
        description: {
          ru: "\u0425\u043E\u043B\u043E\u0434\u043D\u044B\u0439 \u043B\u0443\u0447 \u043C\u043E\u0436\u0435\u0442 \u0437\u0430\u043C\u043E\u0440\u043E\u0437\u0438\u0442\u044C \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "An icy beam may freeze the target."
        },
        type: "ice",
        power: 90,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/58/",
        meta: {
          ailment: {
            name: "freeze"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/144/"
        }
      },
      {
        id: 542,
        slug: "hurricane",
        name: {
          ru: "\u0423\u0440\u0430\u0433\u0430\u043D",
          en: "Hurricane"
        },
        description: {
          ru: "\u041C\u043E\u0449\u043D\u044B\u0439 \u0432\u0438\u0445\u0440\u044C \u043C\u043E\u0436\u0435\u0442 \u043F\u0440\u0438\u0432\u0435\u0441\u0442\u0438 \u0446\u0435\u043B\u044C \u0432 \u0437\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u043E.",
          en: "A fierce whirlwind may leave the target confused."
        },
        type: "flying",
        power: 110,
        accuracy: 70,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 30,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/542/",
        meta: {
          ailment: {
            name: "confusion"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: 2,
          max_turns: 5,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 30,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/144/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 144,
          name: {
            ru: "\u0410\u0440\u0442\u0438\u043A\u0443\u043D\u043E",
            en: "Articuno"
          }
        }
      ],
      edges: []
    },
    isLegendary: true,
    isMythical: false,
    classification: "legendary"
  },
  {
    id: 147,
    slug: "dratini",
    name: {
      ru: "\u0414\u0440\u0430\u0442\u0438\u043D\u0438",
      en: "Dratini"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0434\u0440\u0430\u043A\u043E\u043D",
      en: "Dragon Pok\xE9mon"
    },
    description: {
      ru: "\u0414\u043E\u043B\u0433\u043E\u0435 \u0432\u0440\u0435\u043C\u044F \u0441\u0447\u0438\u0442\u0430\u043B\u0441\u044F \u043C\u0438\u0444\u043E\u043C. \u041C\u0430\u043B\u0435\u043D\u044C\u043A\u0438\u0439 \u0432\u044B\u0441\u0442\u0443\u043F \u043D\u0430 \u0435\u0433\u043E \u043B\u0431\u0443 \u2014 \u044D\u0442\u043E \u0440\u043E\u0433, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u0435\u0449\u0451 \u0442\u043E\u043B\u044C\u043A\u043E \u0440\u0430\u0441\u0442\u0451\u0442.",
      en: "Once thought to be a myth, Dratini has a small forehead horn that is still developing."
    },
    habitat: "water",
    types: [
      "dragon"
    ],
    height: 1.8,
    weight: 3.3,
    stats: [
      41,
      64,
      45,
      50,
      50,
      50
    ],
    abilities: [
      {
        id: 61,
        slug: "shed-skin",
        name: {
          ru: "\u041B\u0438\u043D\u044C\u043A\u0430",
          en: "Shed Skin"
        },
        description: {
          ru: "\u0412 \u043A\u043E\u043D\u0446\u0435 \u0445\u043E\u0434\u0430 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u044F\u0442\u044C \u043F\u0440\u043E\u0431\u043B\u0435\u043C\u0443 \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u044F.",
          en: "May cure a status condition at the end of a turn."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/61/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 63,
        slug: "marvel-scale",
        name: {
          ru: "\u0427\u0443\u0434\u043E-\u0447\u0435\u0448\u0443\u044F",
          en: "Marvel Scale"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0437\u0430\u0449\u0438\u0442\u0443 \u043F\u0440\u0438 \u043F\u0440\u043E\u0431\u043B\u0435\u043C\u0430\u0445 \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u044F.",
          en: "Raises Defense while affected by a status condition."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/63/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 82,
        slug: "dragon-rage",
        name: {
          ru: "\u042F\u0440\u043E\u0441\u0442\u044C \u0434\u0440\u0430\u043A\u043E\u043D\u0430",
          en: "Dragon Rage"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u044F\u0440\u043E\u0441\u0442\u043D\u0443\u044E \u0432\u043E\u043B\u043D\u0443, \u043D\u0430\u043D\u043E\u0441\u044F\u0449\u0443\u044E 40 \u0435\u0434\u0438\u043D\u0438\u0446 \u0443\u0440\u043E\u043D\u0430.",
          en: "Releases a fierce wave that deals 40 points of damage."
        },
        type: "dragon",
        power: null,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/82/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/147/"
        }
      },
      {
        id: 525,
        slug: "dragon-tail",
        name: {
          ru: "\u0425\u0432\u043E\u0441\u0442 \u0434\u0440\u0430\u043A\u043E\u043D\u0430",
          en: "Dragon Tail"
        },
        description: {
          ru: "\u0423\u0434\u0430\u0440 \u0445\u0432\u043E\u0441\u0442\u043E\u043C \u0437\u0430\u0441\u0442\u0430\u0432\u043B\u044F\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u0441\u043C\u0435\u043D\u0438\u0442\u044C\u0441\u044F.",
          en: "A tail strike that forces the opponent to switch out."
        },
        type: "dragon",
        power: 60,
        accuracy: 90,
        pp: 10,
        damageClass: "physical",
        priority: -6,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/525/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/147/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 147,
          name: {
            ru: "\u0414\u0440\u0430\u0442\u0438\u043D\u0438",
            en: "Dratini"
          }
        },
        {
          id: 148,
          name: {
            ru: "\u0414\u0440\u0430\u0433\u043E\u043D\u044D\u0439\u0440",
            en: "Dragonair"
          }
        },
        {
          id: 149,
          name: {
            ru: "\u0414\u0440\u0430\u0433\u043E\u043D\u0430\u0439\u0442",
            en: "Dragonite"
          }
        }
      ],
      edges: [
        {
          from: 147,
          to: 148,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 30",
            en: "Level 30"
          },
          isDefault: true
        },
        {
          from: 148,
          to: 149,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 55",
            en: "Level 55"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 148,
    slug: "dragonair",
    name: {
      ru: "\u0414\u0440\u0430\u0433\u043E\u043D\u044D\u0439\u0440",
      en: "Dragonair"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0434\u0440\u0430\u043A\u043E\u043D",
      en: "Dragon Pok\xE9mon"
    },
    description: {
      ru: "\u0425\u0440\u0430\u043D\u0438\u0442 \u044D\u043D\u0435\u0440\u0433\u0438\u044E \u0432 \u0448\u0430\u0440\u0438\u043A\u0430\u0445 \u043D\u0430 \u0445\u0432\u043E\u0441\u0442\u0435 \u0438 \u0441 \u0435\u0451 \u043F\u043E\u043C\u043E\u0449\u044C\u044E \u0432\u043B\u0438\u044F\u0435\u0442 \u043D\u0430 \u043F\u043E\u0433\u043E\u0434\u0443.",
      en: "Energy stored in its tail orbs lets Dragonair influence the weather."
    },
    habitat: "water",
    types: [
      "dragon"
    ],
    height: 4,
    weight: 16.5,
    stats: [
      61,
      84,
      65,
      70,
      70,
      70
    ],
    abilities: [
      {
        id: 61,
        slug: "shed-skin",
        name: {
          ru: "\u041B\u0438\u043D\u044C\u043A\u0430",
          en: "Shed Skin"
        },
        description: {
          ru: "\u0412 \u043A\u043E\u043D\u0446\u0435 \u0445\u043E\u0434\u0430 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u044F\u0442\u044C \u043F\u0440\u043E\u0431\u043B\u0435\u043C\u0443 \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u044F.",
          en: "May cure a status condition at the end of a turn."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/61/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 63,
        slug: "marvel-scale",
        name: {
          ru: "\u0427\u0443\u0434\u043E-\u0447\u0435\u0448\u0443\u044F",
          en: "Marvel Scale"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0437\u0430\u0449\u0438\u0442\u0443 \u043F\u0440\u0438 \u043F\u0440\u043E\u0431\u043B\u0435\u043C\u0430\u0445 \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u044F.",
          en: "Raises Defense while affected by a status condition."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/63/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 525,
        slug: "dragon-tail",
        name: {
          ru: "\u0425\u0432\u043E\u0441\u0442 \u0434\u0440\u0430\u043A\u043E\u043D\u0430",
          en: "Dragon Tail"
        },
        description: {
          ru: "\u0423\u0434\u0430\u0440 \u0445\u0432\u043E\u0441\u0442\u043E\u043C \u0437\u0430\u0441\u0442\u0430\u0432\u043B\u044F\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u0441\u043C\u0435\u043D\u0438\u0442\u044C\u0441\u044F.",
          en: "A tail strike that forces the opponent to switch out."
        },
        type: "dragon",
        power: 60,
        accuracy: 90,
        pp: 10,
        damageClass: "physical",
        priority: -6,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/525/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/148/"
        }
      },
      {
        id: 82,
        slug: "dragon-rage",
        name: {
          ru: "\u042F\u0440\u043E\u0441\u0442\u044C \u0434\u0440\u0430\u043A\u043E\u043D\u0430",
          en: "Dragon Rage"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u044F\u0440\u043E\u0441\u0442\u043D\u0443\u044E \u0432\u043E\u043B\u043D\u0443, \u043D\u0430\u043D\u043E\u0441\u044F\u0449\u0443\u044E 40 \u0435\u0434\u0438\u043D\u0438\u0446 \u0443\u0440\u043E\u043D\u0430.",
          en: "Releases a fierce wave that deals 40 points of damage."
        },
        type: "dragon",
        power: null,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/82/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/148/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 147,
          name: {
            ru: "\u0414\u0440\u0430\u0442\u0438\u043D\u0438",
            en: "Dratini"
          }
        },
        {
          id: 148,
          name: {
            ru: "\u0414\u0440\u0430\u0433\u043E\u043D\u044D\u0439\u0440",
            en: "Dragonair"
          }
        },
        {
          id: 149,
          name: {
            ru: "\u0414\u0440\u0430\u0433\u043E\u043D\u0430\u0439\u0442",
            en: "Dragonite"
          }
        }
      ],
      edges: [
        {
          from: 147,
          to: 148,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 30",
            en: "Level 30"
          },
          isDefault: true
        },
        {
          from: 148,
          to: 149,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 55",
            en: "Level 55"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 149,
    slug: "dragonite",
    name: {
      ru: "\u0414\u0440\u0430\u0433\u043E\u043D\u0430\u0439\u0442",
      en: "Dragonite"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0434\u0440\u0430\u043A\u043E\u043D",
      en: "Dragon Pok\xE9mon"
    },
    description: {
      ru: "\u041C\u043E\u0440\u0441\u043A\u043E\u0433\u043E \u0434\u0440\u0430\u043A\u043E\u043D\u0430 \u0441\u0447\u0438\u0442\u0430\u044E\u0442 \u043E\u043B\u0438\u0446\u0435\u0442\u0432\u043E\u0440\u0435\u043D\u0438\u0435\u043C \u043C\u043E\u0440\u044F. \u0415\u0433\u043E \u043E\u0431\u0440\u0430\u0437 \u0447\u0430\u0441\u0442\u043E \u0443\u043A\u0440\u0430\u0448\u0430\u0435\u0442 \u043D\u043E\u0441\u044B \u043A\u043E\u0440\u0430\u0431\u043B\u0435\u0439.",
      en: "This sea dragon is celebrated as an embodiment of the ocean, and its likeness adorns ships."
    },
    habitat: "water",
    types: [
      "dragon",
      "flying"
    ],
    height: 2.2,
    weight: 210,
    stats: [
      91,
      134,
      95,
      100,
      100,
      80
    ],
    abilities: [
      {
        id: 39,
        slug: "inner-focus",
        name: {
          ru: "\u0421\u043E\u0441\u0440\u0435\u0434\u043E\u0442\u043E\u0447\u0435\u043D\u043D\u043E\u0441\u0442\u044C",
          en: "Inner Focus"
        },
        description: {
          ru: "\u041D\u0435 \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0438\u0441\u043F\u0443\u0433\u0430\u0442\u044C\u0441\u044F \u0438 \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Prevents flinching."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/39/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 136,
        slug: "multiscale",
        name: {
          ru: "\u041C\u0443\u043B\u044C\u0442\u0438\u0447\u0435\u0448\u0443\u044F",
          en: "Multiscale"
        },
        description: {
          ru: "\u0423\u043C\u0435\u043D\u044C\u0448\u0430\u0435\u0442 \u043F\u043E\u043B\u0443\u0447\u0430\u0435\u043C\u044B\u0439 \u0443\u0440\u043E\u043D \u043F\u0440\u0438 \u043F\u043E\u043B\u043D\u043E\u043C \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435.",
          en: "Reduces incoming damage while at full HP."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/136/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 337,
        slug: "dragon-claw",
        name: {
          ru: "\u041A\u043E\u0433\u043E\u0442\u044C \u0434\u0440\u0430\u043A\u043E\u043D\u0430",
          en: "Dragon Claw"
        },
        description: {
          ru: "\u041D\u0430\u043D\u043E\u0441\u0438\u0442 \u0443\u0434\u0430\u0440 \u043E\u0441\u0442\u0440\u044B\u043C\u0438 \u0434\u0440\u0430\u043A\u043E\u043D\u044C\u0438\u043C\u0438 \u043A\u043E\u0433\u0442\u044F\u043C\u0438.",
          en: "Slashes the target with sharp dragon claws."
        },
        type: "dragon",
        power: 80,
        accuracy: 100,
        pp: 15,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/337/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/149/"
        }
      },
      {
        id: 200,
        slug: "outrage",
        name: {
          ru: "\u041D\u0435\u0438\u0441\u0442\u043E\u0432\u0441\u0442\u0432\u043E",
          en: "Outrage"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0443\u0435\u0442 \u043D\u0435\u0441\u043A\u043E\u043B\u044C\u043A\u043E \u0445\u043E\u0434\u043E\u0432 \u043F\u043E\u0434\u0440\u044F\u0434, \u0437\u0430\u0442\u0435\u043C \u043F\u0440\u0438\u0445\u043E\u0434\u0438\u0442 \u0432 \u0437\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u043E.",
          en: "Attacks repeatedly for several turns, then becomes confused."
        },
        type: "dragon",
        power: 120,
        accuracy: 100,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "random-opponent",
        sourceUrl: "https://pokeapi.co/api/v2/move/200/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/149/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 147,
          name: {
            ru: "\u0414\u0440\u0430\u0442\u0438\u043D\u0438",
            en: "Dratini"
          }
        },
        {
          id: 148,
          name: {
            ru: "\u0414\u0440\u0430\u0433\u043E\u043D\u044D\u0439\u0440",
            en: "Dragonair"
          }
        },
        {
          id: 149,
          name: {
            ru: "\u0414\u0440\u0430\u0433\u043E\u043D\u0430\u0439\u0442",
            en: "Dragonite"
          }
        }
      ],
      edges: [
        {
          from: 147,
          to: 148,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 30",
            en: "Level 30"
          },
          isDefault: true
        },
        {
          from: 148,
          to: 149,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 55",
            en: "Level 55"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 150,
    slug: "mewtwo",
    name: {
      ru: "\u041C\u044C\u044E\u0442\u0443",
      en: "Mewtwo"
    },
    genus: {
      ru: "\u0413\u0435\u043D\u0435\u0442\u0438\u0447\u0435\u0441\u043A\u0438\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Genetic Pok\xE9mon"
    },
    description: {
      ru: "\u0415\u0433\u043E \u0414\u041D\u041A \u0431\u043B\u0438\u0437\u043A\u0430 \u043A \u0414\u041D\u041A \u041C\u044C\u044E, \u043D\u043E \u0445\u0430\u0440\u0430\u043A\u0442\u0435\u0440 \u0438 \u0440\u0430\u0437\u043C\u0435\u0440\u044B \u0437\u0430\u043C\u0435\u0442\u043D\u043E \u043E\u0442\u043B\u0438\u0447\u0430\u044E\u0442\u0441\u044F. \u041E\u0431\u043B\u0430\u0434\u0430\u0435\u0442 \u043C\u043E\u0449\u043D\u044B\u043C\u0438 \u043F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0438\u043C\u0438 \u0441\u043F\u043E\u0441\u043E\u0431\u043D\u043E\u0441\u0442\u044F\u043C\u0438.",
      en: "Its DNA resembles Mew\u2019s, yet its size and temperament differ greatly. It wields powerful psychic abilities."
    },
    habitat: "unknown",
    types: [
      "psychic"
    ],
    height: 2,
    weight: 122,
    stats: [
      106,
      110,
      90,
      154,
      90,
      130
    ],
    abilities: [
      {
        id: 46,
        slug: "pressure",
        name: {
          ru: "\u0414\u0430\u0432\u043B\u0435\u043D\u0438\u0435",
          en: "Pressure"
        },
        description: {
          ru: "\u041F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A \u0442\u0440\u0430\u0442\u0438\u0442 \u0431\u043E\u043B\u044C\u0448\u0435 \u043E\u0447\u043A\u043E\u0432 PP \u043D\u0430 \u0430\u0442\u0430\u043A\u0438 \u043F\u043E \u044D\u0442\u043E\u043C\u0443 \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u0443.",
          en: "Opponents spend extra PP on moves targeting this Pok\xE9mon."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/46/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 127,
        slug: "unnerve",
        name: {
          ru: "\u041D\u0435\u0440\u0432\u043E\u0437\u043D\u043E\u0441\u0442\u044C",
          en: "Unnerve"
        },
        description: {
          ru: "\u041D\u0435 \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430\u043C \u0435\u0441\u0442\u044C \u0443\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u043C\u044B\u0435 \u044F\u0433\u043E\u0434\u044B.",
          en: "Stops opponents from eating held berries."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/127/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 94,
        slug: "psychic",
        name: {
          ru: "\u041F\u0441\u0438\u0445\u043E\u043A\u0438\u043D\u0435\u0437",
          en: "Psychic"
        },
        description: {
          ru: "\u041F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0441\u0438\u043B\u0430 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443 \u0446\u0435\u043B\u0438.",
          en: "Psychic force may lower the target\u2019s Special Defense."
        },
        type: "psychic",
        power: 90,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/94/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 10
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/150/"
        }
      },
      {
        id: 540,
        slug: "psystrike",
        name: {
          ru: "\u041F\u0441\u0438\u0445\u043E\u0443\u0434\u0430\u0440",
          en: "Psystrike"
        },
        description: {
          ru: "\u041F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0430\u0442\u0430\u043A\u0430 \u0440\u0430\u0441\u0441\u0447\u0438\u0442\u044B\u0432\u0430\u0435\u0442 \u0443\u0440\u043E\u043D \u043F\u043E \u0444\u0438\u0437\u0438\u0447\u0435\u0441\u043A\u043E\u0439 \u0437\u0430\u0449\u0438\u0442\u0435 \u0446\u0435\u043B\u0438.",
          en: "A psychic attack that uses the target\u2019s physical Defense."
        },
        type: "psychic",
        power: 100,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/540/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/150/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 150,
          name: {
            ru: "\u041C\u044C\u044E\u0442\u0443",
            en: "Mewtwo"
          }
        }
      ],
      edges: []
    },
    isLegendary: true,
    isMythical: false,
    classification: "legendary"
  },
  {
    id: 169,
    slug: "crobat",
    name: {
      ru: "\u041A\u0440\u043E\u0431\u0430\u0442",
      en: "Crobat"
    },
    genus: {
      ru: "\u041B\u0435\u0442\u0443\u0447\u0430\u044F \u043C\u044B\u0448\u044C",
      en: "Bat Pok\xE9mon"
    },
    description: {
      ru: "\u0417\u0430\u0434\u043D\u0438\u0435 \u043B\u0430\u043F\u044B \u043F\u0440\u0435\u0432\u0440\u0430\u0442\u0438\u043B\u0438\u0441\u044C \u0432\u043E \u0432\u0442\u043E\u0440\u0443\u044E \u043F\u0430\u0440\u0443 \u043A\u0440\u044B\u043B\u044C\u0435\u0432. \u041B\u043E\u0432\u043A\u043E \u043B\u0435\u0442\u0430\u0435\u0442 \u0434\u0430\u0436\u0435 \u0432 \u0442\u0435\u0441\u043D\u044B\u0445 \u043F\u0435\u0449\u0435\u0440\u0430\u0445.",
      en: "Four wings let Crobat maneuver rapidly through even narrow caves."
    },
    habitat: "cave",
    types: [
      "poison",
      "flying"
    ],
    height: 1.8,
    weight: 75,
    stats: [
      85,
      90,
      80,
      70,
      80,
      130
    ],
    abilities: [
      {
        id: 39,
        slug: "inner-focus",
        name: {
          ru: "\u0421\u043E\u0441\u0440\u0435\u0434\u043E\u0442\u043E\u0447\u0435\u043D\u043D\u043E\u0441\u0442\u044C",
          en: "Inner Focus"
        },
        description: {
          ru: "\u041D\u0435 \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0438\u0441\u043F\u0443\u0433\u0430\u0442\u044C\u0441\u044F \u0438 \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Prevents flinching."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/39/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 151,
        slug: "infiltrator",
        name: {
          ru: "\u041F\u0440\u043E\u043D\u0438\u043A\u043D\u043E\u0432\u0435\u043D\u0438\u0435",
          en: "Infiltrator"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0438 \u043F\u0440\u043E\u0445\u043E\u0434\u044F\u0442 \u0441\u043A\u0432\u043E\u0437\u044C \u0437\u0430\u0449\u0438\u0442\u043D\u044B\u0435 \u044D\u043A\u0440\u0430\u043D\u044B \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Moves bypass the opponent\u2019s protective screens."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/151/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 17,
        slug: "wing-attack",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043A\u0440\u044B\u043B\u043E\u043C",
          en: "Wing Attack"
        },
        description: {
          ru: "\u041D\u0430\u043D\u043E\u0441\u0438\u0442 \u0443\u0434\u0430\u0440 \u0448\u0438\u0440\u043E\u043A\u043E \u0440\u0430\u0441\u043A\u0440\u044B\u0442\u044B\u043C\u0438 \u043A\u0440\u044B\u043B\u044C\u044F\u043C\u0438.",
          en: "Strikes the target with outstretched wings."
        },
        type: "flying",
        power: 60,
        accuracy: 100,
        pp: 35,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/17/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/169/"
        }
      },
      {
        id: 16,
        slug: "gust",
        name: {
          ru: "\u041F\u043E\u0440\u044B\u0432 \u0432\u0435\u0442\u0440\u0430",
          en: "Gust"
        },
        description: {
          ru: "\u0411\u044C\u0451\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u0441\u0438\u043B\u044C\u043D\u044B\u043C \u0432\u043E\u0437\u0434\u0443\u0448\u043D\u044B\u043C \u043F\u043E\u0442\u043E\u043A\u043E\u043C.",
          en: "Buffets the target with a strong gust of wind."
        },
        type: "flying",
        power: 40,
        accuracy: 100,
        pp: 35,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/16/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/169/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 41,
          name: {
            ru: "\u0417\u0443\u0431\u0430\u0442",
            en: "Zubat"
          }
        },
        {
          id: 42,
          name: {
            ru: "\u0413\u043E\u043B\u0431\u0430\u0442",
            en: "Golbat"
          }
        },
        {
          id: 169,
          name: {
            ru: "\u041A\u0440\u043E\u0431\u0430\u0442",
            en: "Crobat"
          }
        }
      ],
      edges: [
        {
          from: 41,
          to: 42,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 22",
            en: "Level 22"
          },
          isDefault: true
        },
        {
          from: 42,
          to: 169,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160",
            en: "Level up \xB7 friendship \u2265 160"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 172,
    slug: "pichu",
    name: {
      ru: "\u041F\u0438\u0447\u0443",
      en: "Pichu"
    },
    genus: {
      ru: "\u041C\u0430\u043B\u0435\u043D\u044C\u043A\u0430\u044F \u043C\u044B\u0448\u044C",
      en: "Tiny Mouse Pok\xE9mon"
    },
    description: {
      ru: "\u041D\u0430\u043A\u0430\u043F\u043B\u0438\u0432\u0430\u0435\u0442 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u0442\u0432\u043E \u0432 \u0449\u0435\u043A\u0430\u0445, \u043D\u043E \u043E\u0442 \u0432\u043E\u043B\u043D\u0435\u043D\u0438\u044F \u0447\u0430\u0441\u0442\u043E \u0432\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u0440\u0430\u0437\u0440\u044F\u0434 \u0441\u043B\u0443\u0447\u0430\u0439\u043D\u043E.",
      en: "It stores electricity in its cheeks but often releases it accidentally when excited."
    },
    habitat: "forest",
    types: [
      "electric"
    ],
    height: 0.3,
    weight: 2,
    stats: [
      20,
      40,
      15,
      35,
      35,
      60
    ],
    abilities: [
      {
        id: 9,
        slug: "static",
        name: {
          ru: "\u0421\u0442\u0430\u0442\u0438\u043A\u0430",
          en: "Static"
        },
        description: {
          ru: "\u041A\u043E\u043D\u0442\u0430\u043A\u0442\u043D\u0430\u044F \u0430\u0442\u0430\u043A\u0430 \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C \u0430\u0442\u0430\u043A\u0443\u044E\u0449\u0435\u0433\u043E.",
          en: "Contact attacks may paralyze the attacker."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/9/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 31,
        slug: "lightning-rod",
        name: {
          ru: "\u0413\u0440\u043E\u043C\u043E\u043E\u0442\u0432\u043E\u0434",
          en: "Lightning Rod"
        },
        description: {
          ru: "\u041F\u0440\u0438\u0442\u044F\u0433\u0438\u0432\u0430\u0435\u0442 \u0438 \u043F\u043E\u0433\u043B\u043E\u0449\u0430\u0435\u0442 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0435 \u0430\u0442\u0430\u043A\u0438, \u043F\u043E\u0432\u044B\u0448\u0430\u044F \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443.",
          en: "Draws in and absorbs Electric moves to raise Special Attack."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/31/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 85,
        slug: "thunderbolt",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043C\u043E\u043B\u043D\u0438\u0438",
          en: "Thunderbolt"
        },
        description: {
          ru: "\u041C\u043E\u0449\u043D\u044B\u0439 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0439 \u0440\u0430\u0437\u0440\u044F\u0434 \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C \u0446\u0435\u043B\u044C.",
          en: "A strong electric bolt may paralyze the target."
        },
        type: "electric",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/85/",
        meta: {
          ailment: {
            name: "paralysis"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/172/"
        }
      },
      {
        id: 84,
        slug: "thunder-shock",
        name: {
          ru: "\u042D\u043B\u0435\u043A\u0442\u0440\u043E\u0448\u043E\u043A",
          en: "Thunder Shock"
        },
        description: {
          ru: "\u041D\u0435\u0431\u043E\u043B\u044C\u0448\u043E\u0439 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0439 \u0440\u0430\u0437\u0440\u044F\u0434 \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C.",
          en: "A small electric discharge may cause paralysis."
        },
        type: "electric",
        power: 40,
        accuracy: 100,
        pp: 30,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/84/",
        meta: {
          ailment: {
            name: "paralysis"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/172/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 172,
          name: {
            ru: "\u041F\u0438\u0447\u0443",
            en: "Pichu"
          }
        },
        {
          id: 25,
          name: {
            ru: "\u041F\u0438\u043A\u0430\u0447\u0443",
            en: "Pikachu"
          }
        },
        {
          id: 26,
          name: {
            ru: "\u0420\u0430\u0439\u0447\u0443",
            en: "Raichu"
          }
        }
      ],
      edges: [
        {
          from: 172,
          to: 25,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 220",
            en: "Level up \xB7 friendship \u2265 220"
          },
          isDefault: true
        },
        {
          from: 25,
          to: 26,
          condition: {
            ru: "\u0413\u0440\u043E\u043C\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Thunder Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 173,
    slug: "cleffa",
    name: {
      ru: "\u041A\u043B\u0435\u0444\u0444\u0430",
      en: "Cleffa"
    },
    genus: {
      ru: "\u0417\u0432\u0435\u0437\u0434\u043E\u043E\u0431\u0440\u0430\u0437\u043D\u044B\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Star Shape Pok\xE9mon"
    },
    description: {
      ru: "\u0415\u0433\u043E \u0441\u0438\u043B\u0443\u044D\u0442 \u043D\u0430\u043F\u043E\u043C\u0438\u043D\u0430\u0435\u0442 \u0437\u0432\u0435\u0437\u0434\u0443. \u0412\u043E \u0432\u0440\u0435\u043C\u044F \u0437\u0432\u0435\u0437\u0434\u043E\u043F\u0430\u0434\u0430 \u041A\u043B\u0435\u0444\u0444\u0430 \u0441\u043E\u0431\u0438\u0440\u0430\u044E\u0442\u0441\u044F \u0438 \u0442\u0430\u043D\u0446\u0443\u044E\u0442.",
      en: "Its star-like shape is especially fitting when groups gather to dance beneath shooting stars."
    },
    habitat: "mountain",
    types: [
      "fairy"
    ],
    height: 0.3,
    weight: 3,
    stats: [
      50,
      25,
      28,
      45,
      55,
      15
    ],
    abilities: [
      {
        id: 56,
        slug: "cute-charm",
        name: {
          ru: "\u041C\u0438\u043B\u043E\u0435 \u043E\u0447\u0430\u0440\u043E\u0432\u0430\u043D\u0438\u0435",
          en: "Cute Charm"
        },
        description: {
          ru: "\u041A\u043E\u043D\u0442\u0430\u043A\u0442\u043D\u0430\u044F \u0430\u0442\u0430\u043A\u0430 \u043C\u043E\u0436\u0435\u0442 \u0432\u043B\u044E\u0431\u0438\u0442\u044C \u0430\u0442\u0430\u043A\u0443\u044E\u0449\u0435\u0433\u043E \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Contact attacks may cause the attacker to become infatuated."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/56/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 98,
        slug: "magic-guard",
        name: {
          ru: "\u041C\u0430\u0433\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0437\u0430\u0449\u0438\u0442\u0430",
          en: "Magic Guard"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u043A\u043E\u0441\u0432\u0435\u043D\u043D\u043E\u0433\u043E \u0443\u0440\u043E\u043D\u0430, \u043D\u0430\u043F\u0440\u0438\u043C\u0435\u0440 \u043E\u0442 \u043F\u043E\u0433\u043E\u0434\u044B.",
          en: "Prevents indirect damage, such as weather damage."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/98/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 132,
        slug: "friend-guard",
        name: {
          ru: "\u0417\u0430\u0449\u0438\u0442\u0430 \u0434\u0440\u0443\u0433\u0430",
          en: "Friend Guard"
        },
        description: {
          ru: "\u0423\u043C\u0435\u043D\u044C\u0448\u0430\u0435\u0442 \u0443\u0440\u043E\u043D, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u043F\u043E\u043B\u0443\u0447\u0430\u044E\u0442 \u0441\u043E\u044E\u0437\u043D\u0438\u043A\u0438.",
          en: "Reduces damage taken by allies."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/132/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 585,
        slug: "moonblast",
        name: {
          ru: "\u041B\u0443\u043D\u043D\u044B\u0439 \u0432\u0437\u0440\u044B\u0432",
          en: "Moonblast"
        },
        description: {
          ru: "\u0421\u0438\u043B\u0430 \u043B\u0443\u043D\u044B \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Moonlight energy may lower the target\u2019s Special Attack."
        },
        type: "fairy",
        power: 95,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 30,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/585/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 30
        },
        statChanges: [
          {
            stat: "special-attack",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/173/"
        }
      },
      {
        id: 94,
        slug: "psychic",
        name: {
          ru: "\u041F\u0441\u0438\u0445\u043E\u043A\u0438\u043D\u0435\u0437",
          en: "Psychic"
        },
        description: {
          ru: "\u041F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0441\u0438\u043B\u0430 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443 \u0446\u0435\u043B\u0438.",
          en: "Psychic force may lower the target\u2019s Special Defense."
        },
        type: "psychic",
        power: 90,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/94/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 10
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/173/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 173,
          name: {
            ru: "\u041A\u043B\u0435\u0444\u0444\u0430",
            en: "Cleffa"
          }
        },
        {
          id: 35,
          name: {
            ru: "\u041A\u043B\u0435\u0444\u0435\u0439\u0440\u0438",
            en: "Clefairy"
          }
        },
        {
          id: 36,
          name: {
            ru: "\u041A\u043B\u0435\u0444\u0435\u0439\u0431\u043B",
            en: "Clefable"
          }
        }
      ],
      edges: [
        {
          from: 173,
          to: 35,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160",
            en: "Level up \xB7 friendship \u2265 160"
          },
          isDefault: true
        },
        {
          from: 35,
          to: 36,
          condition: {
            ru: "\u041B\u0443\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Moon Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 174,
    slug: "igglybuff",
    name: {
      ru: "\u0418\u0433\u0433\u043B\u0438\u0431\u0430\u0444\u0444",
      en: "Igglybuff"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0448\u0430\u0440",
      en: "Balloon Pok\xE9mon"
    },
    description: {
      ru: "\u041C\u044F\u0433\u043A\u043E\u0435 \u0442\u0435\u043B\u043E \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u043F\u0435\u0440\u0435\u0434\u0432\u0438\u0433\u0430\u0442\u044C\u0441\u044F \u043F\u043E\u0434\u0441\u043A\u043E\u043A\u0430\u043C\u0438. \u041F\u0440\u0438 \u043D\u0430\u0433\u0440\u0435\u0432\u0430\u043D\u0438\u0438 \u043E\u043A\u0440\u0430\u0441\u043A\u0430 \u0441\u0442\u0430\u043D\u043E\u0432\u0438\u0442\u0441\u044F \u044F\u0440\u0447\u0435.",
      en: "Its soft body bounces along and becomes a deeper pink as it warms up."
    },
    habitat: "grassland",
    types: [
      "normal",
      "fairy"
    ],
    height: 0.3,
    weight: 1,
    stats: [
      90,
      30,
      15,
      40,
      20,
      15
    ],
    abilities: [
      {
        id: 56,
        slug: "cute-charm",
        name: {
          ru: "\u041C\u0438\u043B\u043E\u0435 \u043E\u0447\u0430\u0440\u043E\u0432\u0430\u043D\u0438\u0435",
          en: "Cute Charm"
        },
        description: {
          ru: "\u041A\u043E\u043D\u0442\u0430\u043A\u0442\u043D\u0430\u044F \u0430\u0442\u0430\u043A\u0430 \u043C\u043E\u0436\u0435\u0442 \u0432\u043B\u044E\u0431\u0438\u0442\u044C \u0430\u0442\u0430\u043A\u0443\u044E\u0449\u0435\u0433\u043E \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Contact attacks may cause the attacker to become infatuated."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/56/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 172,
        slug: "competitive",
        name: {
          ru: "\u0421\u043E\u043F\u0435\u0440\u043D\u0438\u0447\u0435\u0441\u0442\u0432\u043E",
          en: "Competitive"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443, \u0435\u0441\u043B\u0438 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A \u0441\u043D\u0438\u0436\u0430\u0435\u0442 \u0445\u0430\u0440\u0430\u043A\u0442\u0435\u0440\u0438\u0441\u0442\u0438\u043A\u0438.",
          en: "Raises Special Attack when an opponent lowers a stat."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/172/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 132,
        slug: "friend-guard",
        name: {
          ru: "\u0417\u0430\u0449\u0438\u0442\u0430 \u0434\u0440\u0443\u0433\u0430",
          en: "Friend Guard"
        },
        description: {
          ru: "\u0423\u043C\u0435\u043D\u044C\u0448\u0430\u0435\u0442 \u0443\u0440\u043E\u043D, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u043F\u043E\u043B\u0443\u0447\u0430\u044E\u0442 \u0441\u043E\u044E\u0437\u043D\u0438\u043A\u0438.",
          en: "Reduces damage taken by allies."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/132/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 304,
        slug: "hyper-voice",
        name: {
          ru: "\u0413\u0438\u043F\u0435\u0440\u0433\u043E\u043B\u043E\u0441",
          en: "Hyper Voice"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0443\u0435\u0442 \u043C\u043E\u0449\u043D\u043E\u0439 \u0437\u0432\u0443\u043A\u043E\u0432\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Attacks with a powerful wave of sound."
        },
        type: "normal",
        power: 90,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/304/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/174/"
        }
      },
      {
        id: 34,
        slug: "body-slam",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u0442\u0435\u043B\u043E\u043C",
          en: "Body Slam"
        },
        description: {
          ru: "\u041E\u0431\u0440\u0443\u0448\u0438\u0432\u0430\u0435\u0442\u0441\u044F \u043D\u0430 \u0446\u0435\u043B\u044C \u0432\u0441\u0435\u043C \u0442\u0435\u043B\u043E\u043C; \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C.",
          en: "Slams into the target and may cause paralysis."
        },
        type: "normal",
        power: 85,
        accuracy: 100,
        pp: 15,
        damageClass: "physical",
        priority: 0,
        effectChance: 30,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/34/",
        meta: {
          ailment: {
            name: "paralysis"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 30,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/174/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 174,
          name: {
            ru: "\u0418\u0433\u0433\u043B\u0438\u0431\u0430\u0444\u0444",
            en: "Igglybuff"
          }
        },
        {
          id: 39,
          name: {
            ru: "\u0414\u0436\u0438\u0433\u0433\u043B\u0438\u043F\u0430\u0444\u0444",
            en: "Jigglypuff"
          }
        },
        {
          id: 40,
          name: {
            ru: "\u0412\u0438\u0433\u0433\u043B\u0438\u0442\u0430\u0444\u0444",
            en: "Wigglytuff"
          }
        }
      ],
      edges: [
        {
          from: 174,
          to: 39,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160",
            en: "Level up \xB7 friendship \u2265 160"
          },
          isDefault: true
        },
        {
          from: 39,
          to: 40,
          condition: {
            ru: "\u041B\u0443\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Moon Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 182,
    slug: "bellossom",
    name: {
      ru: "\u0411\u0435\u043B\u043B\u043E\u0441\u0441\u043E\u043C",
      en: "Bellossom"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0446\u0432\u0435\u0442\u043E\u043A",
      en: "Flower Pok\xE9mon"
    },
    description: {
      ru: "\u0418\u043D\u043E\u0433\u0434\u0430 \u0441\u043E\u0431\u0438\u0440\u0430\u0435\u0442\u0441\u044F \u0441 \u0441\u043E\u0440\u043E\u0434\u0438\u0447\u0430\u043C\u0438 \u0434\u043B\u044F \u0442\u0430\u043D\u0446\u0430, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u0441\u0447\u0438\u0442\u0430\u044E\u0442 \u043E\u0431\u0440\u044F\u0434\u043E\u043C \u043F\u0440\u0438\u0437\u044B\u0432\u0430 \u0441\u043E\u043B\u043D\u0446\u0430.",
      en: "Groups perform dances believed to be rituals that call forth the sun."
    },
    habitat: "grassland",
    types: [
      "grass"
    ],
    height: 0.4,
    weight: 5.8,
    stats: [
      75,
      80,
      95,
      90,
      100,
      50
    ],
    abilities: [
      {
        id: 34,
        slug: "chlorophyll",
        name: {
          ru: "\u0425\u043B\u043E\u0440\u043E\u0444\u0438\u043B\u043B",
          en: "Chlorophyll"
        },
        description: {
          ru: "\u0423\u0434\u0432\u0430\u0438\u0432\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u0440\u0438 \u044F\u0440\u043A\u043E\u043C \u0441\u043E\u043B\u043D\u0435\u0447\u043D\u043E\u043C \u0441\u0432\u0435\u0442\u0435.",
          en: "Doubles Speed in strong sunlight."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/34/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 131,
        slug: "healer",
        name: {
          ru: "\u0426\u0435\u043B\u0438\u0442\u0435\u043B\u044C",
          en: "Healer"
        },
        description: {
          ru: "\u0418\u043D\u043E\u0433\u0434\u0430 \u0441\u043D\u0438\u043C\u0430\u0435\u0442 \u043F\u0440\u043E\u0431\u043B\u0435\u043C\u0443 \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u044F \u0443 \u0441\u043E\u0441\u0435\u0434\u043D\u0435\u0433\u043E \u0441\u043E\u044E\u0437\u043D\u0438\u043A\u0430.",
          en: "May cure a nearby ally's status condition."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/131/",
        descriptionSource: "editorial-summary-of-core-ability"
      }
    ],
    moves: [
      {
        id: 75,
        slug: "razor-leaf",
        name: {
          ru: "\u041E\u0441\u0442\u0440\u044B\u0435 \u043B\u0438\u0441\u0442\u044C\u044F",
          en: "Razor Leaf"
        },
        description: {
          ru: "\u0411\u0440\u043E\u0441\u0430\u0435\u0442 \u043E\u0441\u0442\u0440\u044B\u0435 \u043B\u0438\u0441\u0442\u044C\u044F; \u0448\u0430\u043D\u0441 \u043A\u0440\u0438\u0442\u0438\u0447\u0435\u0441\u043A\u043E\u0433\u043E \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u044F \u0432\u044B\u0448\u0435.",
          en: "Throws sharp leaves with an increased critical-hit chance."
        },
        type: "grass",
        power: 55,
        accuracy: 95,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/75/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 1,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/182/"
        }
      },
      {
        id: 71,
        slug: "absorb",
        name: {
          ru: "\u041F\u043E\u0433\u043B\u043E\u0449\u0435\u043D\u0438\u0435",
          en: "Absorb"
        },
        description: {
          ru: "\u041F\u043E\u0433\u043B\u043E\u0449\u0430\u0435\u0442 \u044D\u043D\u0435\u0440\u0433\u0438\u044E \u0446\u0435\u043B\u0438 \u0438 \u0432\u043E\u0441\u0441\u0442\u0430\u043D\u0430\u0432\u043B\u0438\u0432\u0430\u0435\u0442 \u0447\u0430\u0441\u0442\u044C \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u044F.",
          en: "Drains the target\u2019s energy to restore some HP."
        },
        type: "grass",
        power: 20,
        accuracy: 100,
        pp: 25,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/71/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-heal"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 50,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/182/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 43,
          name: {
            ru: "\u041E\u0434\u0434\u0438\u0448",
            en: "Oddish"
          }
        },
        {
          id: 44,
          name: {
            ru: "\u0413\u043B\u0443\u043C",
            en: "Gloom"
          }
        },
        {
          id: 45,
          name: {
            ru: "\u0412\u0430\u0439\u043B\u043F\u043B\u0443\u043C",
            en: "Vileplume"
          }
        },
        {
          id: 182,
          name: {
            ru: "\u0411\u0435\u043B\u043B\u043E\u0441\u0441\u043E\u043C",
            en: "Bellossom"
          }
        }
      ],
      edges: [
        {
          from: 43,
          to: 44,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 21",
            en: "Level 21"
          },
          isDefault: true
        },
        {
          from: 44,
          to: 45,
          condition: {
            ru: "\u041B\u0438\u0441\u0442\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Leaf Stone"
          },
          isDefault: true
        },
        {
          from: 44,
          to: 182,
          condition: {
            ru: "\u0421\u043E\u043B\u043D\u0435\u0447\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Sun Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 196,
    slug: "espeon",
    name: {
      ru: "\u042D\u0441\u043F\u0435\u043E\u043D",
      en: "Espeon"
    },
    genus: {
      ru: "\u0421\u043E\u043B\u043D\u0435\u0447\u043D\u044B\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Sun Pok\xE9mon"
    },
    description: {
      ru: "\u0427\u0443\u0432\u0441\u0442\u0432\u0443\u0435\u0442 \u043F\u0435\u0440\u0435\u043C\u0435\u043D\u044B \u043F\u043E\u0433\u043E\u0434\u044B \u0438 \u043C\u044B\u0441\u043B\u0438 \u043E\u043A\u0440\u0443\u0436\u0430\u044E\u0449\u0438\u0445. \u0421\u043E\u043B\u043D\u0435\u0447\u043D\u044B\u0439 \u0441\u0432\u0435\u0442 \u0437\u0430\u0440\u044F\u0436\u0430\u0435\u0442 \u043A\u0430\u043C\u0435\u043D\u044C \u043D\u0430 \u043B\u0431\u0443.",
      en: "Its psychic senses read thoughts and weather changes; sunlight energizes its forehead gem."
    },
    habitat: "urban",
    types: [
      "psychic"
    ],
    height: 0.9,
    weight: 26.5,
    stats: [
      65,
      65,
      60,
      130,
      95,
      110
    ],
    abilities: [
      {
        id: 28,
        slug: "synchronize",
        name: {
          ru: "\u0421\u0438\u043D\u0445\u0440\u043E\u043D\u0438\u0437\u0430\u0446\u0438\u044F",
          en: "Synchronize"
        },
        description: {
          ru: "\u041F\u0435\u0440\u0435\u0434\u0430\u0451\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0443 \u043F\u043E\u043B\u0443\u0447\u0435\u043D\u043D\u044B\u0435 \u043E\u0436\u043E\u0433, \u043E\u0442\u0440\u0430\u0432\u043B\u0435\u043D\u0438\u0435 \u0438\u043B\u0438 \u043F\u0430\u0440\u0430\u043B\u0438\u0447.",
          en: "Passes burns, poison or paralysis back to the opponent."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/28/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 156,
        slug: "magic-bounce",
        name: {
          ru: "\u041C\u0430\u0433\u0438\u0447\u0435\u0441\u043A\u043E\u0435 \u043E\u0442\u0440\u0430\u0436\u0435\u043D\u0438\u0435",
          en: "Magic Bounce"
        },
        description: {
          ru: "\u041E\u0442\u0440\u0430\u0436\u0430\u0435\u0442 \u043D\u0435\u043A\u043E\u0442\u043E\u0440\u044B\u0435 \u0441\u0442\u0430\u0442\u0443\u0441\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438 \u043E\u0431\u0440\u0430\u0442\u043D\u043E \u0432 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Reflects certain status moves back at the opponent."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/156/",
        descriptionSource: "editorial-summary-of-core-ability"
      }
    ],
    moves: [
      {
        id: 94,
        slug: "psychic",
        name: {
          ru: "\u041F\u0441\u0438\u0445\u043E\u043A\u0438\u043D\u0435\u0437",
          en: "Psychic"
        },
        description: {
          ru: "\u041F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0441\u0438\u043B\u0430 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443 \u0446\u0435\u043B\u0438.",
          en: "Psychic force may lower the target\u2019s Special Defense."
        },
        type: "psychic",
        power: 90,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/94/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 10
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/196/"
        }
      },
      {
        id: 93,
        slug: "confusion",
        name: {
          ru: "\u0417\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u043E",
          en: "Confusion"
        },
        description: {
          ru: "\u041F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0430\u0442\u0430\u043A\u0430, \u043A\u043E\u0442\u043E\u0440\u0430\u044F \u043C\u043E\u0436\u0435\u0442 \u0437\u0430\u043F\u0443\u0442\u0430\u0442\u044C \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "A psychic strike that may confuse the target."
        },
        type: "psychic",
        power: 50,
        accuracy: 100,
        pp: 25,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/93/",
        meta: {
          ailment: {
            name: "confusion"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: 2,
          max_turns: 5,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/196/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 133,
          name: {
            ru: "\u0418\u0432\u0438",
            en: "Eevee"
          }
        },
        {
          id: 134,
          name: {
            ru: "\u0412\u0430\u043F\u043E\u0440\u0435\u043E\u043D",
            en: "Vaporeon"
          }
        },
        {
          id: 135,
          name: {
            ru: "\u0414\u0436\u043E\u043B\u0442\u0435\u043E\u043D",
            en: "Jolteon"
          }
        },
        {
          id: 136,
          name: {
            ru: "\u0424\u043B\u0430\u0440\u0435\u043E\u043D",
            en: "Flareon"
          }
        },
        {
          id: 196,
          name: {
            ru: "\u042D\u0441\u043F\u0435\u043E\u043D",
            en: "Espeon"
          }
        },
        {
          id: 197,
          name: {
            ru: "\u0410\u043C\u0431\u0440\u0435\u043E\u043D",
            en: "Umbreon"
          }
        },
        {
          id: 470,
          name: {
            ru: "\u041B\u0438\u0444\u0435\u043E\u043D",
            en: "Leafeon"
          }
        },
        {
          id: 471,
          name: {
            ru: "\u0413\u043B\u0430\u0441\u0435\u043E\u043D",
            en: "Glaceon"
          }
        },
        {
          id: 700,
          name: {
            ru: "\u0421\u0438\u043B\u044C\u0432\u0435\u043E\u043D",
            en: "Sylveon"
          }
        }
      ],
      edges: [
        {
          from: 133,
          to: 134,
          condition: {
            ru: "\u0412\u043E\u0434\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Water Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 135,
          condition: {
            ru: "\u0413\u0440\u043E\u043C\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Thunder Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 136,
          condition: {
            ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Fire Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 196,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0434\u043D\u0451\u043C",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during day"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 197,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u043D\u043E\u0447\u044C\u044E",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during night"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 470,
          condition: {
            ru: "\u041B\u0438\u0441\u0442\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Leaf Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 471,
          condition: {
            ru: "\u041B\u0435\u0434\u044F\u043D\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Ice Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 700,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0437\u043D\u0430\u0435\u0442 \u0432\u043E\u043B\u0448\u0435\u0431\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443",
            en: "Level up \xB7 friendship \u2265 160 \xB7 knows a Fairy move"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 197,
    slug: "umbreon",
    name: {
      ru: "\u0410\u043C\u0431\u0440\u0435\u043E\u043D",
      en: "Umbreon"
    },
    genus: {
      ru: "\u041B\u0443\u043D\u043D\u044B\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Moonlight Pok\xE9mon"
    },
    description: {
      ru: "\u0410\u043A\u0442\u0438\u0432\u043D\u0435\u0435 \u0432\u0441\u0435\u0433\u043E \u0433\u043B\u0443\u0431\u043E\u043A\u043E\u0439 \u043D\u043E\u0447\u044C\u044E. \u041A\u0440\u0443\u043F\u043D\u044B\u0435 \u0433\u043B\u0430\u0437\u0430 \u0445\u043E\u0440\u043E\u0448\u043E \u0440\u0430\u0437\u043B\u0438\u0447\u0430\u044E\u0442 \u0434\u043E\u0431\u044B\u0447\u0443 \u0432 \u0442\u0435\u043C\u043D\u043E\u0442\u0435.",
      en: "Most active late at night, Umbreon spots prey clearly with its large eyes."
    },
    habitat: "urban",
    types: [
      "dark"
    ],
    height: 1,
    weight: 27,
    stats: [
      95,
      65,
      110,
      60,
      130,
      65
    ],
    abilities: [
      {
        id: 28,
        slug: "synchronize",
        name: {
          ru: "\u0421\u0438\u043D\u0445\u0440\u043E\u043D\u0438\u0437\u0430\u0446\u0438\u044F",
          en: "Synchronize"
        },
        description: {
          ru: "\u041F\u0435\u0440\u0435\u0434\u0430\u0451\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0443 \u043F\u043E\u043B\u0443\u0447\u0435\u043D\u043D\u044B\u0435 \u043E\u0436\u043E\u0433, \u043E\u0442\u0440\u0430\u0432\u043B\u0435\u043D\u0438\u0435 \u0438\u043B\u0438 \u043F\u0430\u0440\u0430\u043B\u0438\u0447.",
          en: "Passes burns, poison or paralysis back to the opponent."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/28/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 39,
        slug: "inner-focus",
        name: {
          ru: "\u0421\u043E\u0441\u0440\u0435\u0434\u043E\u0442\u043E\u0447\u0435\u043D\u043D\u043E\u0441\u0442\u044C",
          en: "Inner Focus"
        },
        description: {
          ru: "\u041D\u0435 \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0438\u0441\u043F\u0443\u0433\u0430\u0442\u044C\u0441\u044F \u0438 \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Prevents flinching."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/39/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 242,
        slug: "crunch",
        name: {
          ru: "\u0425\u0440\u0443\u0441\u0442",
          en: "Crunch"
        },
        description: {
          ru: "\u0421\u0438\u043B\u044C\u043D\u044B\u0439 \u0443\u043A\u0443\u0441, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0437\u0430\u0449\u0438\u0442\u0443 \u0446\u0435\u043B\u0438.",
          en: "A strong bite that may lower Defense."
        },
        type: "dark",
        power: 80,
        accuracy: 100,
        pp: 15,
        damageClass: "physical",
        priority: 0,
        effectChance: 20,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/242/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 20
        },
        statChanges: [
          {
            stat: "defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/197/"
        }
      },
      {
        id: 44,
        slug: "bite",
        name: {
          ru: "\u0423\u043A\u0443\u0441",
          en: "Bite"
        },
        description: {
          ru: "\u041A\u0443\u0441\u0430\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430; \u043C\u043E\u0436\u0435\u0442 \u0437\u0430\u0441\u0442\u0430\u0432\u0438\u0442\u044C \u0435\u0433\u043E \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Bites the target and may make it flinch."
        },
        type: "dark",
        power: 60,
        accuracy: 100,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: 30,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/44/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 30,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/197/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 133,
          name: {
            ru: "\u0418\u0432\u0438",
            en: "Eevee"
          }
        },
        {
          id: 134,
          name: {
            ru: "\u0412\u0430\u043F\u043E\u0440\u0435\u043E\u043D",
            en: "Vaporeon"
          }
        },
        {
          id: 135,
          name: {
            ru: "\u0414\u0436\u043E\u043B\u0442\u0435\u043E\u043D",
            en: "Jolteon"
          }
        },
        {
          id: 136,
          name: {
            ru: "\u0424\u043B\u0430\u0440\u0435\u043E\u043D",
            en: "Flareon"
          }
        },
        {
          id: 196,
          name: {
            ru: "\u042D\u0441\u043F\u0435\u043E\u043D",
            en: "Espeon"
          }
        },
        {
          id: 197,
          name: {
            ru: "\u0410\u043C\u0431\u0440\u0435\u043E\u043D",
            en: "Umbreon"
          }
        },
        {
          id: 470,
          name: {
            ru: "\u041B\u0438\u0444\u0435\u043E\u043D",
            en: "Leafeon"
          }
        },
        {
          id: 471,
          name: {
            ru: "\u0413\u043B\u0430\u0441\u0435\u043E\u043D",
            en: "Glaceon"
          }
        },
        {
          id: 700,
          name: {
            ru: "\u0421\u0438\u043B\u044C\u0432\u0435\u043E\u043D",
            en: "Sylveon"
          }
        }
      ],
      edges: [
        {
          from: 133,
          to: 134,
          condition: {
            ru: "\u0412\u043E\u0434\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Water Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 135,
          condition: {
            ru: "\u0413\u0440\u043E\u043C\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Thunder Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 136,
          condition: {
            ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Fire Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 196,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0434\u043D\u0451\u043C",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during day"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 197,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u043D\u043E\u0447\u044C\u044E",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during night"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 470,
          condition: {
            ru: "\u041B\u0438\u0441\u0442\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Leaf Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 471,
          condition: {
            ru: "\u041B\u0435\u0434\u044F\u043D\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Ice Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 700,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0437\u043D\u0430\u0435\u0442 \u0432\u043E\u043B\u0448\u0435\u0431\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443",
            en: "Level up \xB7 friendship \u2265 160 \xB7 knows a Fairy move"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 199,
    slug: "slowking",
    name: {
      ru: "\u0421\u043B\u043E\u0443\u043A\u0438\u043D\u0433",
      en: "Slowking"
    },
    genus: {
      ru: "\u041A\u043E\u0440\u043E\u043B\u0435\u0432\u0441\u043A\u0438\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Royal Pok\xE9mon"
    },
    description: {
      ru: "\u0423\u043C\u0435\u0435\u0442 \u0440\u0435\u0448\u0430\u0442\u044C \u0441\u043B\u043E\u0436\u043D\u044B\u0435 \u0437\u0430\u0434\u0430\u0447\u0438, \u0445\u043E\u0442\u044F \u043E\u043A\u0440\u0443\u0436\u0430\u044E\u0449\u0438\u043C \u0442\u0440\u0443\u0434\u043D\u043E \u043F\u043E\u043D\u044F\u0442\u044C \u0435\u0433\u043E \u0440\u0435\u0447\u044C.",
      en: "It can solve difficult problems, but others cannot make sense of its speech."
    },
    habitat: "water",
    types: [
      "water",
      "psychic"
    ],
    height: 2,
    weight: 79.5,
    stats: [
      95,
      75,
      80,
      100,
      110,
      30
    ],
    abilities: [
      {
        id: 12,
        slug: "oblivious",
        name: {
          ru: "\u041D\u0435\u0432\u043E\u0437\u043C\u0443\u0442\u0438\u043C\u043E\u0441\u0442\u044C",
          en: "Oblivious"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u0432\u043B\u044E\u0431\u043B\u0451\u043D\u043D\u043E\u0441\u0442\u0438.",
          en: "Prevents infatuation."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/12/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 20,
        slug: "own-tempo",
        name: {
          ru: "\u0421\u0432\u043E\u0439 \u0442\u0435\u043C\u043F",
          en: "Own Tempo"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u0437\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u0430.",
          en: "Prevents confusion."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/20/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 144,
        slug: "regenerator",
        name: {
          ru: "\u0420\u0435\u0433\u0435\u043D\u0435\u0440\u0430\u0446\u0438\u044F",
          en: "Regenerator"
        },
        description: {
          ru: "\u0412\u043E\u0441\u0441\u0442\u0430\u043D\u0430\u0432\u043B\u0438\u0432\u0430\u0435\u0442 \u0447\u0430\u0441\u0442\u044C \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u044F \u043F\u0440\u0438 \u0441\u043C\u0435\u043D\u0435 \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u0430.",
          en: "Restores some HP when the Pok\xE9mon switches out."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/144/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 57,
        slug: "surf",
        name: {
          ru: "\u0421\u0451\u0440\u0444\u0438\u043D\u0433",
          en: "Surf"
        },
        description: {
          ru: "\u041D\u0430\u043A\u0440\u044B\u0432\u0430\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u0431\u043E\u043B\u044C\u0448\u043E\u0439 \u0432\u043E\u0434\u044F\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Sweeps over opponents with a large wave of water."
        },
        type: "water",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/57/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/199/"
        }
      },
      {
        id: 94,
        slug: "psychic",
        name: {
          ru: "\u041F\u0441\u0438\u0445\u043E\u043A\u0438\u043D\u0435\u0437",
          en: "Psychic"
        },
        description: {
          ru: "\u041F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0441\u0438\u043B\u0430 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443 \u0446\u0435\u043B\u0438.",
          en: "Psychic force may lower the target\u2019s Special Defense."
        },
        type: "psychic",
        power: 90,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/94/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 10
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/199/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 79,
          name: {
            ru: "\u0421\u043B\u043E\u0443\u043F\u043E\u043A",
            en: "Slowpoke"
          }
        },
        {
          id: 80,
          name: {
            ru: "\u0421\u043B\u043E\u0443\u0431\u0440\u043E",
            en: "Slowbro"
          }
        },
        {
          id: 199,
          name: {
            ru: "\u0421\u043B\u043E\u0443\u043A\u0438\u043D\u0433",
            en: "Slowking"
          }
        }
      ],
      edges: [
        {
          from: 79,
          to: 80,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 37",
            en: "Level 37"
          },
          isDefault: true
        },
        {
          from: 79,
          to: 199,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D \xB7 \u0441 \u043F\u0440\u0435\u0434\u043C\u0435\u0442\u043E\u043C \xAB\u041A\u043E\u0440\u043E\u043B\u0435\u0432\u0441\u043A\u0438\u0439 \u043A\u0430\u043C\u0435\u043D\u044C\xBB",
            en: "Trade \xB7 holding King\u2019s Rock"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 208,
    slug: "steelix",
    name: {
      ru: "\u0421\u0442\u0438\u043B\u0438\u043A\u0441",
      en: "Steelix"
    },
    genus: {
      ru: "\u0416\u0435\u043B\u0435\u0437\u043D\u0430\u044F \u0437\u043C\u0435\u044F",
      en: "Iron Snake Pok\xE9mon"
    },
    description: {
      ru: "\u0422\u0435\u043B\u043E \u043F\u043E\u043A\u0440\u044B\u0442\u043E \u0447\u0440\u0435\u0437\u0432\u044B\u0447\u0430\u0439\u043D\u043E \u0442\u0432\u0451\u0440\u0434\u043E\u0439 \u0441\u0442\u0430\u043B\u044C\u044E, \u043A\u043E\u0442\u043E\u0440\u0443\u044E \u0441\u043B\u043E\u0436\u043D\u043E \u043F\u043E\u0446\u0430\u0440\u0430\u043F\u0430\u0442\u044C \u0434\u0430\u0436\u0435 \u0430\u043B\u043C\u0430\u0437\u043E\u043C.",
      en: "Its steel-coated body is exceptionally hard, resisting even a diamond's scratch."
    },
    habitat: "cave",
    types: [
      "steel",
      "ground"
    ],
    height: 9.2,
    weight: 400,
    stats: [
      75,
      85,
      200,
      55,
      65,
      30
    ],
    abilities: [
      {
        id: 69,
        slug: "rock-head",
        name: {
          ru: "\u041A\u0430\u043C\u0435\u043D\u043D\u0430\u044F \u0433\u043E\u043B\u043E\u0432\u0430",
          en: "Rock Head"
        },
        description: {
          ru: "\u0417\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u0443\u0440\u043E\u043D\u0430 \u043E\u0442\u0434\u0430\u0447\u0438 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u044B\u0445 \u0430\u0442\u0430\u043A.",
          en: "Prevents recoil damage from its own moves."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/69/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 5,
        slug: "sturdy",
        name: {
          ru: "\u041F\u0440\u043E\u0447\u043D\u043E\u0441\u0442\u044C",
          en: "Sturdy"
        },
        description: {
          ru: "\u041F\u0440\u0438 \u043F\u043E\u043B\u043D\u043E\u043C \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043F\u0435\u0440\u0435\u0436\u0438\u0432\u0430\u0435\u0442 \u0443\u0434\u0430\u0440, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u0438\u043D\u0430\u0447\u0435 \u0441\u0442\u0430\u043B \u0431\u044B \u043D\u043E\u043A\u0430\u0443\u0442\u043E\u043C.",
          en: "At full HP, survives a hit that would otherwise knock it out."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/5/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 125,
        slug: "sheer-force",
        name: {
          ru: "\u0413\u0440\u0443\u0431\u0430\u044F \u0441\u0438\u043B\u0430",
          en: "Sheer Force"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0430\u0442\u0430\u043A\u0438 \u0441 \u0434\u043E\u043F\u043E\u043B\u043D\u0438\u0442\u0435\u043B\u044C\u043D\u044B\u043C\u0438 \u044D\u0444\u0444\u0435\u043A\u0442\u0430\u043C\u0438, \u0443\u0431\u0438\u0440\u0430\u044F \u044D\u0442\u0438 \u044D\u0444\u0444\u0435\u043A\u0442\u044B.",
          en: "Boosts moves with secondary effects while removing those effects."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/125/",
        descriptionSource: "editorial-summary-of-core-ability"
      }
    ],
    moves: [
      {
        id: 430,
        slug: "flash-cannon",
        name: {
          ru: "\u0421\u0432\u0435\u0442\u043E\u0432\u0430\u044F \u043F\u0443\u0448\u043A\u0430",
          en: "Flash Cannon"
        },
        description: {
          ru: "\u041B\u0443\u0447 \u043D\u0430\u043A\u043E\u043F\u043B\u0435\u043D\u043D\u043E\u0439 \u044D\u043D\u0435\u0440\u0433\u0438\u0438 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443.",
          en: "Fires stored energy and may lower Special Defense."
        },
        type: "steel",
        power: 80,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/430/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 10
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/208/"
        }
      },
      {
        id: 89,
        slug: "earthquake",
        name: {
          ru: "\u0417\u0435\u043C\u043B\u0435\u0442\u0440\u044F\u0441\u0435\u043D\u0438\u0435",
          en: "Earthquake"
        },
        description: {
          ru: "\u0421\u043E\u0442\u0440\u044F\u0441\u0430\u0435\u0442 \u0437\u0435\u043C\u043B\u044E \u043C\u043E\u0449\u043D\u043E\u0439 \u0443\u0434\u0430\u0440\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Shakes the ground with a powerful shock wave."
        },
        type: "ground",
        power: 100,
        accuracy: 100,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/89/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/208/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 95,
          name: {
            ru: "\u041E\u043D\u0438\u043A\u0441",
            en: "Onix"
          }
        },
        {
          id: 208,
          name: {
            ru: "\u0421\u0442\u0438\u043B\u0438\u043A\u0441",
            en: "Steelix"
          }
        }
      ],
      edges: [
        {
          from: 95,
          to: 208,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D \xB7 \u0441 \u043F\u0440\u0435\u0434\u043C\u0435\u0442\u043E\u043C \xAB\u041C\u0435\u0442\u0430\u043B\u043B\u0438\u0447\u0435\u0441\u043A\u043E\u0435 \u043F\u043E\u043A\u0440\u044B\u0442\u0438\u0435\xBB",
            en: "Trade \xB7 holding Metal Coat"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 212,
    slug: "scizor",
    name: {
      ru: "\u0421\u0438\u0437\u043E\u0440",
      en: "Scizor"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D \u0441 \u043A\u043B\u0435\u0448\u043D\u044F\u043C\u0438",
      en: "Pincer Pok\xE9mon"
    },
    description: {
      ru: "\u041F\u043E\u0441\u043B\u0435 \u044D\u0432\u043E\u043B\u044E\u0446\u0438\u0438 \u0435\u0433\u043E \u0442\u0435\u043B\u043E \u0437\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043F\u0430\u043D\u0446\u0438\u0440\u044C \u043F\u0440\u043E\u0447\u043D\u0435\u0435 \u043A\u043E\u0432\u0430\u043D\u043E\u0439 \u0441\u0442\u0430\u043B\u0438.",
      en: "Evolution gives Scizor a shell tougher than forged steel."
    },
    habitat: "grassland",
    types: [
      "bug",
      "steel"
    ],
    height: 1.8,
    weight: 118,
    stats: [
      70,
      130,
      100,
      55,
      80,
      65
    ],
    abilities: [
      {
        id: 68,
        slug: "swarm",
        name: {
          ru: "\u0420\u043E\u0439",
          en: "Swarm"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u043D\u0430\u0441\u0435\u043A\u043E\u043C\u044B\u0435 \u0430\u0442\u0430\u043A\u0438, \u043A\u043E\u0433\u0434\u0430 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043D\u0438\u0437\u043A\u043E\u0435.",
          en: "Boosts Bug moves when HP is low."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/68/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 101,
        slug: "technician",
        name: {
          ru: "\u0422\u0435\u0445\u043D\u0438\u043A",
          en: "Technician"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0430\u0442\u0430\u043A\u0438 \u0441 \u043D\u0435\u0431\u043E\u043B\u044C\u0448\u043E\u0439 \u0431\u0430\u0437\u043E\u0432\u043E\u0439 \u043C\u043E\u0449\u043D\u043E\u0441\u0442\u044C\u044E.",
          en: "Boosts moves with low base power."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/101/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 135,
        slug: "light-metal",
        name: {
          ru: "\u041B\u0451\u0433\u043A\u0438\u0439 \u043C\u0435\u0442\u0430\u043B\u043B",
          en: "Light Metal"
        },
        description: {
          ru: "\u0412\u0434\u0432\u043E\u0435 \u0443\u043C\u0435\u043D\u044C\u0448\u0430\u0435\u0442 \u0432\u0435\u0441 \u043F\u043E\u043A\u0435\u043C\u043E\u043D\u0430.",
          en: "Halves the Pok\xE9mon's weight."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/135/",
        descriptionSource: "editorial-summary-of-core-ability"
      }
    ],
    moves: [
      {
        id: 404,
        slug: "x-scissor",
        name: {
          ru: "\u041A\u0440\u0435\u0441\u0442-\u043D\u043E\u0436\u043D\u0438\u0446\u044B",
          en: "X-Scissor"
        },
        description: {
          ru: "\u041F\u0435\u0440\u0435\u043A\u0440\u0435\u0449\u0438\u0432\u0430\u0435\u0442 \u043B\u0435\u0437\u0432\u0438\u044F \u0438 \u043D\u0430\u043D\u043E\u0441\u0438\u0442 \u0440\u0435\u0436\u0443\u0449\u0438\u0439 \u0443\u0434\u0430\u0440.",
          en: "Crosses its blades to deliver a slashing strike."
        },
        type: "bug",
        power: 80,
        accuracy: 100,
        pp: 15,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/404/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/212/"
        }
      },
      {
        id: 430,
        slug: "flash-cannon",
        name: {
          ru: "\u0421\u0432\u0435\u0442\u043E\u0432\u0430\u044F \u043F\u0443\u0448\u043A\u0430",
          en: "Flash Cannon"
        },
        description: {
          ru: "\u041B\u0443\u0447 \u043D\u0430\u043A\u043E\u043F\u043B\u0435\u043D\u043D\u043E\u0439 \u044D\u043D\u0435\u0440\u0433\u0438\u0438 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443.",
          en: "Fires stored energy and may lower Special Defense."
        },
        type: "steel",
        power: 80,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/430/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 10
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/212/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 123,
          name: {
            ru: "\u0421\u043A\u0430\u0439\u0442\u0435\u0440",
            en: "Scyther"
          }
        },
        {
          id: 212,
          name: {
            ru: "\u0421\u0438\u0437\u043E\u0440",
            en: "Scizor"
          }
        },
        {
          id: 900,
          name: {
            ru: "\u041A\u043B\u0438\u0432\u043E\u0440",
            en: "Kleavor"
          }
        }
      ],
      edges: [
        {
          from: 123,
          to: 212,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D \xB7 \u0441 \u043F\u0440\u0435\u0434\u043C\u0435\u0442\u043E\u043C \xAB\u041C\u0435\u0442\u0430\u043B\u043B\u0438\u0447\u0435\u0441\u043A\u043E\u0435 \u043F\u043E\u043A\u0440\u044B\u0442\u0438\u0435\xBB",
            en: "Trade \xB7 holding Metal Coat"
          },
          isDefault: true
        },
        {
          from: 123,
          to: 900,
          condition: {
            ru: "\u0427\u0451\u0440\u043D\u044B\u0439 \u0430\u0432\u0433\u0443\u0440\u0438\u0442",
            en: "Black Augurite"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 230,
    slug: "kingdra",
    name: {
      ru: "\u041A\u0438\u043D\u0433\u0434\u0440\u0430",
      en: "Kingdra"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0434\u0440\u0430\u043A\u043E\u043D",
      en: "Dragon Pok\xE9mon"
    },
    description: {
      ru: "\u0421\u0431\u0440\u043E\u0448\u0435\u043D\u043D\u0430\u044F \u0447\u0435\u0448\u0443\u044F \u0442\u0430\u043A \u043A\u0440\u0430\u0441\u0438\u0432\u043E \u0431\u043B\u0435\u0441\u0442\u0438\u0442, \u0447\u0442\u043E \u0435\u0451 \u043F\u0440\u0435\u043F\u043E\u0434\u043D\u043E\u0441\u0438\u043B\u0438 \u043F\u0440\u0430\u0432\u0438\u0442\u0435\u043B\u044F\u043C \u0432 \u043F\u043E\u0434\u0430\u0440\u043E\u043A.",
      en: "Its shed scales shine so brilliantly that they have been presented as royal gifts."
    },
    habitat: "water",
    types: [
      "water",
      "dragon"
    ],
    height: 1.8,
    weight: 152,
    stats: [
      75,
      95,
      95,
      95,
      95,
      85
    ],
    abilities: [
      {
        id: 33,
        slug: "swift-swim",
        name: {
          ru: "\u0411\u044B\u0441\u0442\u0440\u043E\u0435 \u043F\u043B\u0430\u0432\u0430\u043D\u0438\u0435",
          en: "Swift Swim"
        },
        description: {
          ru: "\u0423\u0434\u0432\u0430\u0438\u0432\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u043E\u0434 \u0434\u043E\u0436\u0434\u0451\u043C.",
          en: "Doubles Speed in rain."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/33/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 97,
        slug: "sniper",
        name: {
          ru: "\u0421\u043D\u0430\u0439\u043F\u0435\u0440",
          en: "Sniper"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0443\u0440\u043E\u043D \u043A\u0440\u0438\u0442\u0438\u0447\u0435\u0441\u043A\u0438\u0445 \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u0439.",
          en: "Increases damage dealt by critical hits."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/97/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 6,
        slug: "damp",
        name: {
          ru: "\u0412\u043B\u0430\u0436\u043D\u043E\u0441\u0442\u044C",
          en: "Damp"
        },
        description: {
          ru: "\u041F\u0440\u0435\u0434\u043E\u0442\u0432\u0440\u0430\u0449\u0430\u0435\u0442 \u0441\u0430\u043C\u043E\u0443\u043D\u0438\u0447\u0442\u043E\u0436\u0435\u043D\u0438\u0435 \u0438 \u0432\u0437\u0440\u044B\u0432\u043D\u044B\u0435 \u044D\u0444\u0444\u0435\u043A\u0442\u044B.",
          en: "Prevents self-destructing moves and explosive effects."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/6/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 57,
        slug: "surf",
        name: {
          ru: "\u0421\u0451\u0440\u0444\u0438\u043D\u0433",
          en: "Surf"
        },
        description: {
          ru: "\u041D\u0430\u043A\u0440\u044B\u0432\u0430\u0435\u0442 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430 \u0431\u043E\u043B\u044C\u0448\u043E\u0439 \u0432\u043E\u0434\u044F\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Sweeps over opponents with a large wave of water."
        },
        type: "water",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/57/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/230/"
        }
      },
      {
        id: 200,
        slug: "outrage",
        name: {
          ru: "\u041D\u0435\u0438\u0441\u0442\u043E\u0432\u0441\u0442\u0432\u043E",
          en: "Outrage"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0443\u0435\u0442 \u043D\u0435\u0441\u043A\u043E\u043B\u044C\u043A\u043E \u0445\u043E\u0434\u043E\u0432 \u043F\u043E\u0434\u0440\u044F\u0434, \u0437\u0430\u0442\u0435\u043C \u043F\u0440\u0438\u0445\u043E\u0434\u0438\u0442 \u0432 \u0437\u0430\u043C\u0435\u0448\u0430\u0442\u0435\u043B\u044C\u0441\u0442\u0432\u043E.",
          en: "Attacks repeatedly for several turns, then becomes confused."
        },
        type: "dragon",
        power: 120,
        accuracy: 100,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "random-opponent",
        sourceUrl: "https://pokeapi.co/api/v2/move/200/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/230/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 116,
          name: {
            ru: "\u0425\u043E\u0440\u0441\u0438",
            en: "Horsea"
          }
        },
        {
          id: 117,
          name: {
            ru: "\u0421\u0438\u0434\u0440\u0430",
            en: "Seadra"
          }
        },
        {
          id: 230,
          name: {
            ru: "\u041A\u0438\u043D\u0433\u0434\u0440\u0430",
            en: "Kingdra"
          }
        }
      ],
      edges: [
        {
          from: 116,
          to: 117,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 32",
            en: "Level 32"
          },
          isDefault: true
        },
        {
          from: 117,
          to: 230,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D \xB7 \u0441 \u043F\u0440\u0435\u0434\u043C\u0435\u0442\u043E\u043C \xAB\u0427\u0435\u0448\u0443\u044F \u0434\u0440\u0430\u043A\u043E\u043D\u0430\xBB",
            en: "Trade \xB7 holding Dragon Scale"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 446,
    slug: "munchlax",
    name: {
      ru: "\u041C\u0430\u043D\u0447\u043B\u0430\u043A\u0441",
      en: "Munchlax"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D \u0441 \u0431\u043E\u043B\u044C\u0448\u0438\u043C \u0430\u043F\u043F\u0435\u0442\u0438\u0442\u043E\u043C",
      en: "Big Eater Pok\xE9mon"
    },
    description: {
      ru: "\u041A\u0440\u0435\u043F\u043A\u0438\u0439 \u0436\u0435\u043B\u0443\u0434\u043E\u043A \u043F\u0435\u0440\u0435\u0432\u0430\u0440\u0438\u0432\u0430\u0435\u0442 \u0434\u0430\u0436\u0435 \u0438\u0441\u043F\u043E\u0440\u0447\u0435\u043D\u043D\u0443\u044E \u0435\u0434\u0443. \u0427\u0430\u0441\u0442\u043E \u0438\u0449\u0435\u0442 \u043F\u0438\u0449\u0435\u0432\u044B\u0435 \u043E\u0441\u0442\u0430\u0442\u043A\u0438 \u0432 \u043F\u043E\u0441\u0435\u043B\u0435\u043D\u0438\u044F\u0445.",
      en: "A sturdy stomach handles spoiled food, and it often visits villages for scraps."
    },
    habitat: "unknown",
    types: [
      "normal"
    ],
    height: 0.6,
    weight: 105,
    stats: [
      135,
      85,
      40,
      40,
      85,
      5
    ],
    abilities: [
      {
        id: 53,
        slug: "pickup",
        name: {
          ru: "\u0421\u0431\u043E\u0440",
          en: "Pickup"
        },
        description: {
          ru: "\u041C\u043E\u0436\u0435\u0442 \u043D\u0430\u0445\u043E\u0434\u0438\u0442\u044C \u043F\u0440\u0435\u0434\u043C\u0435\u0442\u044B \u043F\u043E\u0441\u043B\u0435 \u0431\u043E\u044F.",
          en: "May find items after a battle."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/53/",
        descriptionSource: "editorial-summary-of-core-ability"
      },
      {
        id: 47,
        slug: "thick-fat",
        name: {
          ru: "\u041F\u043B\u043E\u0442\u043D\u044B\u0439 \u0436\u0438\u0440",
          en: "Thick Fat"
        },
        description: {
          ru: "\u0423\u043C\u0435\u043D\u044C\u0448\u0430\u0435\u0442 \u0443\u0440\u043E\u043D \u043E\u0433\u043D\u0435\u043D\u043D\u044B\u0445 \u0438 \u043B\u0435\u0434\u044F\u043D\u044B\u0445 \u0430\u0442\u0430\u043A.",
          en: "Reduces damage from Fire and Ice moves."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/47/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 82,
        slug: "gluttony",
        name: {
          ru: "\u041E\u0431\u0436\u043E\u0440\u0441\u0442\u0432\u043E",
          en: "Gluttony"
        },
        description: {
          ru: "\u041F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0440\u0430\u043D\u044C\u0448\u0435 \u0441\u044A\u0435\u0441\u0442\u044C \u0443\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u043C\u0443\u044E \u043B\u0435\u0447\u0435\u0431\u043D\u0443\u044E \u044F\u0433\u043E\u0434\u0443.",
          en: "Makes the Pok\xE9mon eat its held HP-triggered berry earlier."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/82/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 304,
        slug: "hyper-voice",
        name: {
          ru: "\u0413\u0438\u043F\u0435\u0440\u0433\u043E\u043B\u043E\u0441",
          en: "Hyper Voice"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0443\u0435\u0442 \u043C\u043E\u0449\u043D\u043E\u0439 \u0437\u0432\u0443\u043A\u043E\u0432\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Attacks with a powerful wave of sound."
        },
        type: "normal",
        power: 90,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/304/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/446/"
        }
      },
      {
        id: 34,
        slug: "body-slam",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u0442\u0435\u043B\u043E\u043C",
          en: "Body Slam"
        },
        description: {
          ru: "\u041E\u0431\u0440\u0443\u0448\u0438\u0432\u0430\u0435\u0442\u0441\u044F \u043D\u0430 \u0446\u0435\u043B\u044C \u0432\u0441\u0435\u043C \u0442\u0435\u043B\u043E\u043C; \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C.",
          en: "Slams into the target and may cause paralysis."
        },
        type: "normal",
        power: 85,
        accuracy: 100,
        pp: 15,
        damageClass: "physical",
        priority: 0,
        effectChance: 30,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/34/",
        meta: {
          ailment: {
            name: "paralysis"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 30,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/446/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 446,
          name: {
            ru: "\u041C\u0430\u043D\u0447\u043B\u0430\u043A\u0441",
            en: "Munchlax"
          }
        },
        {
          id: 143,
          name: {
            ru: "\u0421\u043D\u043E\u0440\u043B\u0430\u043A\u0441",
            en: "Snorlax"
          }
        }
      ],
      edges: [
        {
          from: 446,
          to: 143,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160",
            en: "Level up \xB7 friendship \u2265 160"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 447,
    slug: "riolu",
    name: {
      ru: "\u0420\u0438\u043E\u043B\u0443",
      en: "Riolu"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D \u0438\u0437\u043B\u0443\u0447\u0435\u043D\u0438\u044F",
      en: "Emanation Pok\xE9mon"
    },
    description: {
      ru: "\u041D\u0435\u0441\u043C\u043E\u0442\u0440\u044F \u043D\u0430 \u0434\u0435\u0442\u0441\u043A\u0438\u0439 \u0432\u0438\u0434, \u043E\u0449\u0443\u0449\u0430\u0435\u0442 \u043C\u044B\u0441\u043B\u0438 \u043B\u044E\u0434\u0435\u0439 \u0438 \u0440\u0430\u0437\u043B\u0438\u0447\u0430\u0435\u0442 \u0438\u0445 \u043D\u0430\u043C\u0435\u0440\u0435\u043D\u0438\u044F.",
      en: "Despite its youthful appearance, Riolu can sense human thoughts and intentions."
    },
    habitat: "unknown",
    types: [
      "fighting"
    ],
    height: 0.7,
    weight: 20.2,
    stats: [
      40,
      70,
      40,
      35,
      40,
      60
    ],
    abilities: [
      {
        id: 80,
        slug: "steadfast",
        name: {
          ru: "\u0421\u0442\u043E\u0439\u043A\u043E\u0441\u0442\u044C",
          en: "Steadfast"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u043E\u0441\u043B\u0435 \u0438\u0441\u043F\u0443\u0433\u0430.",
          en: "Raises Speed after flinching."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/80/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 39,
        slug: "inner-focus",
        name: {
          ru: "\u0421\u043E\u0441\u0440\u0435\u0434\u043E\u0442\u043E\u0447\u0435\u043D\u043D\u043E\u0441\u0442\u044C",
          en: "Inner Focus"
        },
        description: {
          ru: "\u041D\u0435 \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0438\u0441\u043F\u0443\u0433\u0430\u0442\u044C\u0441\u044F \u0438 \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Prevents flinching."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/39/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 158,
        slug: "prankster",
        name: {
          ru: "\u0428\u0443\u0442\u043D\u0438\u043A",
          en: "Prankster"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u043F\u0440\u0438\u043E\u0440\u0438\u0442\u0435\u0442 \u0441\u0442\u0430\u0442\u0443\u0441\u043D\u044B\u0445 \u043F\u0440\u0438\u0451\u043C\u043E\u0432.",
          en: "Increases the priority of status moves."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/158/",
        descriptionSource: "editorial-summary-of-core-ability"
      }
    ],
    moves: [
      {
        id: 396,
        slug: "aura-sphere",
        name: {
          ru: "\u0421\u0444\u0435\u0440\u0430 \u0430\u0443\u0440\u044B",
          en: "Aura Sphere"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u0441\u0433\u0443\u0441\u0442\u043E\u043A \u0430\u0443\u0440\u044B. \u0410\u0442\u0430\u043A\u0430 \u043D\u0435 \u043F\u0440\u043E\u043C\u0430\u0445\u0438\u0432\u0430\u0435\u0442\u0441\u044F.",
          en: "Fires a sphere of aura that cannot miss."
        },
        type: "fighting",
        power: 80,
        accuracy: null,
        pp: 20,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/396/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/447/"
        }
      },
      {
        id: 67,
        slug: "low-kick",
        name: {
          ru: "\u041F\u043E\u0434\u0441\u0435\u0447\u043A\u0430",
          en: "Low Kick"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0443\u0435\u0442 \u043D\u043E\u0433\u0438; \u043F\u0440\u043E\u0442\u0438\u0432 \u0442\u044F\u0436\u0451\u043B\u043E\u0439 \u0446\u0435\u043B\u0438 \u0443\u0434\u0430\u0440 \u0441\u0438\u043B\u044C\u043D\u0435\u0435.",
          en: "Sweeps the target\u2019s legs, dealing more damage to heavier foes."
        },
        type: "fighting",
        power: null,
        accuracy: 100,
        pp: 20,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/67/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/447/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 447,
          name: {
            ru: "\u0420\u0438\u043E\u043B\u0443",
            en: "Riolu"
          }
        },
        {
          id: 448,
          name: {
            ru: "\u041B\u0443\u043A\u0430\u0440\u0438\u043E",
            en: "Lucario"
          }
        }
      ],
      edges: [
        {
          from: 447,
          to: 448,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0434\u043D\u0451\u043C",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during day"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 448,
    slug: "lucario",
    name: {
      ru: "\u041B\u0443\u043A\u0430\u0440\u0438\u043E",
      en: "Lucario"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D \u0430\u0443\u0440\u044B",
      en: "Aura Pok\xE9mon"
    },
    description: {
      ru: "\u0427\u0443\u0432\u0441\u0442\u0432\u0443\u0435\u0442 \u0438 \u043D\u0430\u043F\u0440\u0430\u0432\u043B\u044F\u0435\u0442 \u043E\u0441\u043E\u0431\u0443\u044E \u044D\u043D\u0435\u0440\u0433\u0438\u044E \u2014 \u0430\u0443\u0440\u0443. \u0415\u0451 \u0432\u043E\u043B\u043D\u044B \u043F\u043E\u043C\u043E\u0433\u0430\u044E\u0442 \u0435\u043C\u0443 \u0437\u0430\u043C\u0435\u0447\u0430\u0442\u044C \u0441\u0443\u0449\u0435\u0441\u0442\u0432 \u043D\u0430 \u0431\u043E\u043B\u044C\u0448\u043E\u043C \u0440\u0430\u0441\u0441\u0442\u043E\u044F\u043D\u0438\u0438.",
      en: "Lucario senses and controls aura, using its energy waves to detect beings far away."
    },
    habitat: "unknown",
    types: [
      "fighting",
      "steel"
    ],
    height: 1.2,
    weight: 54,
    stats: [
      70,
      110,
      70,
      115,
      70,
      90
    ],
    abilities: [
      {
        id: 80,
        slug: "steadfast",
        name: {
          ru: "\u0421\u0442\u043E\u0439\u043A\u043E\u0441\u0442\u044C",
          en: "Steadfast"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u043E\u0441\u043B\u0435 \u0438\u0441\u043F\u0443\u0433\u0430.",
          en: "Raises Speed after flinching."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/80/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 39,
        slug: "inner-focus",
        name: {
          ru: "\u0421\u043E\u0441\u0440\u0435\u0434\u043E\u0442\u043E\u0447\u0435\u043D\u043D\u043E\u0441\u0442\u044C",
          en: "Inner Focus"
        },
        description: {
          ru: "\u041D\u0435 \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u0435\u0442 \u0438\u0441\u043F\u0443\u0433\u0430\u0442\u044C\u0441\u044F \u0438 \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Prevents flinching."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/39/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 154,
        slug: "justified",
        name: {
          ru: "\u0421\u043F\u0440\u0430\u0432\u0435\u0434\u043B\u0438\u0432\u043E\u0441\u0442\u044C",
          en: "Justified"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0441\u0438\u043B\u0443 \u0430\u0442\u0430\u043A\u0438 \u043F\u043E\u0441\u043B\u0435 \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u044F \u0442\u0451\u043C\u043D\u043E\u0439 \u0430\u0442\u0430\u043A\u043E\u0439.",
          en: "Raises Attack after being hit by a Dark move."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/154/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 396,
        slug: "aura-sphere",
        name: {
          ru: "\u0421\u0444\u0435\u0440\u0430 \u0430\u0443\u0440\u044B",
          en: "Aura Sphere"
        },
        description: {
          ru: "\u0412\u044B\u043F\u0443\u0441\u043A\u0430\u0435\u0442 \u0441\u0433\u0443\u0441\u0442\u043E\u043A \u0430\u0443\u0440\u044B. \u0410\u0442\u0430\u043A\u0430 \u043D\u0435 \u043F\u0440\u043E\u043C\u0430\u0445\u0438\u0432\u0430\u0435\u0442\u0441\u044F.",
          en: "Fires a sphere of aura that cannot miss."
        },
        type: "fighting",
        power: 80,
        accuracy: null,
        pp: 20,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/396/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/448/"
        }
      },
      {
        id: 370,
        slug: "close-combat",
        name: {
          ru: "\u0411\u043B\u0438\u0436\u043D\u0438\u0439 \u0431\u043E\u0439",
          en: "Close Combat"
        },
        description: {
          ru: "\u041C\u043E\u0449\u043D\u0430\u044F \u0430\u0442\u0430\u043A\u0430 \u0432\u0431\u043B\u0438\u0437\u0438; \u043F\u043E\u0441\u043B\u0435 \u043D\u0435\u0451 \u0441\u043E\u0431\u0441\u0442\u0432\u0435\u043D\u043D\u0430\u044F \u0437\u0430\u0449\u0438\u0442\u0430 \u0441\u043D\u0438\u0436\u0430\u0435\u0442\u0441\u044F.",
          en: "A powerful close-range strike that lowers the user\u2019s defenses."
        },
        type: "fighting",
        power: 120,
        accuracy: 100,
        pp: 5,
        damageClass: "physical",
        priority: 0,
        effectChance: 100,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/370/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-raise"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 100
        },
        statChanges: [
          {
            stat: "defense",
            change: -1
          },
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/448/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 447,
          name: {
            ru: "\u0420\u0438\u043E\u043B\u0443",
            en: "Riolu"
          }
        },
        {
          id: 448,
          name: {
            ru: "\u041B\u0443\u043A\u0430\u0440\u0438\u043E",
            en: "Lucario"
          }
        }
      ],
      edges: [
        {
          from: 447,
          to: 448,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0434\u043D\u0451\u043C",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during day"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 462,
    slug: "magnezone",
    name: {
      ru: "\u041C\u0430\u0433\u043D\u0435\u0437\u043E\u043D",
      en: "Magnezone"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D \u043C\u0430\u0433\u043D\u0438\u0442\u043D\u043E\u0433\u043E \u043F\u043E\u043B\u044F",
      en: "Magnet Area Pok\xE9mon"
    },
    description: {
      ru: "\u042D\u0432\u043E\u043B\u044E\u0446\u0438\u044E \u0441\u0432\u044F\u0437\u044B\u0432\u0430\u044E\u0442 \u0441 \u043E\u0441\u043E\u0431\u044B\u043C \u043C\u0430\u0433\u043D\u0438\u0442\u043D\u044B\u043C \u043F\u043E\u043B\u0435\u043C. \u0410\u043D\u0442\u0435\u043D\u043D\u0430 \u043F\u043E\u0441\u044B\u043B\u0430\u0435\u0442 \u043D\u0435\u043E\u0431\u044B\u0447\u043D\u044B\u0435 \u0440\u0430\u0434\u0438\u043E\u0432\u043E\u043B\u043D\u044B \u0432 \u043A\u043E\u0441\u043C\u043E\u0441.",
      en: "A special magnetic field shaped its evolution; its antenna sends unusual radio signals into space."
    },
    habitat: "unknown",
    types: [
      "electric",
      "steel"
    ],
    height: 1.2,
    weight: 180,
    stats: [
      70,
      70,
      115,
      130,
      90,
      60
    ],
    abilities: [
      {
        id: 42,
        slug: "magnet-pull",
        name: {
          ru: "\u041C\u0430\u0433\u043D\u0438\u0442\u043D\u043E\u0435 \u043F\u0440\u0438\u0442\u044F\u0436\u0435\u043D\u0438\u0435",
          en: "Magnet Pull"
        },
        description: {
          ru: "\u041D\u0435 \u0434\u0430\u0451\u0442 \u0441\u0442\u0430\u043B\u044C\u043D\u044B\u043C \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430\u043C \u0441\u043C\u0435\u043D\u0438\u0442\u044C\u0441\u044F \u0438\u043B\u0438 \u0441\u0431\u0435\u0436\u0430\u0442\u044C.",
          en: "Traps opposing Steel Pok\xE9mon."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/42/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 5,
        slug: "sturdy",
        name: {
          ru: "\u041F\u0440\u043E\u0447\u043D\u043E\u0441\u0442\u044C",
          en: "Sturdy"
        },
        description: {
          ru: "\u041F\u0440\u0438 \u043F\u043E\u043B\u043D\u043E\u043C \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043F\u0435\u0440\u0435\u0436\u0438\u0432\u0430\u0435\u0442 \u0443\u0434\u0430\u0440, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u0438\u043D\u0430\u0447\u0435 \u0441\u0442\u0430\u043B \u0431\u044B \u043D\u043E\u043A\u0430\u0443\u0442\u043E\u043C.",
          en: "At full HP, survives a hit that would otherwise knock it out."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/5/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 148,
        slug: "analytic",
        name: {
          ru: "\u0410\u043D\u0430\u043B\u0438\u0442\u0438\u043A",
          en: "Analytic"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0430\u0442\u0430\u043A\u0438, \u043A\u043E\u0433\u0434\u0430 \u043F\u043E\u043A\u0435\u043C\u043E\u043D \u0445\u043E\u0434\u0438\u0442 \u043F\u043E\u0441\u043B\u0435\u0434\u043D\u0438\u043C.",
          en: "Boosts moves when the Pok\xE9mon acts last."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/148/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 85,
        slug: "thunderbolt",
        name: {
          ru: "\u0423\u0434\u0430\u0440 \u043C\u043E\u043B\u043D\u0438\u0438",
          en: "Thunderbolt"
        },
        description: {
          ru: "\u041C\u043E\u0449\u043D\u044B\u0439 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0439 \u0440\u0430\u0437\u0440\u044F\u0434 \u043C\u043E\u0436\u0435\u0442 \u043F\u0430\u0440\u0430\u043B\u0438\u0437\u043E\u0432\u0430\u0442\u044C \u0446\u0435\u043B\u044C.",
          en: "A strong electric bolt may paralyze the target."
        },
        type: "electric",
        power: 90,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/85/",
        meta: {
          ailment: {
            name: "paralysis"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/462/"
        }
      },
      {
        id: 430,
        slug: "flash-cannon",
        name: {
          ru: "\u0421\u0432\u0435\u0442\u043E\u0432\u0430\u044F \u043F\u0443\u0448\u043A\u0430",
          en: "Flash Cannon"
        },
        description: {
          ru: "\u041B\u0443\u0447 \u043D\u0430\u043A\u043E\u043F\u043B\u0435\u043D\u043D\u043E\u0439 \u044D\u043D\u0435\u0440\u0433\u0438\u0438 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443.",
          en: "Fires stored energy and may lower Special Defense."
        },
        type: "steel",
        power: 80,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/430/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 10
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/462/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 81,
          name: {
            ru: "\u041C\u0430\u0433\u043D\u0435\u043C\u0430\u0439\u0442",
            en: "Magnemite"
          }
        },
        {
          id: 82,
          name: {
            ru: "\u041C\u0430\u0433\u043D\u0435\u0442\u043E\u043D",
            en: "Magneton"
          }
        },
        {
          id: 462,
          name: {
            ru: "\u041C\u0430\u0433\u043D\u0435\u0437\u043E\u043D",
            en: "Magnezone"
          }
        }
      ],
      edges: [
        {
          from: 81,
          to: 82,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 30",
            en: "Level 30"
          },
          isDefault: true
        },
        {
          from: 82,
          to: 462,
          condition: {
            ru: "\u0413\u0440\u043E\u043C\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Thunder Stone"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 464,
    slug: "rhyperior",
    name: {
      ru: "\u0420\u0430\u0439\u043F\u0435\u0440\u0438\u043E\u0440",
      en: "Rhyperior"
    },
    genus: {
      ru: "\u0411\u0443\u0440\u044F\u0449\u0438\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Drill Pok\xE9mon"
    },
    description: {
      ru: "\u041A\u0430\u043C\u0435\u043D\u0438\u0441\u0442\u0430\u044F \u043A\u043E\u0436\u0430 \u043D\u0435\u0432\u0435\u0440\u043E\u044F\u0442\u043D\u043E \u043F\u0440\u043E\u0447\u043D\u0430 \u0438 \u0432\u044B\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u0442 \u0441\u0438\u043B\u044C\u043D\u044B\u0435 \u0443\u0434\u0430\u0440\u044B.",
      en: "Its stony hide is exceptionally durable and withstands heavy blows."
    },
    habitat: "unknown",
    types: [
      "ground",
      "rock"
    ],
    height: 2.4,
    weight: 282.8,
    stats: [
      115,
      140,
      130,
      55,
      55,
      40
    ],
    abilities: [
      {
        id: 31,
        slug: "lightning-rod",
        name: {
          ru: "\u0413\u0440\u043E\u043C\u043E\u043E\u0442\u0432\u043E\u0434",
          en: "Lightning Rod"
        },
        description: {
          ru: "\u041F\u0440\u0438\u0442\u044F\u0433\u0438\u0432\u0430\u0435\u0442 \u0438 \u043F\u043E\u0433\u043B\u043E\u0449\u0430\u0435\u0442 \u044D\u043B\u0435\u043A\u0442\u0440\u0438\u0447\u0435\u0441\u043A\u0438\u0435 \u0430\u0442\u0430\u043A\u0438, \u043F\u043E\u0432\u044B\u0448\u0430\u044F \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443.",
          en: "Draws in and absorbs Electric moves to raise Special Attack."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/31/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 116,
        slug: "solid-rock",
        name: {
          ru: "\u041F\u0440\u043E\u0447\u043D\u0430\u044F \u0441\u043A\u0430\u043B\u0430",
          en: "Solid Rock"
        },
        description: {
          ru: "\u0423\u043C\u0435\u043D\u044C\u0448\u0430\u0435\u0442 \u0443\u0440\u043E\u043D \u0441\u0443\u043F\u0435\u0440\u044D\u0444\u0444\u0435\u043A\u0442\u0438\u0432\u043D\u044B\u0445 \u0430\u0442\u0430\u043A.",
          en: "Reduces damage from super-effective attacks."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/116/",
        descriptionSource: "editorial-summary-of-core-ability"
      },
      {
        id: 120,
        slug: "reckless",
        name: {
          ru: "\u0411\u0435\u0437\u0440\u0430\u0441\u0441\u0443\u0434\u0441\u0442\u0432\u043E",
          en: "Reckless"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0430\u0442\u0430\u043A\u0438 \u0441 \u043E\u0442\u0434\u0430\u0447\u0435\u0439.",
          en: "Boosts moves that cause recoil damage."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/120/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 89,
        slug: "earthquake",
        name: {
          ru: "\u0417\u0435\u043C\u043B\u0435\u0442\u0440\u044F\u0441\u0435\u043D\u0438\u0435",
          en: "Earthquake"
        },
        description: {
          ru: "\u0421\u043E\u0442\u0440\u044F\u0441\u0430\u0435\u0442 \u0437\u0435\u043C\u043B\u044E \u043C\u043E\u0449\u043D\u043E\u0439 \u0443\u0434\u0430\u0440\u043D\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Shakes the ground with a powerful shock wave."
        },
        type: "ground",
        power: 100,
        accuracy: 100,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "all-other-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/89/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/464/"
        }
      },
      {
        id: 157,
        slug: "rock-slide",
        name: {
          ru: "\u041A\u0430\u043C\u043D\u0435\u043F\u0430\u0434",
          en: "Rock Slide"
        },
        description: {
          ru: "\u041E\u0431\u0440\u0443\u0448\u0438\u0432\u0430\u0435\u0442 \u043A\u0430\u043C\u043D\u0438; \u043C\u043E\u0436\u0435\u0442 \u0437\u0430\u0441\u0442\u0430\u0432\u0438\u0442\u044C \u0446\u0435\u043B\u044C \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Drops rocks onto the target and may cause flinching."
        },
        type: "rock",
        power: 75,
        accuracy: 90,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: 30,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/157/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 30,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/464/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 111,
          name: {
            ru: "\u0420\u0430\u0439\u0445\u043E\u0440\u043D",
            en: "Rhyhorn"
          }
        },
        {
          id: 112,
          name: {
            ru: "\u0420\u0430\u0439\u0434\u043E\u043D",
            en: "Rhydon"
          }
        },
        {
          id: 464,
          name: {
            ru: "\u0420\u0430\u0439\u043F\u0435\u0440\u0438\u043E\u0440",
            en: "Rhyperior"
          }
        }
      ],
      edges: [
        {
          from: 111,
          to: 112,
          condition: {
            ru: "\u0423\u0440\u043E\u0432\u0435\u043D\u044C 42",
            en: "Level 42"
          },
          isDefault: true
        },
        {
          from: 112,
          to: 464,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D \xB7 \u0441 \u043F\u0440\u0435\u0434\u043C\u0435\u0442\u043E\u043C \xAB\u0417\u0430\u0449\u0438\u0442\u043D\u0438\u043A\xBB",
            en: "Trade \xB7 holding Protector"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 470,
    slug: "leafeon",
    name: {
      ru: "\u041B\u0438\u0444\u0435\u043E\u043D",
      en: "Leafeon"
    },
    genus: {
      ru: "\u0417\u0435\u043B\u0435\u043D\u0435\u044E\u0449\u0438\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Verdant Pok\xE9mon"
    },
    description: {
      ru: "\u0412 \u0448\u0435\u0440\u0441\u0442\u0438 \u0435\u0441\u0442\u044C \u043A\u043B\u0435\u0442\u043A\u0438, \u043F\u043E\u0445\u043E\u0436\u0438\u0435 \u043D\u0430 \u0440\u0430\u0441\u0442\u0438\u0442\u0435\u043B\u044C\u043D\u044B\u0435. \u041E\u0441\u0442\u0440\u044B\u0439 \u0445\u0432\u043E\u0441\u0442 \u0441\u043F\u043E\u0441\u043E\u0431\u0435\u043D \u0441\u0440\u0443\u0431\u0438\u0442\u044C \u0434\u0435\u0440\u0435\u0432\u043E.",
      en: "Plant-like cells occur in its fur, and its sharp tail can cut down a tree."
    },
    habitat: "unknown",
    types: [
      "grass"
    ],
    height: 1,
    weight: 25.5,
    stats: [
      65,
      110,
      130,
      60,
      65,
      95
    ],
    abilities: [
      {
        id: 102,
        slug: "leaf-guard",
        name: {
          ru: "\u0417\u0430\u0449\u0438\u0442\u0430 \u043B\u0438\u0441\u0442\u0430",
          en: "Leaf Guard"
        },
        description: {
          ru: "\u042F\u0440\u043A\u0438\u0439 \u0441\u043E\u043B\u043D\u0435\u0447\u043D\u044B\u0439 \u0441\u0432\u0435\u0442 \u0437\u0430\u0449\u0438\u0449\u0430\u0435\u0442 \u043E\u0442 \u043F\u0440\u043E\u0431\u043B\u0435\u043C \u0441\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u044F.",
          en: "Strong sunlight prevents status conditions."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/102/",
        descriptionSource: "editorial-summary-of-core-ability"
      },
      {
        id: 34,
        slug: "chlorophyll",
        name: {
          ru: "\u0425\u043B\u043E\u0440\u043E\u0444\u0438\u043B\u043B",
          en: "Chlorophyll"
        },
        description: {
          ru: "\u0423\u0434\u0432\u0430\u0438\u0432\u0430\u0435\u0442 \u0441\u043A\u043E\u0440\u043E\u0441\u0442\u044C \u043F\u0440\u0438 \u044F\u0440\u043A\u043E\u043C \u0441\u043E\u043B\u043D\u0435\u0447\u043D\u043E\u043C \u0441\u0432\u0435\u0442\u0435.",
          en: "Doubles Speed in strong sunlight."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/34/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      }
    ],
    moves: [
      {
        id: 75,
        slug: "razor-leaf",
        name: {
          ru: "\u041E\u0441\u0442\u0440\u044B\u0435 \u043B\u0438\u0441\u0442\u044C\u044F",
          en: "Razor Leaf"
        },
        description: {
          ru: "\u0411\u0440\u043E\u0441\u0430\u0435\u0442 \u043E\u0441\u0442\u0440\u044B\u0435 \u043B\u0438\u0441\u0442\u044C\u044F; \u0448\u0430\u043D\u0441 \u043A\u0440\u0438\u0442\u0438\u0447\u0435\u0441\u043A\u043E\u0433\u043E \u043F\u043E\u043F\u0430\u0434\u0430\u043D\u0438\u044F \u0432\u044B\u0448\u0435.",
          en: "Throws sharp leaves with an increased critical-hit chance."
        },
        type: "grass",
        power: 55,
        accuracy: 95,
        pp: 25,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/75/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 1,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/470/"
        }
      },
      {
        id: 304,
        slug: "hyper-voice",
        name: {
          ru: "\u0413\u0438\u043F\u0435\u0440\u0433\u043E\u043B\u043E\u0441",
          en: "Hyper Voice"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0443\u0435\u0442 \u043C\u043E\u0449\u043D\u043E\u0439 \u0437\u0432\u0443\u043A\u043E\u0432\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Attacks with a powerful wave of sound."
        },
        type: "normal",
        power: 90,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/304/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/470/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 133,
          name: {
            ru: "\u0418\u0432\u0438",
            en: "Eevee"
          }
        },
        {
          id: 134,
          name: {
            ru: "\u0412\u0430\u043F\u043E\u0440\u0435\u043E\u043D",
            en: "Vaporeon"
          }
        },
        {
          id: 135,
          name: {
            ru: "\u0414\u0436\u043E\u043B\u0442\u0435\u043E\u043D",
            en: "Jolteon"
          }
        },
        {
          id: 136,
          name: {
            ru: "\u0424\u043B\u0430\u0440\u0435\u043E\u043D",
            en: "Flareon"
          }
        },
        {
          id: 196,
          name: {
            ru: "\u042D\u0441\u043F\u0435\u043E\u043D",
            en: "Espeon"
          }
        },
        {
          id: 197,
          name: {
            ru: "\u0410\u043C\u0431\u0440\u0435\u043E\u043D",
            en: "Umbreon"
          }
        },
        {
          id: 470,
          name: {
            ru: "\u041B\u0438\u0444\u0435\u043E\u043D",
            en: "Leafeon"
          }
        },
        {
          id: 471,
          name: {
            ru: "\u0413\u043B\u0430\u0441\u0435\u043E\u043D",
            en: "Glaceon"
          }
        },
        {
          id: 700,
          name: {
            ru: "\u0421\u0438\u043B\u044C\u0432\u0435\u043E\u043D",
            en: "Sylveon"
          }
        }
      ],
      edges: [
        {
          from: 133,
          to: 134,
          condition: {
            ru: "\u0412\u043E\u0434\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Water Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 135,
          condition: {
            ru: "\u0413\u0440\u043E\u043C\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Thunder Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 136,
          condition: {
            ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Fire Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 196,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0434\u043D\u0451\u043C",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during day"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 197,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u043D\u043E\u0447\u044C\u044E",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during night"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 470,
          condition: {
            ru: "\u041B\u0438\u0441\u0442\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Leaf Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 471,
          condition: {
            ru: "\u041B\u0435\u0434\u044F\u043D\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Ice Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 700,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0437\u043D\u0430\u0435\u0442 \u0432\u043E\u043B\u0448\u0435\u0431\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443",
            en: "Level up \xB7 friendship \u2265 160 \xB7 knows a Fairy move"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 471,
    slug: "glaceon",
    name: {
      ru: "\u0413\u043B\u0430\u0441\u0435\u043E\u043D",
      en: "Glaceon"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D \u0441\u0432\u0435\u0436\u0435\u0433\u043E \u0441\u043D\u0435\u0433\u0430",
      en: "Fresh Snow Pok\xE9mon"
    },
    description: {
      ru: "\u0411\u044B\u0441\u0442\u0440\u043E \u043E\u0445\u043B\u0430\u0436\u0434\u0430\u0435\u0442 \u0442\u0435\u043B\u043E \u0438 \u0437\u0430\u043C\u043E\u0440\u0430\u0436\u0438\u0432\u0430\u0435\u0442 \u0432\u043E\u0437\u0434\u0443\u0445, \u0441\u043E\u0437\u0434\u0430\u0432\u0430\u044F \u0441\u0432\u0435\u0440\u043A\u0430\u044E\u0449\u0443\u044E \u043B\u0435\u0434\u044F\u043D\u0443\u044E \u043F\u044B\u043B\u044C.",
      en: "It rapidly chills its body, freezing the surrounding air into sparkling ice crystals."
    },
    habitat: "unknown",
    types: [
      "ice"
    ],
    height: 0.8,
    weight: 25.9,
    stats: [
      65,
      60,
      110,
      130,
      95,
      65
    ],
    abilities: [
      {
        id: 81,
        slug: "snow-cloak",
        name: {
          ru: "\u0421\u043D\u0435\u0436\u043D\u0430\u044F \u0437\u0430\u0432\u0435\u0441\u0430",
          en: "Snow Cloak"
        },
        description: {
          ru: "\u041F\u043E\u0432\u044B\u0448\u0430\u0435\u0442 \u0443\u043A\u043B\u043E\u043D\u0435\u043D\u0438\u0435 \u043F\u0440\u0438 \u0433\u0440\u0430\u0434\u0435.",
          en: "Improves evasion in hail."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/81/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 115,
        slug: "ice-body",
        name: {
          ru: "\u041B\u0435\u0434\u044F\u043D\u043E\u0435 \u0442\u0435\u043B\u043E",
          en: "Ice Body"
        },
        description: {
          ru: "\u041F\u043E\u0441\u0442\u0435\u043F\u0435\u043D\u043D\u043E \u0432\u043E\u0441\u0441\u0442\u0430\u043D\u0430\u0432\u043B\u0438\u0432\u0430\u0435\u0442 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u0432 \u0441\u043D\u0435\u0436\u043D\u0443\u044E \u043F\u043E\u0433\u043E\u0434\u0443.",
          en: "Gradually restores HP in snowy weather."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/115/",
        descriptionSource: "editorial-summary-of-core-ability"
      }
    ],
    moves: [
      {
        id: 58,
        slug: "ice-beam",
        name: {
          ru: "\u041B\u0435\u0434\u044F\u043D\u043E\u0439 \u043B\u0443\u0447",
          en: "Ice Beam"
        },
        description: {
          ru: "\u0425\u043E\u043B\u043E\u0434\u043D\u044B\u0439 \u043B\u0443\u0447 \u043C\u043E\u0436\u0435\u0442 \u0437\u0430\u043C\u043E\u0440\u043E\u0437\u0438\u0442\u044C \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "An icy beam may freeze the target."
        },
        type: "ice",
        power: 90,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/58/",
        meta: {
          ailment: {
            name: "freeze"
          },
          category: {
            name: "damage-ailment"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 10,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/471/"
        }
      },
      {
        id: 304,
        slug: "hyper-voice",
        name: {
          ru: "\u0413\u0438\u043F\u0435\u0440\u0433\u043E\u043B\u043E\u0441",
          en: "Hyper Voice"
        },
        description: {
          ru: "\u0410\u0442\u0430\u043A\u0443\u0435\u0442 \u043C\u043E\u0449\u043D\u043E\u0439 \u0437\u0432\u0443\u043A\u043E\u0432\u043E\u0439 \u0432\u043E\u043B\u043D\u043E\u0439.",
          en: "Attacks with a powerful wave of sound."
        },
        type: "normal",
        power: 90,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: null,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/304/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/471/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 133,
          name: {
            ru: "\u0418\u0432\u0438",
            en: "Eevee"
          }
        },
        {
          id: 134,
          name: {
            ru: "\u0412\u0430\u043F\u043E\u0440\u0435\u043E\u043D",
            en: "Vaporeon"
          }
        },
        {
          id: 135,
          name: {
            ru: "\u0414\u0436\u043E\u043B\u0442\u0435\u043E\u043D",
            en: "Jolteon"
          }
        },
        {
          id: 136,
          name: {
            ru: "\u0424\u043B\u0430\u0440\u0435\u043E\u043D",
            en: "Flareon"
          }
        },
        {
          id: 196,
          name: {
            ru: "\u042D\u0441\u043F\u0435\u043E\u043D",
            en: "Espeon"
          }
        },
        {
          id: 197,
          name: {
            ru: "\u0410\u043C\u0431\u0440\u0435\u043E\u043D",
            en: "Umbreon"
          }
        },
        {
          id: 470,
          name: {
            ru: "\u041B\u0438\u0444\u0435\u043E\u043D",
            en: "Leafeon"
          }
        },
        {
          id: 471,
          name: {
            ru: "\u0413\u043B\u0430\u0441\u0435\u043E\u043D",
            en: "Glaceon"
          }
        },
        {
          id: 700,
          name: {
            ru: "\u0421\u0438\u043B\u044C\u0432\u0435\u043E\u043D",
            en: "Sylveon"
          }
        }
      ],
      edges: [
        {
          from: 133,
          to: 134,
          condition: {
            ru: "\u0412\u043E\u0434\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Water Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 135,
          condition: {
            ru: "\u0413\u0440\u043E\u043C\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Thunder Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 136,
          condition: {
            ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Fire Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 196,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0434\u043D\u0451\u043C",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during day"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 197,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u043D\u043E\u0447\u044C\u044E",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during night"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 470,
          condition: {
            ru: "\u041B\u0438\u0441\u0442\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Leaf Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 471,
          condition: {
            ru: "\u041B\u0435\u0434\u044F\u043D\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Ice Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 700,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0437\u043D\u0430\u0435\u0442 \u0432\u043E\u043B\u0448\u0435\u0431\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443",
            en: "Level up \xB7 friendship \u2265 160 \xB7 knows a Fairy move"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 700,
    slug: "sylveon",
    name: {
      ru: "\u0421\u0438\u043B\u044C\u0432\u0435\u043E\u043D",
      en: "Sylveon"
    },
    genus: {
      ru: "\u041F\u0435\u0440\u0435\u043F\u043B\u0435\u0442\u0430\u044E\u0449\u0438\u0439 \u043F\u043E\u043A\u0435\u043C\u043E\u043D",
      en: "Intertwining Pok\xE9mon"
    },
    description: {
      ru: "\u041B\u0435\u043D\u0442\u043E\u043E\u0431\u0440\u0430\u0437\u043D\u044B\u0435 \u043E\u0440\u0433\u0430\u043D\u044B \u0438\u0437\u043B\u0443\u0447\u0430\u044E\u0442 \u0443\u0441\u043F\u043E\u043A\u0430\u0438\u0432\u0430\u044E\u0449\u0443\u044E \u0430\u0443\u0440\u0443. \u041E\u0431\u0432\u0438\u0432\u0430\u044F \u0441\u043F\u043E\u0440\u044F\u0449\u0438\u0445, \u043F\u043E\u043C\u043E\u0433\u0430\u0435\u0442 \u0438\u043C \u0443\u0442\u0438\u0445\u043D\u0443\u0442\u044C.",
      en: "Its ribbon-like organs release a calming aura that settles quarrels when wrapped around others."
    },
    habitat: "unknown",
    types: [
      "fairy"
    ],
    height: 1,
    weight: 23.5,
    stats: [
      95,
      65,
      65,
      110,
      130,
      60
    ],
    abilities: [
      {
        id: 56,
        slug: "cute-charm",
        name: {
          ru: "\u041C\u0438\u043B\u043E\u0435 \u043E\u0447\u0430\u0440\u043E\u0432\u0430\u043D\u0438\u0435",
          en: "Cute Charm"
        },
        description: {
          ru: "\u041A\u043E\u043D\u0442\u0430\u043A\u0442\u043D\u0430\u044F \u0430\u0442\u0430\u043A\u0430 \u043C\u043E\u0436\u0435\u0442 \u0432\u043B\u044E\u0431\u0438\u0442\u044C \u0430\u0442\u0430\u043A\u0443\u044E\u0449\u0435\u0433\u043E \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Contact attacks may cause the attacker to become infatuated."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/56/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 182,
        slug: "pixilate",
        name: {
          ru: "\u0412\u043E\u043B\u0448\u0435\u0431\u043D\u0430\u044F \u043A\u043E\u0436\u0430",
          en: "Pixilate"
        },
        description: {
          ru: "\u041F\u0440\u0435\u0432\u0440\u0430\u0449\u0430\u0435\u0442 \u043E\u0431\u044B\u0447\u043D\u044B\u0435 \u0430\u0442\u0430\u043A\u0438 \u0432 \u0432\u043E\u043B\u0448\u0435\u0431\u043D\u044B\u0435 \u0438 \u0443\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0438\u0445.",
          en: "Turns Normal moves into Fairy moves and boosts their power."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/182/",
        descriptionSource: "editorial-summary-of-core-ability"
      }
    ],
    moves: [
      {
        id: 585,
        slug: "moonblast",
        name: {
          ru: "\u041B\u0443\u043D\u043D\u044B\u0439 \u0432\u0437\u0440\u044B\u0432",
          en: "Moonblast"
        },
        description: {
          ru: "\u0421\u0438\u043B\u0430 \u043B\u0443\u043D\u044B \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443 \u043F\u0440\u043E\u0442\u0438\u0432\u043D\u0438\u043A\u0430.",
          en: "Moonlight energy may lower the target\u2019s Special Attack."
        },
        type: "fairy",
        power: 95,
        accuracy: 100,
        pp: 15,
        damageClass: "special",
        priority: 0,
        effectChance: 30,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/585/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 30
        },
        statChanges: [
          {
            stat: "special-attack",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/700/"
        }
      },
      {
        id: 94,
        slug: "psychic",
        name: {
          ru: "\u041F\u0441\u0438\u0445\u043E\u043A\u0438\u043D\u0435\u0437",
          en: "Psychic"
        },
        description: {
          ru: "\u041F\u0441\u0438\u0445\u0438\u0447\u0435\u0441\u043A\u0430\u044F \u0441\u0438\u043B\u0430 \u043C\u043E\u0436\u0435\u0442 \u0441\u043D\u0438\u0437\u0438\u0442\u044C \u0441\u043F\u0435\u0446\u0438\u0430\u043B\u044C\u043D\u0443\u044E \u0437\u0430\u0449\u0438\u0442\u0443 \u0446\u0435\u043B\u0438.",
          en: "Psychic force may lower the target\u2019s Special Defense."
        },
        type: "psychic",
        power: 90,
        accuracy: 100,
        pp: 10,
        damageClass: "special",
        priority: 0,
        effectChance: 10,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/94/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage-lower"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 10
        },
        statChanges: [
          {
            stat: "special-defense",
            change: -1
          }
        ],
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/700/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 133,
          name: {
            ru: "\u0418\u0432\u0438",
            en: "Eevee"
          }
        },
        {
          id: 134,
          name: {
            ru: "\u0412\u0430\u043F\u043E\u0440\u0435\u043E\u043D",
            en: "Vaporeon"
          }
        },
        {
          id: 135,
          name: {
            ru: "\u0414\u0436\u043E\u043B\u0442\u0435\u043E\u043D",
            en: "Jolteon"
          }
        },
        {
          id: 136,
          name: {
            ru: "\u0424\u043B\u0430\u0440\u0435\u043E\u043D",
            en: "Flareon"
          }
        },
        {
          id: 196,
          name: {
            ru: "\u042D\u0441\u043F\u0435\u043E\u043D",
            en: "Espeon"
          }
        },
        {
          id: 197,
          name: {
            ru: "\u0410\u043C\u0431\u0440\u0435\u043E\u043D",
            en: "Umbreon"
          }
        },
        {
          id: 470,
          name: {
            ru: "\u041B\u0438\u0444\u0435\u043E\u043D",
            en: "Leafeon"
          }
        },
        {
          id: 471,
          name: {
            ru: "\u0413\u043B\u0430\u0441\u0435\u043E\u043D",
            en: "Glaceon"
          }
        },
        {
          id: 700,
          name: {
            ru: "\u0421\u0438\u043B\u044C\u0432\u0435\u043E\u043D",
            en: "Sylveon"
          }
        }
      ],
      edges: [
        {
          from: 133,
          to: 134,
          condition: {
            ru: "\u0412\u043E\u0434\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Water Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 135,
          condition: {
            ru: "\u0413\u0440\u043E\u043C\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Thunder Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 136,
          condition: {
            ru: "\u041E\u0433\u043D\u0435\u043D\u043D\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Fire Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 196,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0434\u043D\u0451\u043C",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during day"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 197,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u043D\u043E\u0447\u044C\u044E",
            en: "Level up \xB7 friendship \u2265 160 \xB7 during night"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 470,
          condition: {
            ru: "\u041B\u0438\u0441\u0442\u043E\u0432\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Leaf Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 471,
          condition: {
            ru: "\u041B\u0435\u0434\u044F\u043D\u043E\u0439 \u043A\u0430\u043C\u0435\u043D\u044C",
            en: "Ice Stone"
          },
          isDefault: true
        },
        {
          from: 133,
          to: 700,
          condition: {
            ru: "\u041F\u043E\u0432\u044B\u0448\u0435\u043D\u0438\u0435 \u0443\u0440\u043E\u0432\u043D\u044F \xB7 \u0434\u0440\u0443\u0436\u0431\u0430 \u2265 160 \xB7 \u0437\u043D\u0430\u0435\u0442 \u0432\u043E\u043B\u0448\u0435\u0431\u043D\u0443\u044E \u0430\u0442\u0430\u043A\u0443",
            en: "Level up \xB7 friendship \u2265 160 \xB7 knows a Fairy move"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  },
  {
    id: 900,
    slug: "kleavor",
    name: {
      ru: "\u041A\u043B\u0438\u0432\u043E\u0440",
      en: "Kleavor"
    },
    genus: {
      ru: "\u041F\u043E\u043A\u0435\u043C\u043E\u043D-\u0442\u043E\u043F\u043E\u0440",
      en: "Axe Pok\xE9mon"
    },
    description: {
      ru: "\u0413\u0440\u0443\u0431\u044B\u043C\u0438 \u0442\u043E\u043F\u043E\u0440\u0430\u043C\u0438 \u0440\u0443\u0431\u0438\u0442 \u0432\u044B\u0441\u043E\u043A\u0438\u0435 \u0434\u0435\u0440\u0435\u0432\u044C\u044F. \u0422\u0432\u0451\u0440\u0434\u044B\u0439 \u043A\u0430\u043C\u0435\u043D\u043D\u044B\u0439 \u043F\u043E\u043A\u0440\u043E\u0432 \u0441\u043B\u0443\u0436\u0438\u0442 \u0437\u0430\u0449\u0438\u0442\u043E\u0439.",
      en: "Its rugged axes fell tall trees, while a hard stone covering provides protection."
    },
    habitat: "unknown",
    types: [
      "bug",
      "rock"
    ],
    height: 1.8,
    weight: 89,
    stats: [
      70,
      135,
      95,
      45,
      70,
      85
    ],
    abilities: [
      {
        id: 68,
        slug: "swarm",
        name: {
          ru: "\u0420\u043E\u0439",
          en: "Swarm"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u043D\u0430\u0441\u0435\u043A\u043E\u043C\u044B\u0435 \u0430\u0442\u0430\u043A\u0438, \u043A\u043E\u0433\u0434\u0430 \u0437\u0434\u043E\u0440\u043E\u0432\u044C\u0435 \u043D\u0438\u0437\u043A\u043E\u0435.",
          en: "Boosts Bug moves when HP is low."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/68/",
        descriptionSource: "paraphrase-of-cached-api-effect"
      },
      {
        id: 125,
        slug: "sheer-force",
        name: {
          ru: "\u0413\u0440\u0443\u0431\u0430\u044F \u0441\u0438\u043B\u0430",
          en: "Sheer Force"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0430\u0442\u0430\u043A\u0438 \u0441 \u0434\u043E\u043F\u043E\u043B\u043D\u0438\u0442\u0435\u043B\u044C\u043D\u044B\u043C\u0438 \u044D\u0444\u0444\u0435\u043A\u0442\u0430\u043C\u0438, \u0443\u0431\u0438\u0440\u0430\u044F \u044D\u0442\u0438 \u044D\u0444\u0444\u0435\u043A\u0442\u044B.",
          en: "Boosts moves with secondary effects while removing those effects."
        },
        hidden: false,
        sourceUrl: "https://pokeapi.co/api/v2/ability/125/",
        descriptionSource: "editorial-summary-of-core-ability"
      },
      {
        id: 292,
        slug: "sharpness",
        name: {
          ru: "\u041E\u0441\u0442\u0440\u043E\u0442\u0430",
          en: "Sharpness"
        },
        description: {
          ru: "\u0423\u0441\u0438\u043B\u0438\u0432\u0430\u0435\u0442 \u0440\u0435\u0436\u0443\u0449\u0438\u0435 \u0430\u0442\u0430\u043A\u0438.",
          en: "Boosts slicing moves."
        },
        hidden: true,
        sourceUrl: "https://pokeapi.co/api/v2/ability/292/",
        descriptionSource: "editorial-summary-of-core-ability"
      }
    ],
    moves: [
      {
        id: 404,
        slug: "x-scissor",
        name: {
          ru: "\u041A\u0440\u0435\u0441\u0442-\u043D\u043E\u0436\u043D\u0438\u0446\u044B",
          en: "X-Scissor"
        },
        description: {
          ru: "\u041F\u0435\u0440\u0435\u043A\u0440\u0435\u0449\u0438\u0432\u0430\u0435\u0442 \u043B\u0435\u0437\u0432\u0438\u044F \u0438 \u043D\u0430\u043D\u043E\u0441\u0438\u0442 \u0440\u0435\u0436\u0443\u0449\u0438\u0439 \u0443\u0434\u0430\u0440.",
          en: "Crosses its blades to deliver a slashing strike."
        },
        type: "bug",
        power: 80,
        accuracy: 100,
        pp: 15,
        damageClass: "physical",
        priority: 0,
        effectChance: null,
        target: "selected-pokemon",
        sourceUrl: "https://pokeapi.co/api/v2/move/404/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 0,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/900/"
        }
      },
      {
        id: 157,
        slug: "rock-slide",
        name: {
          ru: "\u041A\u0430\u043C\u043D\u0435\u043F\u0430\u0434",
          en: "Rock Slide"
        },
        description: {
          ru: "\u041E\u0431\u0440\u0443\u0448\u0438\u0432\u0430\u0435\u0442 \u043A\u0430\u043C\u043D\u0438; \u043C\u043E\u0436\u0435\u0442 \u0437\u0430\u0441\u0442\u0430\u0432\u0438\u0442\u044C \u0446\u0435\u043B\u044C \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0445\u043E\u0434.",
          en: "Drops rocks onto the target and may cause flinching."
        },
        type: "rock",
        power: 75,
        accuracy: 90,
        pp: 10,
        damageClass: "physical",
        priority: 0,
        effectChance: 30,
        target: "all-opponents",
        sourceUrl: "https://pokeapi.co/api/v2/move/157/",
        meta: {
          ailment: {
            name: "none"
          },
          category: {
            name: "damage"
          },
          min_hits: null,
          max_hits: null,
          min_turns: null,
          max_turns: null,
          drain: 0,
          healing: 0,
          crit_rate: 0,
          ailment_chance: 0,
          flinch_chance: 30,
          stat_chance: 0
        },
        learnSource: {
          kind: "pokemon-learnset",
          sourceUrl: "https://pokeapi.co/api/v2/pokemon/900/"
        }
      }
    ],
    evolution: {
      nodes: [
        {
          id: 123,
          name: {
            ru: "\u0421\u043A\u0430\u0439\u0442\u0435\u0440",
            en: "Scyther"
          }
        },
        {
          id: 212,
          name: {
            ru: "\u0421\u0438\u0437\u043E\u0440",
            en: "Scizor"
          }
        },
        {
          id: 900,
          name: {
            ru: "\u041A\u043B\u0438\u0432\u043E\u0440",
            en: "Kleavor"
          }
        }
      ],
      edges: [
        {
          from: 123,
          to: 212,
          condition: {
            ru: "\u041E\u0431\u043C\u0435\u043D \xB7 \u0441 \u043F\u0440\u0435\u0434\u043C\u0435\u0442\u043E\u043C \xAB\u041C\u0435\u0442\u0430\u043B\u043B\u0438\u0447\u0435\u0441\u043A\u043E\u0435 \u043F\u043E\u043A\u0440\u044B\u0442\u0438\u0435\xBB",
            en: "Trade \xB7 holding Metal Coat"
          },
          isDefault: true
        },
        {
          from: 123,
          to: 900,
          condition: {
            ru: "\u0427\u0451\u0440\u043D\u044B\u0439 \u0430\u0432\u0433\u0443\u0440\u0438\u0442",
            en: "Black Augurite"
          },
          isDefault: true
        }
      ]
    },
    isLegendary: false,
    isMythical: false,
    classification: "ordinary"
  }
];

// site/server/source/lib/pokemon.ts
var pokemon = catalog_default;
var byId = new Map(pokemon.map((p) => [p.id, p]));

// site/server/source/data/type-chart.json
var type_chart_default = {
  normal: {
    normal: 1,
    fighting: 1,
    flying: 1,
    poison: 1,
    ground: 1,
    rock: 0.5,
    bug: 1,
    ghost: 0,
    steel: 0.5,
    fire: 1,
    water: 1,
    grass: 1,
    electric: 1,
    psychic: 1,
    ice: 1,
    dragon: 1,
    dark: 1,
    fairy: 1
  },
  fighting: {
    normal: 2,
    fighting: 1,
    flying: 0.5,
    poison: 0.5,
    ground: 1,
    rock: 2,
    bug: 0.5,
    ghost: 0,
    steel: 2,
    fire: 1,
    water: 1,
    grass: 1,
    electric: 1,
    psychic: 0.5,
    ice: 2,
    dragon: 1,
    dark: 2,
    fairy: 0.5
  },
  flying: {
    normal: 1,
    fighting: 2,
    flying: 1,
    poison: 1,
    ground: 1,
    rock: 0.5,
    bug: 2,
    ghost: 1,
    steel: 0.5,
    fire: 1,
    water: 1,
    grass: 2,
    electric: 0.5,
    psychic: 1,
    ice: 1,
    dragon: 1,
    dark: 1,
    fairy: 1
  },
  poison: {
    normal: 1,
    fighting: 1,
    flying: 1,
    poison: 0.5,
    ground: 0.5,
    rock: 0.5,
    bug: 1,
    ghost: 0.5,
    steel: 0,
    fire: 1,
    water: 1,
    grass: 2,
    electric: 1,
    psychic: 1,
    ice: 1,
    dragon: 1,
    dark: 1,
    fairy: 2
  },
  ground: {
    normal: 1,
    fighting: 1,
    flying: 0,
    poison: 2,
    ground: 1,
    rock: 2,
    bug: 0.5,
    ghost: 1,
    steel: 2,
    fire: 2,
    water: 1,
    grass: 0.5,
    electric: 2,
    psychic: 1,
    ice: 1,
    dragon: 1,
    dark: 1,
    fairy: 1
  },
  rock: {
    normal: 1,
    fighting: 0.5,
    flying: 2,
    poison: 1,
    ground: 0.5,
    rock: 1,
    bug: 2,
    ghost: 1,
    steel: 0.5,
    fire: 2,
    water: 1,
    grass: 1,
    electric: 1,
    psychic: 1,
    ice: 2,
    dragon: 1,
    dark: 1,
    fairy: 1
  },
  bug: {
    normal: 1,
    fighting: 0.5,
    flying: 0.5,
    poison: 0.5,
    ground: 1,
    rock: 1,
    bug: 1,
    ghost: 0.5,
    steel: 0.5,
    fire: 0.5,
    water: 1,
    grass: 2,
    electric: 1,
    psychic: 2,
    ice: 1,
    dragon: 1,
    dark: 2,
    fairy: 0.5
  },
  ghost: {
    normal: 0,
    fighting: 1,
    flying: 1,
    poison: 1,
    ground: 1,
    rock: 1,
    bug: 1,
    ghost: 2,
    steel: 1,
    fire: 1,
    water: 1,
    grass: 1,
    electric: 1,
    psychic: 2,
    ice: 1,
    dragon: 1,
    dark: 0.5,
    fairy: 1
  },
  steel: {
    normal: 1,
    fighting: 1,
    flying: 1,
    poison: 1,
    ground: 1,
    rock: 2,
    bug: 1,
    ghost: 1,
    steel: 0.5,
    fire: 0.5,
    water: 0.5,
    grass: 1,
    electric: 0.5,
    psychic: 1,
    ice: 2,
    dragon: 1,
    dark: 1,
    fairy: 2
  },
  fire: {
    normal: 1,
    fighting: 1,
    flying: 1,
    poison: 1,
    ground: 1,
    rock: 0.5,
    bug: 2,
    ghost: 1,
    steel: 2,
    fire: 0.5,
    water: 0.5,
    grass: 2,
    electric: 1,
    psychic: 1,
    ice: 2,
    dragon: 0.5,
    dark: 1,
    fairy: 1
  },
  water: {
    normal: 1,
    fighting: 1,
    flying: 1,
    poison: 1,
    ground: 2,
    rock: 2,
    bug: 1,
    ghost: 1,
    steel: 1,
    fire: 2,
    water: 0.5,
    grass: 0.5,
    electric: 1,
    psychic: 1,
    ice: 1,
    dragon: 0.5,
    dark: 1,
    fairy: 1
  },
  grass: {
    normal: 1,
    fighting: 1,
    flying: 0.5,
    poison: 0.5,
    ground: 2,
    rock: 2,
    bug: 0.5,
    ghost: 1,
    steel: 0.5,
    fire: 0.5,
    water: 2,
    grass: 0.5,
    electric: 1,
    psychic: 1,
    ice: 1,
    dragon: 0.5,
    dark: 1,
    fairy: 1
  },
  electric: {
    normal: 1,
    fighting: 1,
    flying: 2,
    poison: 1,
    ground: 0,
    rock: 1,
    bug: 1,
    ghost: 1,
    steel: 1,
    fire: 1,
    water: 2,
    grass: 0.5,
    electric: 0.5,
    psychic: 1,
    ice: 1,
    dragon: 0.5,
    dark: 1,
    fairy: 1
  },
  psychic: {
    normal: 1,
    fighting: 2,
    flying: 1,
    poison: 2,
    ground: 1,
    rock: 1,
    bug: 1,
    ghost: 1,
    steel: 0.5,
    fire: 1,
    water: 1,
    grass: 1,
    electric: 1,
    psychic: 0.5,
    ice: 1,
    dragon: 1,
    dark: 0,
    fairy: 1
  },
  ice: {
    normal: 1,
    fighting: 1,
    flying: 2,
    poison: 1,
    ground: 2,
    rock: 1,
    bug: 1,
    ghost: 1,
    steel: 0.5,
    fire: 0.5,
    water: 0.5,
    grass: 2,
    electric: 1,
    psychic: 1,
    ice: 0.5,
    dragon: 2,
    dark: 1,
    fairy: 1
  },
  dragon: {
    normal: 1,
    fighting: 1,
    flying: 1,
    poison: 1,
    ground: 1,
    rock: 1,
    bug: 1,
    ghost: 1,
    steel: 0.5,
    fire: 1,
    water: 1,
    grass: 1,
    electric: 1,
    psychic: 1,
    ice: 1,
    dragon: 2,
    dark: 1,
    fairy: 0
  },
  dark: {
    normal: 1,
    fighting: 0.5,
    flying: 1,
    poison: 1,
    ground: 1,
    rock: 1,
    bug: 1,
    ghost: 2,
    steel: 1,
    fire: 1,
    water: 1,
    grass: 1,
    electric: 1,
    psychic: 2,
    ice: 1,
    dragon: 1,
    dark: 0.5,
    fairy: 0.5
  },
  fairy: {
    normal: 1,
    fighting: 2,
    flying: 1,
    poison: 0.5,
    ground: 1,
    rock: 1,
    bug: 1,
    ghost: 1,
    steel: 0.5,
    fire: 0.5,
    water: 1,
    grass: 1,
    electric: 1,
    psychic: 1,
    ice: 1,
    dragon: 2,
    dark: 2,
    fairy: 1
  }
};

// site/server/source/server/battle.ts
var chart = type_chart_default;
function random() {
  return crypto.getRandomValues(new Uint32Array(1))[0] / 4294967296;
}
function choose(items, rng = random) {
  if (!items.length) throw new Error("Empty reward pool");
  return items[Math.floor(rng() * items.length)];
}
function makeSide(id, username, ids) {
  return { id, username, active: 0, team: ids.map((id2) => {
    const p = byId.get(id2);
    return { id: id2, formId: id2, hp: p.stats[0] + 60, maxHp: p.stats[0] + 60, pp: p.moves.map((m) => m.pp || 15) };
  }) };
}
function active(side) {
  return side.team[side.active];
}
function fighterMoves(fighter) {
  return byId.get(fighter.formId).moves;
}
var struggle = { id: 165, slug: "struggle", name: { ru: "\u0411\u043E\u0440\u044C\u0431\u0430", en: "Struggle" }, description: { ru: "\u041F\u043E\u0441\u043B\u0435\u0434\u043D\u044F\u044F \u0430\u0442\u0430\u043A\u0430 \u0441 \u043E\u0442\u0434\u0430\u0447\u0435\u0439, \u043A\u043E\u0433\u0434\u0430 \u043D\u0435\u0442 PP.", en: "A last-resort attack with recoil when PP is depleted." }, type: "normal", power: 50, accuracy: null, pp: 1, priority: 0, damageClass: "physical" };
function availableMoves(fighter) {
  return fighter.pp.every((n) => n === 0) ? [struggle] : fighterMoves(fighter);
}
function validOrder(state, side, order) {
  if (!order || !Number.isInteger(order.index)) return false;
  const player = state.sides[side];
  if (order.kind === "switch") return order.index >= 0 && order.index < player.team.length && order.index !== player.active && player.team[order.index].hp > 0;
  if (order.kind === "attack") return order.index >= 0 && order.index < availableMoves(active(player)).length && (active(player).pp.every((n) => n === 0) || active(player).pp[order.index] > 0);
  return false;
}
function typeMultiplier(type, defenders) {
  return defenders.reduce((m, t) => m * (chart[type]?.[t] ?? 1), 1);
}
function movePower(attacker, defender, move) {
  if (move.id === 67) {
    const weight = byId.get(defender.formId).weight;
    return weight < 10 ? 20 : weight < 25 ? 40 : weight < 50 ? 60 : weight < 100 ? 80 : weight < 200 ? 100 : 120;
  }
  if (move.id === 175) {
    const ratio = Math.floor(64 * attacker.hp / attacker.maxHp);
    return ratio <= 1 ? 200 : ratio <= 5 ? 150 : ratio <= 12 ? 100 : ratio <= 21 ? 80 : ratio <= 42 ? 40 : 20;
  }
  return move.power ?? 60;
}
function calculateDamage(attacker, defender, move, rng = random) {
  const a = byId.get(attacker.formId), d = byId.get(defender.formId);
  const special = move.damageClass === "special";
  const power = movePower(attacker, defender, move);
  const effectiveness = move.id === 165 ? 1 : typeMultiplier(move.type, d.types);
  if (effectiveness === 0) return { damage: 0, effectiveness };
  if (move.id === 82) return { damage: 40, effectiveness: 1 };
  const base = Math.floor(Math.floor(22 * power * (a.stats[special ? 3 : 1] + 5) / (d.stats[special ? 4 : 2] + 5)) / 50) + 2;
  const stab = move.id !== 165 && a.types.includes(move.type) ? 1.5 : 1;
  return { damage: Math.max(1, Math.floor(base * stab * effectiveness * (0.85 + rng() * 0.15))), effectiveness };
}
function resolveRound(input, rng = random, now = Date.now()) {
  const s = structuredClone(input);
  const event = (value) => s.logs.push({ ...value, id: crypto.randomUUID(), round: s.round });
  const starting = s.sides.map((x) => x.active);
  const priority = (i) => {
    const o = s.orders[i];
    if (o?.kind === "switch") return 6;
    if (o?.kind === "attack") return availableMoves(active(s.sides[i]))[o.index]?.priority ?? 0;
    return -10;
  };
  const speed = (i) => byId.get(active(s.sides[i]).formId).stats[5];
  const order = [0, 1].sort((a, b) => priority(b) - priority(a) || speed(b) - speed(a) || (rng() < 0.5 ? -1 : 1));
  for (const i of order) {
    if (s.winner) break;
    const side = s.sides[i], enemy = s.sides[1 - i], command = s.orders[i];
    if (!command || command.kind === "pass") {
      event({ kind: "pass", actor: i });
      continue;
    }
    if (command.kind === "switch") {
      if (side.team[command.index].hp > 0) {
        side.active = command.index;
        event({ kind: "switch", actor: i, pokemonId: active(side).formId });
      }
      continue;
    }
    if (side.active !== starting[i] || active(side).hp <= 0) continue;
    const actor = active(side), target = active(enemy), moves = availableMoves(actor), move = moves[command.index];
    if (!move) continue;
    const exhausted = actor.pp.every((n) => n === 0);
    if (!exhausted) {
      if (actor.pp[command.index] <= 0) continue;
      actor.pp[command.index]--;
    }
    if (move.slug === "transform" || move.id === 144) {
      actor.formId = target.formId;
      actor.pp = fighterMoves(target).map(() => 5);
      event({ kind: "transform", actor: i, pokemonId: actor.id, targetId: target.formId, move });
      continue;
    }
    const miss = move.accuracy !== null && rng() * 100 >= move.accuracy;
    const result = miss ? { damage: 0, effectiveness: 1 } : calculateDamage(actor, target, move, rng);
    const damage = Math.min(target.hp, result.damage);
    target.hp -= damage;
    event({ kind: "attack", actor: i, pokemonId: actor.formId, targetId: target.formId, move, damage, effectiveness: result.effectiveness, miss });
    if (!miss && move.meta?.drain && damage > 0) actor.hp = Math.min(actor.maxHp, Math.max(0, actor.hp + Math.ceil(damage * move.meta.drain / 100)));
    if (move.id === 165) actor.hp = Math.max(0, actor.hp - Math.max(1, Math.floor(actor.maxHp / 4)));
    for (const j of [1 - i, i]) {
      const x = s.sides[j];
      if (active(x).hp === 0) {
        event({ kind: "faint", actor: j, pokemonId: active(x).formId });
        const next = x.team.findIndex((p) => p.hp > 0);
        if (next >= 0) x.active = next;
      }
    }
    const alive = s.sides.map((x) => x.team.some((p) => p.hp > 0));
    if (!alive[0] || !alive[1]) {
      s.winner = alive[0] ? s.sides[0].id : alive[1] ? s.sides[1].id : null;
      s.reason = alive.some(Boolean) ? "knockout" : "draw";
      event({ kind: "end", actor: alive[0] ? 0 : 1 });
      break;
    }
  }
  s.logs = s.logs.slice(-40);
  s.orders = [null, null];
  s.round++;
  s.deadline = now + 12e4;
  return s;
}

// site/server/source/server/trainer-service.ts
var DAY = 864e5;
var covers = ["forest", "water", "mountain", "grassland", "cave", "urban", "unknown"];
async function trainerDetails(p, cards) {
  const db = gameDb();
  await db.prepare("INSERT OR IGNORE INTO trainer_profiles (player_id,avatar) VALUES (?,?)").bind(p.id, cards[0]?.id || 25).run();
  const t = await db.prepare("SELECT * FROM trainer_profiles WHERE player_id=?").bind(p.id).first();
  const xp = t.xp + p.wins * 40 + p.losses * 10 + cards.length * 10;
  return { trainer: { avatar: t.avatar, cover: t.cover, favorites: JSON.parse(t.favorites), xp, level: 1 + Math.floor(xp / 100), pveWins: t.pve_wins, evolutions: t.evolutions } };
}
function practiceOrder(state) {
  const bot = state.sides[1], enemy = state.sides[0], fighter = active(bot), target = active(enemy), moves = availableMoves(fighter);
  const valid = moves.map((m, i) => ({ m, i })).filter((x) => fighter.pp.every((n) => n === 0) || fighter.pp[x.i] > 0);
  if (state.practice === "easy" || state.practice === "normal" && random() < 0.25) return { kind: "attack", index: valid[Math.floor(random() * valid.length)].i };
  const score = (form) => Math.max(...availableMoves(form).filter((m, i) => form.pp.every((n) => n === 0) || form.pp[i] > 0).map((m) => m.id === 144 ? 20 : calculateDamage(form, target, m, () => 1).damage * (m.accuracy ?? 100) / 100));
  if (state.practice === "hard" && score(fighter) === 0) {
    const i = bot.team.findIndex((f, i2) => i2 !== bot.active && f.hp > 0 && score(f) > 0);
    if (i >= 0) return { kind: "switch", index: i };
  }
  valid.sort((a, b) => calculateDamage(fighter, target, b.m, () => 1).damage * (b.m.accuracy ?? 100) - calculateDamage(fighter, target, a.m, () => 1).damage * (a.m.accuracy ?? 100));
  return { kind: "attack", index: valid[0].i };
}
function seasonBounds(offset = 0) {
  const d = /* @__PURE__ */ new Date(), start = Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + offset, 1), end = Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + offset + 1, 1);
  return { id: new Date(start).toISOString().slice(0, 7), start: Math.floor(start / DAY), end: Math.floor(end / DAY), endsAt: end };
}
async function ranking(offset = 0) {
  const season = seasonBounds(offset);
  const rows = await gameDb().prepare(`SELECT p.id,p.username,COALESCE(t.avatar,25) AS avatar,SUM(CASE WHEN b.won=1 THEN 1 ELSE 0 END) AS wins,SUM(CASE WHEN b.won=0 THEN 1 ELSE 0 END) AS losses,MAX(0,SUM(CASE WHEN b.won=1 THEN 25 WHEN b.won=0 THEN -10 ELSE 0 END)) AS points FROM battle_rewards b JOIN players p ON p.id=b.player_id LEFT JOIN trainer_profiles t ON t.player_id=p.id WHERE b.day>=? AND b.day<? AND b.won>=0 GROUP BY p.id ORDER BY points DESC,wins DESC,p.created_at LIMIT 50`).bind(season.start, season.end).all();
  return { season, players: rows.results.map((r, i) => ({ ...r, rank: i + 1, league: r.points >= 500 ? "legend" : r.points >= 250 ? "gold" : r.points >= 100 ? "silver" : "bronze" })) };
}
async function tasks(p) {
  const db = gameDb(), day = Math.floor(Date.now() / DAY), cards = (await db.prepare("SELECT COUNT(*) AS n FROM cards WHERE player_id=?").bind(p.id).first()).n;
  const t = await db.prepare("SELECT * FROM trainer_profiles WHERE player_id=?").bind(p.id).first();
  const expedition = !!await db.prepare("SELECT id FROM claims WHERE player_id=? AND kind='expedition' AND created_at>=?").bind(p.id, day * DAY).first();
  const duel = !!await db.prepare("SELECT room_code FROM battle_rewards WHERE player_id=? AND day=? AND won>=0").bind(p.id, day).first();
  const practice = !!await db.prepare("SELECT room_code FROM practice_results WHERE player_id=? AND day=? AND won=1").bind(p.id, day).first();
  const definitions = [{ id: `daily:${day}:explore`, name: "explore", done: expedition, coins: 20, xp: 25, daily: true }, { id: `daily:${day}:duel`, name: "duel", done: duel, coins: 25, xp: 30, daily: true }, { id: `daily:${day}:practice`, name: "practice", done: practice, coins: 20, xp: 25, daily: true }, { id: "achievement:collector", name: "collector", done: cards >= 10, coins: 60, xp: 50, daily: false }, { id: "achievement:winner", name: "winner", done: p.wins >= 1, coins: 50, xp: 50, daily: false }, { id: "achievement:veteran", name: "veteran", done: p.wins >= 10, coins: 150, xp: 100, daily: false }, { id: "achievement:evolve", name: "evolve", done: t.evolutions >= 1, coins: 50, xp: 50, daily: false }, { id: "achievement:practice", name: "botmaster", done: t.pve_wins >= 3, coins: 60, xp: 50, daily: false }];
  const claims = await db.prepare("SELECT id FROM claims WHERE player_id=? AND kind='task'").bind(p.id).all();
  return definitions.map((t2) => ({ ...t2, claimed: claims.results.some((c) => c.id === `${p.id}:${t2.id}`) }));
}
async function rewardClaim(p, id, kind, coins, xp) {
  const db = gameDb(), nonce = crypto.randomUUID();
  const result = await db.batch([
    db.prepare("UPDATE players SET credits=credits+?,version=version+1,last_operation=? WHERE id=? AND version=? AND NOT EXISTS(SELECT 1 FROM claims WHERE id=?)").bind(coins, nonce, p.id, p.version, id),
    db.prepare("INSERT INTO claims (id,player_id,kind,result,created_at) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM players WHERE id=? AND last_operation=?)").bind(id, p.id, kind, JSON.stringify({ coins, xp }), Date.now(), p.id, nonce),
    db.prepare("UPDATE trainer_profiles SET xp=xp+? WHERE player_id=? AND EXISTS(SELECT 1 FROM players WHERE id=? AND last_operation=?)").bind(xp, p.id, p.id, nonce)
  ]);
  if (!result[0].meta.changes) {
    if (await db.prepare("SELECT id FROM claims WHERE id=?").bind(id).first()) return;
    throw new GameError("conflict", 409);
  }
}
async function social(p) {
  const db = gameDb();
  const friends = await db.prepare(`SELECT CASE WHEN f.a=? THEN f.b ELSE f.a END AS id,p.username,COALESCE(t.avatar,25) AS avatar,f.status,f.requester FROM friendships f JOIN players p ON p.id=CASE WHEN f.a=? THEN f.b ELSE f.a END LEFT JOIN trainer_profiles t ON t.player_id=p.id WHERE f.a=? OR f.b=? ORDER BY f.created_at DESC`).bind(p.id, p.id, p.id, p.id).all();
  const invites = await db.prepare(`SELECT i.id,i.room_code AS code,p.username,i.sender,i.receiver FROM duel_invites i JOIN players p ON p.id=i.sender JOIN rooms r ON r.code=i.room_code WHERE i.receiver=? AND i.status='pending' AND i.expires_at>? AND r.status='waiting'`).bind(p.id, Date.now()).all();
  return { friends: friends.results, invites: invites.results };
}
async function extraGame(path, req, p, body, c) {
  const db = gameDb();
  if (path === "ranking") return ranking();
  if (path === "club") {
    await trainerDetails(p, []);
    const current = await ranking(), previous = await ranking(-1), rank = previous.players.find((x) => x.id === p.id);
    const coins = rank && rank.points > 0 ? rank.rank === 1 ? 300 : rank.rank <= 3 ? 200 : rank.rank <= 10 ? 100 : 0 : 0;
    const claimed = !!await db.prepare("SELECT id FROM claims WHERE id=?").bind(`${p.id}:season:${previous.season.id}`).first();
    return { ...await social(p), tasks: await tasks(p), ranking: current, seasonReward: { id: previous.season.id, coins, claimed } };
  }
  if (!body) return void 0;
  if (path === "trainer") {
    const owned = await db.prepare("SELECT pokemon_id AS id FROM cards WHERE player_id=?").bind(p.id).all();
    if (!Number.isInteger(body.avatar) || !owned.results.some((x) => x.id === body.avatar) || !covers.includes(String(body.cover)) || !Array.isArray(body.favorites) || body.favorites.length > 3 || new Set(body.favorites).size !== body.favorites.length || body.favorites.some((id) => !owned.results.some((x) => x.id === id))) throw new GameError("request");
    await trainerDetails(p, owned.results);
    await db.batch([db.prepare("UPDATE trainer_profiles SET avatar=?,cover=?,favorites=? WHERE player_id=?").bind(body.avatar, String(body.cover), JSON.stringify(body.favorites), p.id), db.prepare("UPDATE players SET version=version+1 WHERE id=?").bind(p.id)]);
    return { profile: await c.profile(p.id) };
  }
  if (path === "evolve") {
    const from = Number(body.from), to = Number(body.to), mon = byId.get(from);
    if (typeof body.key !== "string" || !/^[a-f0-9-]{36}$/i.test(body.key)) throw new GameError("request");
    const id = `${p.id}:evolve:${body.key}`, previous = await db.prepare("SELECT result FROM claims WHERE id=?").bind(id).first();
    if (previous) {
      const reward2 = JSON.parse(previous.result);
      if (reward2.fromId !== from || reward2.pokemonId !== to) throw new GameError("request");
      return { reward: reward2, profile: await c.profile(p.id) };
    }
    if (!mon?.evolution.edges.some((e) => e.from === from && e.to === to) || !byId.has(to)) throw new GameError("evolution");
    if (!await db.prepare("SELECT pokemon_id FROM cards WHERE player_id=? AND pokemon_id=?").bind(p.id, from).first()) throw new GameError("ownership", 403);
    if (await db.prepare("SELECT pokemon_id FROM cards WHERE player_id=? AND pokemon_id=?").bind(p.id, to).first()) throw new GameError("owned", 409);
    if (p.credits < 150) throw new GameError("evolveCoins", 409);
    await trainerDetails(p, []);
    const nonce = crypto.randomUUID(), reward = { pokemonId: to, fromId: from, duplicate: false, coins: 0, kind: "evolution" };
    const result = await db.batch([
      db.prepare("UPDATE players SET credits=credits-150,version=version+1,last_operation=? WHERE id=? AND version=? AND credits>=150 AND NOT EXISTS(SELECT 1 FROM cards WHERE player_id=? AND pokemon_id=?) AND NOT EXISTS(SELECT 1 FROM claims WHERE id=?)").bind(nonce, p.id, p.version, p.id, to, id),
      db.prepare("INSERT INTO claims (id,player_id,kind,result,created_at) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM players WHERE id=? AND last_operation=?)").bind(id, p.id, "evolution", JSON.stringify(reward), Date.now(), p.id, nonce),
      db.prepare("INSERT INTO cards (player_id,pokemon_id,source,created_at) SELECT ?,?,'evolution',? WHERE EXISTS(SELECT 1 FROM players WHERE id=? AND last_operation=?)").bind(p.id, to, Date.now(), p.id, nonce),
      db.prepare("UPDATE trainer_profiles SET evolutions=evolutions+1,xp=xp+30 WHERE player_id=? AND EXISTS(SELECT 1 FROM players WHERE id=? AND last_operation=?)").bind(p.id, p.id, nonce)
    ]);
    if (!result[0].meta.changes) throw new GameError("conflict", 409);
    return { reward, profile: await c.profile(p.id) };
  }
  if (path === "task/claim") {
    await trainerDetails(p, []);
    const task = (await tasks(p)).find((t) => t.id === body.id);
    if (!task?.done) throw new GameError("task", 409);
    await rewardClaim(p, `${p.id}:${task.id}`, "task", task.coins, task.xp);
    return { profile: await c.profile(p.id) };
  }
  if (path === "season/claim") {
    const previous = await ranking(-1), rank = previous.players.find((r) => r.id === p.id), coins = rank && rank.points > 0 ? rank.rank === 1 ? 300 : rank.rank <= 3 ? 200 : rank.rank <= 10 ? 100 : 0 : 0;
    if (!coins) throw new GameError("task", 409);
    await trainerDetails(p, []);
    await rewardClaim(p, `${p.id}:season:${previous.season.id}`, "season", coins, 0);
    return { profile: await c.profile(p.id) };
  }
  if (path === "friends/request") {
    if (typeof body.username !== "string" || !/^[a-zA-Z0-9_]{3,20}$/.test(body.username)) throw new GameError("username", 400, "username");
    const friend = await db.prepare("SELECT id FROM players WHERE username=?").bind(body.username.toLowerCase()).first();
    if (!friend || friend.id === p.id) throw new GameError("friend");
    const [a, b] = [p.id, friend.id].sort();
    const count = await db.prepare("SELECT COUNT(*) AS n FROM friendships WHERE a=? OR b=?").bind(p.id, p.id).first();
    if (count.n >= 100) throw new GameError("friendLimit", 409);
    await db.prepare("INSERT OR IGNORE INTO friendships (a,b,requester,status,created_at) VALUES (?,?,?,'pending',?)").bind(a, b, p.id, Date.now()).run();
    return { profile: await c.profile(p.id) };
  }
  if (path === "friends/action") {
    if (typeof body.id !== "string") throw new GameError("request");
    const [a, b] = [p.id, body.id].sort();
    if (body.action === "accept") {
      const r = await db.prepare("UPDATE friendships SET status='accepted' WHERE a=? AND b=? AND requester<>? AND status='pending'").bind(a, b, p.id).run();
      if (!r.meta.changes) throw new GameError("friend");
    } else if (body.action === "remove") await db.prepare("DELETE FROM friendships WHERE a=? AND b=?").bind(a, b).run();
    else throw new GameError("request");
    return { profile: await c.profile(p.id) };
  }
  if (path === "friends/invite") {
    if (typeof body.id !== "string") throw new GameError("request");
    const [a, b] = [p.id, body.id].sort();
    if (!await db.prepare("SELECT a FROM friendships WHERE a=? AND b=? AND status='accepted'").bind(a, b).first()) throw new GameError("friend");
    const existing = await c.ownRoom(p);
    if (existing && ["waiting", "active"].includes(existing.status) && !(existing.status === "waiting" && JSON.parse(existing.state).inviteOnly === body.id)) throw new GameError("alreadyPlaying", 409);
    const room = existing?.status === "waiting" ? await c.roomView(p, existing.code) : await c.createRoom(p, body.id);
    await db.prepare("INSERT OR IGNORE INTO duel_invites (id,sender,receiver,room_code,created_at,expires_at) VALUES (?,?,?,?,?,?)").bind(`${p.id}:${room.code}`, p.id, body.id, room.code, Date.now(), Date.now() + 12e5).run();
    return { room, profile: await c.profile(p.id) };
  }
  if (path === "friends/accept-invite") {
    const invite = await db.prepare("SELECT * FROM duel_invites WHERE id=? AND receiver=? AND status IN ('pending','accepted') AND expires_at>?").bind(String(body.id), p.id, Date.now()).first();
    if (!invite) throw new GameError("roomUnavailable", 409);
    const existing = await c.ownRoom(p);
    const room = existing?.code === invite.room_code ? await c.roomView(p, invite.room_code) : await c.joinRoom(p, invite.room_code);
    await db.prepare("UPDATE duel_invites SET status='accepted' WHERE id=? AND receiver=?").bind(String(body.id), p.id).run();
    return { room, profile: await c.profile(p.id) };
  }
  if (path === "friends/decline-invite") {
    await db.prepare("UPDATE duel_invites SET status='declined' WHERE id=? AND receiver=?").bind(String(body.id), p.id).run();
    return { profile: await c.profile(p.id) };
  }
  return void 0;
}

// site/server/source/server/game-service.ts
var DAY2 = 864e5;
var COOKIE = "__Host-pokehabitat";
var json = (data, status = 200, cookie2) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...cookie2 ? { "Set-Cookie": cookie2 } : {} } });
function token() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function digest(value) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(bytes), (v) => v.toString(16).padStart(2, "0")).join("");
}
async function keyed(value) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(gameConfig().pepper), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)))));
}
function cookie(value, age = 7 * 86400) {
  return `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`;
}
var cookieToken = (r) => r.headers.get("Cookie")?.split(";").map((x) => x.trim()).find((x) => x.startsWith(`${COOKIE}=`))?.slice(COOKIE.length + 1) || "";
function credentials(body, creating = false) {
  const username = typeof body.username === "string" ? body.username.trim().toLowerCase() : "";
  if (!/^[a-z0-9_]{3,20}$/.test(username)) throw new GameError("username", 400, "username");
  const password = typeof body.password === "string" ? body.password : "";
  if (password.length < (creating ? 10 : 1) || password.length > 128) throw new GameError("password", 400, "password");
  return { username, password };
}
async function rate(req, scope, account, limit, period = 9e5) {
  const db = gameDb(), now = Date.now(), window = Math.floor(now / period) * period;
  const key = await keyed(`rate:${scope}:${account}`);
  const row = await db.prepare("INSERT INTO rate_limits (key,window_at,count) VALUES (?,?,1) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN window_at=? THEN count+1 ELSE 1 END, window_at=? RETURNING count").bind(key, window, window, window).first();
  if (!row || row.count > limit) throw new GameError("rate", 429);
  if (random() < 0.01) await db.batch([db.prepare("DELETE FROM rate_limits WHERE window_at<?").bind(now - DAY2 * 2), db.prepare("DELETE FROM sessions WHERE expires_at<?").bind(now)]);
}
async function session(req) {
  const t = cookieToken(req);
  if (!/^[A-Za-z0-9_-]{43}$/.test(t)) return null;
  return gameDb().prepare("SELECT p.* FROM sessions s JOIN players p ON p.id=s.player_id WHERE s.token_hash=? AND s.expires_at>?").bind(await digest(t), Date.now()).first();
}
async function requirePlayer(req) {
  const p = await session(req);
  if (!p) throw new GameError("unauthorized", 401);
  return p;
}
async function newSession(id) {
  const t = token();
  await gameDb().prepare("INSERT INTO sessions (token_hash,player_id,expires_at) VALUES (?,?,?)").bind(await digest(t), id, Date.now() + DAY2 * 7).run();
  return t;
}
async function profile(id) {
  const db = gameDb(), p = await db.prepare("SELECT id,username,credits,team,expedition_at,wins,losses,created_at,version FROM players WHERE id=?").bind(id).first();
  if (!p) throw new GameError("unauthorized", 401);
  const cards = await db.prepare("SELECT pokemon_id AS id,source,created_at AS createdAt FROM cards WHERE player_id=? ORDER BY created_at,pokemon_id").bind(id).all();
  return { id: p.id, username: p.username, credits: p.credits, team: JSON.parse(p.team), expeditionAt: p.expedition_at, wins: p.wins, losses: p.losses, createdAt: p.created_at, version: p.version, cards: cards.results, ...await trainerDetails(p, cards.results) };
}
async function validateTeam(p, ids) {
  if (!Array.isArray(ids) || ids.length !== 3 || new Set(ids).size !== 3 || ids.some((x) => !Number.isInteger(x) || !byId.has(x))) throw new GameError("team");
  if (ids.reduce((sum, id) => sum + byId.get(id).stats.reduce((a, b) => a + b, 0), 0) > 1500) throw new GameError("teamPower");
  const owned = await gameDb().prepare("SELECT pokemon_id FROM cards WHERE player_id=?").bind(p.id).all();
  if (ids.some((id) => !owned.results.some((c) => c.pokemon_id === id))) throw new GameError("ownership", 403);
  return ids;
}
var evolved = (id) => byId.get(id).evolution.edges.some((e) => e.to === id);
var legendary = (id) => {
  const p = byId.get(id);
  return !!(p.isLegendary || p.isMythical || [144, 145, 146, 150, 151].includes(id));
};
var common = () => pokemon.filter((p) => !legendary(p.id) && !evolved(p.id) && p.stats.reduce((a, b) => a + b, 0) <= 450);
async function acquisition(p, body, kind) {
  if (typeof body.key !== "string" || !/^[a-f0-9-]{36}$/i.test(body.key)) throw new GameError("request");
  const db = gameDb(), id = `${p.id}:${body.key}`;
  const previous = await db.prepare("SELECT result,kind FROM claims WHERE id=? AND player_id=?").bind(id, p.id).first();
  if (previous) {
    if (previous.kind !== kind) throw new GameError("request");
    return JSON.parse(previous.result);
  }
  const now = Date.now();
  if (kind === "expedition" && p.expedition_at > now - DAY2) throw new GameError("cooldown", 409);
  if (kind === "pack" && p.credits < 100) throw new GameError("coins", 409);
  let pool = common();
  if (kind === "expedition") {
    if (!["forest", "water", "mountain", "grassland", "cave", "urban", "unknown"].includes(String(body.habitat))) throw new GameError("habitat");
    pool = pokemon.filter((x) => x.habitat === body.habitat && !legendary(x.id));
  } else {
    const roll = random();
    pool = roll < 0.01 ? pokemon.filter((x) => legendary(x.id)) : roll < 0.1 ? pokemon.filter((x) => evolved(x.id) && !legendary(x.id)) : common();
  }
  if (!pool.length) throw new GameError("habitat");
  const card = choose(pool), exists = !!await db.prepare("SELECT pokemon_id FROM cards WHERE player_id=? AND pokemon_id=?").bind(p.id, card.id).first();
  const reward = { pokemonId: card.id, duplicate: exists, coins: exists ? 20 : 0, kind };
  const nonce = crypto.randomUUID();
  const update = kind === "pack" ? "UPDATE players SET credits=credits-100+?,version=version+1,last_operation=? WHERE id=? AND version=? AND credits>=100 AND NOT EXISTS(SELECT 1 FROM claims WHERE id=?)" : "UPDATE players SET credits=credits+?,expedition_at=?,version=version+1,last_operation=? WHERE id=? AND version=? AND expedition_at<=? AND NOT EXISTS(SELECT 1 FROM claims WHERE id=?)";
  const args = kind === "pack" ? [reward.coins, nonce, p.id, p.version, id] : [reward.coins, now, nonce, p.id, p.version, now - DAY2, id];
  const result = await db.batch([
    db.prepare(update).bind(...args),
    db.prepare("INSERT INTO claims (id,player_id,kind,result,created_at) SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM players WHERE id=? AND last_operation=?)").bind(id, p.id, kind, JSON.stringify(reward), now, p.id, nonce),
    db.prepare("INSERT OR IGNORE INTO cards (player_id,pokemon_id,source,created_at) SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM players WHERE id=? AND last_operation=?)").bind(p.id, card.id, kind, now, p.id, nonce)
  ]);
  if (!result[0].meta.changes) {
    const retry = await db.prepare("SELECT result FROM claims WHERE id=? AND player_id=?").bind(id, p.id).first();
    if (retry) return JSON.parse(retry.result);
    throw new GameError("conflict", 409);
  }
  return reward;
}
function visible(room, p) {
  const state = JSON.parse(room.state), you = state.sides.findIndex((s) => s.id === p.id);
  if (you < 0) throw new GameError("ownership", 403);
  const { orders, ...safe } = state;
  return { code: room.code, status: room.status, version: room.version, ...safe, you, ownOrder: orders[you] || null, opponentReady: !!orders[1 - you] };
}
async function readRoom(code) {
  if (typeof code !== "string" || !/^[A-Z2-9]{6}$/.test(code)) throw new GameError("room", 404);
  const r = await gameDb().prepare("SELECT * FROM rooms WHERE code=?").bind(code).first();
  if (!r) throw new GameError("room", 404);
  return r;
}
async function commitRoom(room, state, status) {
  const db = gameDb(), now = Date.now(), version = room.version + 1;
  const statements = [db.prepare("UPDATE rooms SET state=?,status=?,version=version+1,updated_at=? WHERE code=? AND version=?").bind(JSON.stringify(state), status, now, room.code, room.version)];
  if (status === "finished" && !state.practice) {
    for (const side of state.sides) {
      statements.push(db.prepare(`INSERT OR IGNORE INTO battle_rewards (player_id,room_code,day,credits,won,applied)
        SELECT ?,code,?,CASE WHEN json_extract(state,'$.reason')='draw' THEN 0 WHEN json_extract(state,'$.reason')='forfeit' AND json_extract(state,'$.round')<3 THEN 0
        WHEN (SELECT COUNT(*) FROM battle_rewards WHERE player_id=? AND day=? AND credits>0)>=3 THEN 0
        WHEN json_extract(state,'$.winner')=? THEN 30 ELSE 10 END,
        CASE WHEN json_extract(state,'$.reason')='draw' THEN -1 WHEN json_extract(state,'$.winner')=? THEN 1 ELSE 0 END,0
        FROM rooms WHERE code=? AND version=? AND status='finished'`).bind(side.id, Math.floor(now / DAY2), side.id, Math.floor(now / DAY2), side.id, side.id, room.code, version));
      statements.push(db.prepare(`UPDATE players SET credits=credits+COALESCE((SELECT credits FROM battle_rewards WHERE player_id=? AND room_code=? AND applied=0),0),
        wins=wins+CASE WHEN (SELECT won FROM battle_rewards WHERE player_id=? AND room_code=? AND applied=0)=1 THEN 1 ELSE 0 END,
        losses=losses+CASE WHEN (SELECT won FROM battle_rewards WHERE player_id=? AND room_code=? AND applied=0)=0 THEN 1 ELSE 0 END,
        version=version+1 WHERE id=? AND EXISTS(SELECT 1 FROM battle_rewards WHERE player_id=? AND room_code=? AND applied=0)`).bind(side.id, room.code, side.id, room.code, side.id, room.code, side.id, side.id, room.code));
      statements.push(db.prepare("UPDATE battle_rewards SET applied=1 WHERE player_id=? AND room_code=? AND applied=0").bind(side.id, room.code));
    }
  }
  if (status === "finished" && state.practice) {
    const id = state.sides[0].id, won = state.winner === id ? 1 : 0;
    statements.push(db.prepare("INSERT OR IGNORE INTO trainer_profiles (player_id) VALUES (?)").bind(id));
    statements.push(db.prepare(`INSERT OR IGNORE INTO practice_results (player_id,room_code,day,won,applied) SELECT ?,code,?,?,0 FROM rooms WHERE code=? AND version=? AND status='finished'`).bind(id, Math.floor(now / DAY2), won, room.code, version));
    statements.push(db.prepare("UPDATE trainer_profiles SET xp=xp+?,pve_wins=pve_wins+? WHERE player_id=? AND EXISTS(SELECT 1 FROM practice_results WHERE player_id=? AND room_code=? AND applied=0)").bind(won ? 15 : 5, won, id, id, room.code));
    statements.push(db.prepare("UPDATE players SET version=version+1 WHERE id=? AND EXISTS(SELECT 1 FROM practice_results WHERE player_id=? AND room_code=? AND applied=0)").bind(id, id, room.code));
    statements.push(db.prepare("UPDATE practice_results SET applied=1 WHERE player_id=? AND room_code=?").bind(id, room.code));
  }
  if (status === "finished" || status === "cancelled") statements.push(db.prepare("DELETE FROM player_locks WHERE room_code=? AND EXISTS(SELECT 1 FROM rooms WHERE code=? AND status IN ('finished','cancelled'))").bind(room.code, room.code));
  const result = await db.batch(statements);
  if (!result[0].meta.changes) throw new GameError("conflict", 409);
  return { ...room, state: JSON.stringify(state), status, version, updated_at: now };
}
async function advance(room) {
  const state = JSON.parse(room.state);
  if (room.status === "waiting" && room.updated_at < Date.now() - 12e5) {
    state.reason = "expired";
    return commitRoom(room, state, "cancelled");
  }
  if (room.status === "active" && state.deadline < Date.now()) {
    if (state.orders.every((x) => !x)) {
      state.reason = "expired";
      return commitRoom(room, state, "cancelled");
    }
    const next = resolveRound(state);
    return commitRoom(room, next, next.winner || next.reason === "draw" ? "finished" : "active");
  }
  return room;
}
async function ownRoom(p) {
  const r = await gameDb().prepare("SELECT r.* FROM player_locks l JOIN rooms r ON r.code=l.room_code WHERE l.player_id=?").bind(p.id).first();
  return r ? advance(r) : null;
}
async function arena(req, p) {
  const code = new URL(req.url).searchParams.get("code");
  const room = code ? await readRoom(code) : await ownRoom(p);
  const list = await gameDb().prepare("SELECT r.code,p.username,r.created_at AS createdAt FROM rooms r JOIN players p ON p.id=r.host_id WHERE r.status='waiting' AND json_extract(r.state,'$.inviteOnly') IS NULL AND r.host_id<>? AND r.updated_at>? ORDER BY r.created_at LIMIT 12").bind(p.id, Date.now() - 12e5).all();
  return { room: room ? visible(room, p) : null, rooms: list.results };
}
async function createRoom(p, inviteTo) {
  const locked = await ownRoom(p);
  if (locked && ["waiting", "active"].includes(locked.status)) throw new GameError("alreadyPlaying", 409);
  const ids = await validateTeam(p, JSON.parse(p.team));
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", code = Array.from({ length: 6 }, () => chars[Math.floor(random() * chars.length)]).join("");
  const now = Date.now(), state = { inviteOnly: inviteTo, sides: [makeSide(p.id, p.username, ids)], round: 1, orders: [null, null], deadline: now + 12e5, logs: [], winner: null };
  try {
    await gameDb().batch([
      gameDb().prepare("INSERT INTO rooms (code,host_id,status,state,version,created_at,updated_at) VALUES (?,?,?,?,0,?,?)").bind(code, p.id, "waiting", JSON.stringify(state), now, now),
      gameDb().prepare("INSERT INTO player_locks (player_id,room_code) VALUES (?,?)").bind(p.id, code)
    ]);
  } catch (e) {
    if (String(e).includes("UNIQUE")) throw new GameError("conflict", 409);
    throw e;
  }
  return visible(await readRoom(code), p);
}
async function joinRoom(p, code) {
  const previous = await ownRoom(p);
  if (previous && ["active", "waiting"].includes(previous.status)) throw new GameError("alreadyPlaying", 409);
  const r = await readRoom(typeof code === "string" ? code.trim().toUpperCase() : code);
  if (r.host_id === p.id || r.status !== "waiting" || r.updated_at < Date.now() - 12e5) throw new GameError("roomUnavailable", 409);
  const state = JSON.parse(r.state);
  if (state.inviteOnly && state.inviteOnly !== p.id) throw new GameError("ownership", 403);
  state.sides.push(makeSide(p.id, p.username, await validateTeam(p, JSON.parse(p.team))));
  state.deadline = Date.now() + 12e4;
  try {
    const result = await gameDb().batch([
      gameDb().prepare("UPDATE rooms SET guest_id=?,status='active',state=?,version=version+1,updated_at=? WHERE code=? AND version=? AND status='waiting' AND guest_id IS NULL").bind(p.id, JSON.stringify(state), Date.now(), r.code, r.version),
      gameDb().prepare("INSERT INTO player_locks (player_id,room_code) SELECT ?,? WHERE EXISTS(SELECT 1 FROM rooms WHERE code=? AND guest_id=? AND version=?)").bind(p.id, r.code, r.code, p.id, r.version + 1)
    ]);
    if (!result[0].meta.changes) throw new GameError("roomUnavailable", 409);
  } catch (e) {
    if (String(e).includes("UNIQUE")) throw new GameError("alreadyPlaying", 409);
    throw e;
  }
  return visible(await readRoom(r.code), p);
}
async function arenaAction(p, body) {
  let r = await readRoom(body.code);
  visible(r, p);
  r = await advance(r);
  if (body.action === "sync" || ["finished", "cancelled"].includes(r.status)) return visible(r, p);
  const state = JSON.parse(r.state), side = state.sides.findIndex((x) => x.id === p.id);
  if (body.action === "cancel" && r.status === "waiting") {
    state.reason = "cancelled";
    return visible(await commitRoom(r, state, "cancelled"), p);
  }
  if (r.status !== "active") throw new GameError("roomUnavailable", 409);
  if (body.action === "forfeit") {
    state.winner = state.sides[1 - side].id;
    state.reason = "forfeit";
    state.orders = [null, null];
    return visible(await commitRoom(r, state, "finished"), p);
  }
  if (body.action !== "order" || body.round !== state.round) throw new GameError("conflict", 409);
  if (state.orders[side]) return visible(r, p);
  const order = body.order;
  if (!validOrder(state, side, order)) throw new GameError("order");
  state.orders[side] = order;
  if (state.practice) state.orders[1 - side] = practiceOrder(state);
  const next = state.orders.every(Boolean) ? resolveRound(state) : state;
  return visible(await commitRoom(r, next, next.winner || next.reason === "draw" ? "finished" : "active"), p);
}
async function createPractice(p, difficulty) {
  if (!["easy", "normal", "hard"].includes(String(difficulty))) throw new GameError("request");
  const locked = await ownRoom(p);
  if (locked && ["waiting", "active"].includes(locked.status)) throw new GameError("alreadyPlaying", 409);
  const team = await validateTeam(p, JSON.parse(p.team));
  const ceiling = difficulty === "easy" ? 350 : difficulty === "normal" ? 450 : 500;
  let pool = pokemon.filter((x) => !legendary(x.id) && x.stats.reduce((a, b) => a + b, 0) <= ceiling);
  const ids = [];
  while (ids.length < 3) {
    const selected = choose(pool);
    ids.push(selected.id);
    pool = pool.filter((x) => x.id !== selected.id);
  }
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", code = Array.from({ length: 6 }, () => chars[Math.floor(random() * chars.length)]).join("");
  const now = Date.now(), state = { practice: difficulty, sides: [makeSide(p.id, p.username, team), makeSide("practice-bot", "Practice bot", ids)], round: 1, orders: [null, null], deadline: now + 12e4, logs: [], winner: null };
  try {
    await gameDb().batch([gameDb().prepare("INSERT INTO rooms (code,host_id,status,state,version,created_at,updated_at) VALUES (?,?,?,?,0,?,?)").bind(code, p.id, "active", JSON.stringify(state), now, now), gameDb().prepare("INSERT INTO player_locks (player_id,room_code) VALUES (?,?)").bind(p.id, code)]);
  } catch (e) {
    if (String(e).includes("UNIQUE")) throw new GameError("alreadyPlaying", 409);
    throw e;
  }
  return visible(await readRoom(code), p);
}
async function handleGame(req) {
  try {
    const path = new URL(req.url).pathname.replace(/^\/api\/game\//, ""), db = gameDb();
    if (req.method === "GET") {
      if (path === "me") {
        const p2 = await session(req);
        return json({ profile: p2 ? await profile(p2.id) : null });
      }
      if (path === "arena") return json(await arena(req, await requirePlayer(req)));
      if (["club", "ranking"].includes(path)) return json(await extraGame(path, req, await requirePlayer(req), null, { profile, ownRoom, createRoom, joinRoom, roomView: async (p2, code) => visible(await readRoom(code), p2) }));
      throw new GameError("request", 404);
    }
    if (req.headers.get("Origin") !== gameConfig().origin) throw new GameError("origin", 403);
    if (!req.headers.get("Content-Type")?.startsWith("application/json")) throw new GameError("request", 415);
    if (Number(req.headers.get("Content-Length") || 0) > 8192) throw new GameError("request", 413);
    const raw = await req.text();
    if (new TextEncoder().encode(raw).length > 8192) throw new GameError("request", 413);
    let body;
    try {
      body = JSON.parse(raw);
      if (!body || Array.isArray(body) || typeof body !== "object") throw new Error();
    } catch {
      throw new GameError("request");
    }
    const ip = req.headers.get("CF-Connecting-IP") || "unknown";
    if (path === "auth/register" || path === "auth/login" || path === "auth/recover") {
      await rate(req, "auth-ip", ip, 50);
      const { username, password } = credentials(body, path !== "auth/login");
      await rate(req, `auth-${path}`, username, path === "auth/login" ? 10 : 5);
      const prehash = await keyed(`password:${password}`);
      const player = await db.prepare("SELECT * FROM players WHERE username=?").bind(username).first();
      if (path === "auth/register") {
        await rate(req, "registration-ip", ip, 8, 36e5);
        if (player) throw new GameError("taken", 409, "username");
        if (![1, 4, 7].includes(Number(body.starter))) throw new GameError("starter", 400, "starter");
        const starter = Number(body.starter), pool = common().filter((p2) => p2.id !== starter && ![1, 4, 7].includes(p2.id));
        const first = choose(pool), second = choose(pool.filter((x) => x.id !== first.id)), team = [starter, first.id, second.id], id = crypto.randomUUID(), recovery2 = token(), sessionToken2 = token(), now = Date.now();
        const passwordHash = await bcryptjs_default.hash(prehash, 12), recoveryHash = await keyed(`recovery:${recovery2}`);
        try {
          await db.batch([
            db.prepare("INSERT INTO players (id,username,password_hash,recovery_hash,created_at,team) VALUES (?,?,?,?,?,?)").bind(id, username, passwordHash, recoveryHash, now, JSON.stringify(team)),
            ...team.map((card) => db.prepare("INSERT INTO cards (player_id,pokemon_id,source,created_at) VALUES (?,?,?,?)").bind(id, card, "starter", now)),
            db.prepare("INSERT INTO sessions (token_hash,player_id,expires_at) VALUES (?,?,?)").bind(await digest(sessionToken2), id, now + DAY2 * 7)
          ]);
        } catch (e) {
          if (String(e).includes("UNIQUE")) throw new GameError("taken", 409, "username");
          throw e;
        }
        return json({ profile: await profile(id), recoveryCode: recovery2 }, 201, cookie(sessionToken2));
      }
      if (path === "auth/login") {
        const valid = player ? await bcryptjs_default.compare(prehash, player.password_hash) : await bcryptjs_default.hash(prehash, 12).then(() => false);
        if (!valid || !player) throw new GameError("credentials", 401);
        return json({ profile: await profile(player.id) }, 200, cookie(await newSession(player.id)));
      }
      if (typeof body.recoveryCode !== "string" || !player || player.recovery_hash !== await keyed(`recovery:${body.recoveryCode}`)) throw new GameError("recovery", 401, "recoveryCode");
      const recovery = token(), sessionToken = token();
      const result = await db.batch([
        db.prepare("UPDATE players SET password_hash=?,recovery_hash=?,version=version+1 WHERE id=? AND recovery_hash=?").bind(await bcryptjs_default.hash(prehash, 12), await keyed(`recovery:${recovery}`), player.id, player.recovery_hash),
        db.prepare("DELETE FROM sessions WHERE player_id=? AND EXISTS(SELECT 1 FROM players WHERE id=? AND recovery_hash=?)").bind(player.id, player.id, await keyed(`recovery:${recovery}`)),
        db.prepare("INSERT INTO sessions (token_hash,player_id,expires_at) SELECT ?,?,? WHERE EXISTS(SELECT 1 FROM players WHERE id=? AND recovery_hash=?)").bind(await digest(sessionToken), player.id, Date.now() + DAY2 * 7, player.id, await keyed(`recovery:${recovery}`))
      ]);
      if (!result[0].meta.changes) throw new GameError("recovery", 401);
      return json({ profile: await profile(player.id), recoveryCode: recovery }, 200, cookie(sessionToken));
    }
    if (path === "auth/logout") {
      const t = cookieToken(req);
      if (t) await db.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(t)).run();
      return json({ profile: null }, 200, cookie("", 0));
    }
    const p = await requirePlayer(req);
    await rate(req, "game", p.id, 120, 6e4);
    if (path === "auth/recovery-code") {
      if (typeof body.password !== "string" || body.password.length > 128 || !await bcryptjs_default.compare(await keyed(`password:${body.password}`), p.password_hash)) throw new GameError("credentials", 401, "password");
      const recovery = token();
      await db.prepare("UPDATE players SET recovery_hash=? WHERE id=?").bind(await keyed(`recovery:${recovery}`), p.id).run();
      return json({ recoveryCode: recovery });
    }
    if (path === "team") {
      const ids = await validateTeam(p, body.team);
      await db.prepare("UPDATE players SET team=?,version=version+1 WHERE id=?").bind(JSON.stringify(ids), p.id).run();
      return json({ profile: await profile(p.id) });
    }
    if (path === "expedition" || path === "pack") return json({ reward: await acquisition(p, body, path), profile: await profile(p.id) });
    if (path === "arena/create") return json({ room: await createRoom(p) });
    if (path === "arena/practice") return json({ room: await createPractice(p, body.difficulty) });
    const extra = await extraGame(path, req, p, body, { profile, ownRoom, createRoom, joinRoom, roomView: async (p2, code) => visible(await readRoom(code), p2) });
    if (extra !== void 0) return json(extra);
    if (path === "arena/join") return json({ room: await joinRoom(p, body.code) });
    if (path === "arena/action") return json({ room: await arenaAction(p, body), profile: await profile(p.id) });
    throw new GameError("request", 404);
  } catch (e) {
    if (e instanceof GameError) return json({ error: e.code, field: e.field }, e.status);
    console.error("Game request failed", e instanceof Error ? e.message : "Storage error");
    return json({ error: "unavailable" }, 503);
  }
}

// site/server/source/main.ts
function createGameServer() {
  const { origin } = gameConfig();
  return createServer({ maxHeaderSize: 16384 }, async (req, res) => {
    const reply = (status, error) => {
      res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
      res.end(JSON.stringify({ error }));
    };
    try {
      if (!req.url?.startsWith("/api/game/") || req.url.startsWith("//")) return reply(404, "request");
      if (!["GET", "POST"].includes(req.method || "")) return reply(405, "request");
      if (Number(req.headers["content-length"] || 0) > 8192) return reply(413, "request");
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 8192) {
          reply(413, "request");
          req.destroy();
          return;
        }
        chunks.push(chunk);
      }
      const headers = new Headers();
      for (const [key, value] of Object.entries(req.headers)) if (value) headers.set(key, Array.isArray(value) ? value.join(",") : value);
      const request = new Request(origin + req.url, { method: req.method, headers, ...req.method === "POST" ? { body: Buffer.concat(chunks) } : {} });
      const response = await handleGame(request);
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      if (!res.headersSent) reply(503, "unavailable");
      else res.end();
    }
  });
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = dirname(fileURLToPath(import.meta.url));
  initGameDatabase(process.env.GAME_DB || "/var/lib/nuvrion-pokehabitat/game.sqlite", join(root, "migrations"));
  const socket = process.env.GAME_SOCKET || "/run/nuvrion-pokehabitat/game.sock";
  try {
    if (!lstatSync(socket).isSocket()) throw new Error("Game socket path is occupied");
    unlinkSync(socket);
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
  const server = createGameServer();
  server.requestTimeout = 15e3;
  server.headersTimeout = 1e4;
  server.listen(socket, () => {
    chmodSync(socket, 432);
    console.log("Pok\xE9Habitat is ready on its local Unix socket");
  });
  const stop = () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5e3).unref();
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
export {
  createGameServer,
  handleGame,
  initGameDatabase
};
