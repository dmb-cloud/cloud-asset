/**************************************************************
 * DMS Cloud Registry — Code.gs  (Hardened v2.0)
 * --------------------------------------------------------------
 * สิ่งที่แก้จากเวอร์ชันเดิม
 *  1) Session เป็น HMAC-signed token (ปลอมไม่ได้ + revoke ได้ + ไม่หายเมื่อ cache ถูกล้าง)
 *  2) ทุก action ที่แตะข้อมูล ต้องมี token ที่ผ่านการ verify เท่านั้น
 *  3) Row-level authorization: ผู้ใช้ทั่วไปเห็น/แก้ได้เฉพาะหน่วยงานตัวเอง
 *  4) แก้ cache ข้าม tenant (เดิม cache ผลลัพธ์ที่ filter แล้วด้วย key เดียวกันทุกคน = ข้อมูลรั่ว)
 *  5) OTP เก็บเป็น hash (ไม่เก็บเลขดิบในชีต) + ยกเลิก OTP เก่าทุกครั้งที่ขอใหม่ + จำกัดจำนวนครั้ง
 *  6) ตรวจ state ของ SSO ที่ฝั่ง server จริง (กัน CSRF / code replay)
 *  7) กัน user enumeration (ข้อความตอบกลับเหมือนกันหมดในเส้นทางสมัคร/ขอ OTP)
 *  8) Rate limit ทุก action สำคัญ, ป้องกัน formula injection, ไม่ echo stack trace
 *  9) LockService กัน race condition ตอนเขียนชีต
 * 10) มี audit log แยกสำหรับเหตุการณ์ด้านความปลอดภัย
 *
 * ต้องตั้งค่าใน Project Settings > Script properties ก่อนใช้งาน
 *   CLIENT_ID        = client id ของ DMS SSO
 *   CLIENT_SECRET    = client secret ของ DMS SSO
 *   TOKEN_SECRET     = สุ่มยาว >= 48 ตัวอักษร (ใช้เซ็น session token)
 *   OTP_SECRET       = สุ่มยาว >= 48 ตัวอักษร (ใช้ hash OTP)
 *   ADMIN_AGENCIES   = ชื่อหน่วยงานที่เห็นข้ามหน่วยงานได้ คั่นด้วย , (ไม่ตั้ง = ไม่มีใครเป็น admin)
 *   PUBLIC_AGENCY_LIST = "true" ถ้ายอมให้หน้า login ดึงรายชื่อหน่วยงานได้โดยไม่ล็อกอิน
 * รัน setupSecrets() หนึ่งครั้งเพื่อช่วยสุ่ม TOKEN_SECRET / OTP_SECRET ให้อัตโนมัติ
 **************************************************************/

// ==========================================================
// CONFIG
// ==========================================================
const PROPS = PropertiesService.getScriptProperties();

const SSO_CONFIG = {
  authority: "https://sso.dms.go.th/keycloak/realms/dms/protocol/openid-connect/",
  profileUrl: "https://sso.dms.go.th/dms-sso-api/api/Authen/Verify/Profile",
  redirectUri: "https://cloud.dms.go.th/sso-callback.html",
  get clientId() { return PROPS.getProperty("CLIENT_ID"); },
  get clientSecret() { return PROPS.getProperty("CLIENT_SECRET"); }
};

const SESSION_TTL_MS = 2 * 60 * 60 * 1000;   // session 2 ชม.
const PENDING_TTL_SEC = 10 * 60;             // ระหว่างรอ OTP 10 นาที
const OTP_TTL_MS = 5 * 60 * 1000;            // OTP อายุ 5 นาที
const OTP_RESEND_COOLDOWN_SEC = 60;
const MAX_LOGIN_ATTEMPTS = 5;
const MAX_OTP_ATTEMPTS = 5;
const LOCKOUT_SEC = 180;
const MAX_PAYLOAD_BYTES = 512 * 1024;        // กัน payload ใหญ่ผิดปกติ
const MAX_ASSETS_PER_SAVE = 2000;

// action ที่ต้องมี session token ที่ valid
const PROTECTED_ACTIONS = {
  getAllRiskCloudData: true,
  getAgencies: true,
  saveAssessmentData: true,
  whoAmI: true,
  logout: true
};

// action ที่เปิดสาธารณะ (ทุกอย่างที่ไม่อยู่ใน 2 ลิสต์นี้ = ปฏิเสธ)
const PUBLIC_ACTIONS = {
  getPublicAgencies: true,
  registerUser: true,
  verifyUser: true,
  verifyOTP: true,
  generateAndSaveOTP: true,
  getSsoLoginUrl: true,
  handleSsoCallback: true,
  ping: true
};

// ==========================================================
// ENTRY POINTS
// ==========================================================
function doGet() {
  return jsonOut({ success: true, status: "API Online" });
}

function doPost(e) {
  let action = "";
  try {
    if (!e || !e.postData || !e.postData.contents) {
      return jsonOut({ success: false, message: "คำขอไม่ถูกต้อง" });
    }
    if (e.postData.contents.length > MAX_PAYLOAD_BYTES) {
      return jsonOut({ success: false, message: "ข้อมูลที่ส่งมามีขนาดใหญ่เกินกำหนด" });
    }

    const data = JSON.parse(e.postData.contents);
    action = String(data.action || "");
    const payload = (data.payload && typeof data.payload === "object") ? data.payload : {};

    // กัน client แอบยัด _session เข้ามาเอง
    delete payload._session;

    if (!PROTECTED_ACTIONS[action] && !PUBLIC_ACTIONS[action]) {
      return jsonOut({ success: false, message: "Unrecognized Action" });
    }

    let session = null;
    if (PROTECTED_ACTIONS[action]) {
      session = verifyToken(payload.token);
      if (!session) {
        return jsonOut({ success: false, code: "UNAUTHENTICATED",
          message: "ไม่ได้เข้าสู่ระบบ หรือ Session หมดอายุ กรุณาเข้าสู่ระบบใหม่" });
      }
    }

    let result;
    switch (action) {
      case "ping":                result = { success: true, time: new Date().toISOString() }; break;
      case "getPublicAgencies":   result = getPublicAgencies(); break;
      case "getAgencies":         result = { success: true, agencies: getAgencies(session) }; break;
      case "getAllRiskCloudData": result = { success: true, assets: getAllRiskCloudData(session) }; break;
      case "saveAssessmentData":  result = saveAssessmentData(payload, session); break;
      case "registerUser":        result = registerUser(payload); break;
      case "verifyUser":          result = verifyUser(payload.agency, payload.email, payload.phone); break;
      case "verifyOTP":           result = verifyOTP(payload.email, payload.userOtp); break;
      case "generateAndSaveOTP":  result = requestOtpResend(payload.email); break;
      case "getSsoLoginUrl":      result = getSsoLoginUrl(); break;
      case "handleSsoCallback":   result = handleSsoCallback(payload.code, payload.state); break;
      case "whoAmI":              result = { success: true, user: { email: session.email, agency: session.agency, fullname: session.fullname, isAdmin: isAdminSession(session) } }; break;
      case "logout":              result = logout(session); break;
      default:                    result = { success: false, message: "Unrecognized Action" };
    }

    return jsonOut({ success: true, data: result });

  } catch (err) {
    Logger.log("doPost error [" + action + "]: " + err.stack);
    return jsonOut({ success: false, message: "เกิดข้อผิดพลาดในการประมวลผล" });
  }
}

function jsonOut(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

// ==========================================================
// CRYPTO / SESSION TOKEN (HMAC-SHA256, stateless + revocable)
// ==========================================================
function b64u(bytes) {
  return Utilities.base64EncodeWebSafe(bytes).replace(/=+$/, "");
}

function hmacB64(message, secret) {
  return b64u(Utilities.computeHmacSha256Signature(message, secret));
}

function constantTimeEquals(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a.charCodeAt(i) ^ b.charCodeAt(i));
  return diff === 0;
}

function requireSecret(name) {
  const v = PROPS.getProperty(name);
  if (!v || v.length < 32) {
    throw new Error("Missing/weak script property: " + name + " (run setupSecrets)");
  }
  return v;
}

function createSession(profile) {
  const now = Date.now();
  const body = {
    e: String(profile.email || ""),
    a: String(profile.agency || ""),
    f: String(profile.fullname || ""),
    iat: now,
    exp: now + SESSION_TTL_MS,
    jti: Utilities.getUuid()
  };
  const encoded = b64u(Utilities.newBlob(JSON.stringify(body)).getBytes());
  const sig = hmacB64(encoded, requireSecret("TOKEN_SECRET"));
  return encoded + "." + sig;
}

function verifyToken(token) {
  try {
    if (!token || typeof token !== "string" || token.length > 4000) return null;
    const parts = token.split(".");
    if (parts.length !== 2) return null;

    const expected = hmacB64(parts[0], requireSecret("TOKEN_SECRET"));
    if (!constantTimeEquals(expected, parts[1])) return null;

    const json = Utilities.newBlob(Utilities.base64DecodeWebSafe(parts[0])).getDataAsString();
    const p = JSON.parse(json);
    if (!p || !p.exp || Date.now() > p.exp) return null;

    // รายการ token ที่ถูกเพิกถอน (logout / บังคับออกจากระบบ)
    if (CacheService.getScriptCache().get("revoked_" + p.jti)) return null;

    return { email: p.e, agency: p.a, fullname: p.f, jti: p.jti, exp: p.exp };
  } catch (err) {
    return null;
  }
}

function logout(session) {
  const ttl = Math.max(60, Math.ceil((session.exp - Date.now()) / 1000));
  CacheService.getScriptCache().put("revoked_" + session.jti, "1", Math.min(ttl, 21600));
  auditLog("LOGOUT", session.email, session.agency, "");
  return { success: true, message: "ออกจากระบบเรียบร้อย" };
}

function getAdminAgencies() {
  const raw = PROPS.getProperty("ADMIN_AGENCIES") || "";
  return raw.split(",").map(s => s.trim()).filter(Boolean);
}

function isAdminSession(session) {
  if (!session || !session.agency) return false;
  return getAdminAgencies().indexOf(session.agency) !== -1;
}

// ==========================================================
// UTIL: sanitize / validate / rate limit / audit
// ==========================================================
function sanitizeCell(value) {
  let v = (value === null || value === undefined) ? "" : String(value);
  v = v.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "").trim();
  if (v.length > 500) v = v.substring(0, 500);
  if (v && ["=", "+", "-", "@", "\t", "\r"].indexOf(v.charAt(0)) !== -1) v = "'" + v;
  return v;
}

function isValidEmail(email) {
  return typeof email === "string" && email.length <= 254 &&
    /^[^\s@,;]+@[^\s@,;]+\.[A-Za-z]{2,}$/.test(email.trim());
}

function normEmail(email) {
  return isValidEmail(email) ? email.trim().toLowerCase() : "";
}

function isValidPhone(phone) {
  return typeof phone === "string" && /^0[0-9]{8,9}$/.test(phone.trim());
}

function toInt13(v) {
  const n = parseInt(v, 10);
  return (n === 1 || n === 2 || n === 3) ? n : 1;
}

/** rate limit แบบง่ายด้วย cache: คืน true ถ้ายังทำได้ */
function rateLimit(key, maxHits, windowSec) {
  const cache = CacheService.getScriptCache();
  const k = "rl_" + key;
  const cur = parseInt(cache.get(k) || "0", 10);
  if (cur >= maxHits) return false;
  cache.put(k, String(cur + 1), windowSec);
  return true;
}

function auditLog(event, email, agency, detail) {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sh = ss.getSheetByName("AuditLog");
    if (!sh) {
      sh = ss.insertSheet("AuditLog");
      sh.appendRow(["Timestamp", "Event", "Email", "Agency", "Detail"]);
    }
    sh.appendRow([new Date(), event, sanitizeCell(email), sanitizeCell(agency), sanitizeCell(detail)]);
  } catch (err) {
    Logger.log("auditLog failed: " + err);
  }
}

function getSheetOrThrow(name) {
  const sh = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(name);
  if (!sh) throw new Error("Sheet not found: " + name);
  return sh;
}

// ==========================================================
// SSO (Keycloak)
// ==========================================================
function getSsoLoginUrl() {
  try {
    if (!SSO_CONFIG.clientId) return { success: false, message: "ระบบยังไม่ได้ตั้งค่า SSO" };
    const state = Utilities.getUuid();
    const nonce = Utilities.getUuid();

    const authUrl = SSO_CONFIG.authority + "auth?" +
      "client_id=" + encodeURIComponent(SSO_CONFIG.clientId) +
      "&response_type=code" +
      "&scope=" + encodeURIComponent("openid profile cid") +
      "&redirect_uri=" + encodeURIComponent(SSO_CONFIG.redirectUri) +
      "&state=" + encodeURIComponent(state) +
      "&nonce=" + encodeURIComponent(nonce);

    CacheService.getScriptCache().put("ssostate_" + state, "1", 600);
    return { success: true, url: authUrl, state: state };
  } catch (err) {
    Logger.log("getSsoLoginUrl error: " + err);
    return { success: false, message: "ไม่สามารถสร้างลิงก์เข้าสู่ระบบได้" };
  }
}

function handleSsoCallback(code, state) {
  try {
    if (!code || typeof code !== "string" || code.length > 4000) {
      return { success: false, message: "ไม่พบรหัสยืนยันตัวตน" };
    }
    // ✅ ตรวจ state ที่ฝั่ง server และใช้ได้ครั้งเดียว (กัน CSRF + replay)
    const cache = CacheService.getScriptCache();
    if (!state || typeof state !== "string" || !cache.get("ssostate_" + state)) {
      auditLog("SSO_STATE_INVALID", "", "", String(state || "").substring(0, 60));
      return { success: false, message: "คำขอเข้าสู่ระบบไม่ถูกต้องหรือหมดอายุ กรุณาลองใหม่" };
    }
    cache.remove("ssostate_" + state);

    if (!rateLimit("sso_" + state, 3, 600)) {
      return { success: false, message: "คำขอถี่เกินไป กรุณาลองใหม่ภายหลัง" };
    }

    const tokenResponse = UrlFetchApp.fetch(SSO_CONFIG.authority + "token", {
      method: "post",
      payload: {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: SSO_CONFIG.redirectUri,
        client_id: SSO_CONFIG.clientId,
        client_secret: SSO_CONFIG.clientSecret
      },
      muteHttpExceptions: true
    });

    if (tokenResponse.getResponseCode() !== 200) {
      auditLog("SSO_TOKEN_FAIL", "", "", "HTTP " + tokenResponse.getResponseCode());
      return { success: false, message: "ไม่สามารถยืนยันตัวตนกับระบบ SSO ได้" };
    }

    const tokenData = JSON.parse(tokenResponse.getContentText());
    if (!tokenData.access_token) {
      return { success: false, message: "ไม่สามารถยืนยันตัวตนกับระบบ SSO ได้" };
    }

    const profileResponse = UrlFetchApp.fetch(SSO_CONFIG.profileUrl, {
      method: "post",
      headers: { "AccessToken": tokenData.access_token, "Client-Id": SSO_CONFIG.clientId },
      contentType: "application/json",
      payload: JSON.stringify({}),
      muteHttpExceptions: true
    });

    if (profileResponse.getResponseCode() !== 200) {
      return { success: false, message: "ไม่สามารถดึงข้อมูลผู้ใช้จากระบบ SSO ได้" };
    }

    const profileData = JSON.parse(profileResponse.getContentText());
    if (!(profileData && profileData.data && profileData.data.userSsoInfo)) {
      return { success: false, message: "ไม่พบข้อมูลผู้ใช้จากระบบ DMS SSO" };
    }

    const ssoProfile = mapSsoProfile(profileData.data.userSsoInfo);
    if (!isValidEmail(ssoProfile.email)) {
      auditLog("SSO_NO_EMAIL", ssoProfile.username, "", "");
      return { success: false, message: "บัญชี SSO นี้ไม่มีอีเมลที่ใช้งานได้ กรุณาติดต่อเจ้าหน้าที่" };
    }
    ssoProfile.email = normEmail(ssoProfile.email);

    const dbUser = saveSsoUserToSheet(ssoProfile);
    if (!dbUser.isActive) {
      auditLog("SSO_LOGIN_BLOCKED", ssoProfile.email, dbUser.agency, "inactive account");
      return { success: false, message: "บัญชีนี้ยังไม่ได้รับอนุมัติ กรุณาติดต่อเจ้าหน้าที่" };
    }

    const token = createSession({ email: ssoProfile.email, agency: dbUser.agency, fullname: dbUser.fullname });
    auditLog("LOGIN_SSO", ssoProfile.email, dbUser.agency, "");

    return {
      success: true,
      token: token,
      expiresAt: Date.now() + SESSION_TTL_MS,
      user: { fullname: dbUser.fullname, email: ssoProfile.email, agency: dbUser.agency }
    };

  } catch (err) {
    Logger.log("handleSsoCallback error: " + err.stack);
    return { success: false, message: "เกิดข้อผิดพลาดระหว่างเข้าสู่ระบบด้วย SSO" };
  }
}

function mapSsoProfile(p) {
  const isThai = (s) => /[\u0E00-\u0E7F]/.test(s);
  const firsts = [p.firstNameTh, p.thFirstName, p.nameTh, p.firstName, p.firstname, p.givenName, p.given_name, p.firstNameEn, p.enFirstName, p.name]
    .filter(Boolean).map(s => String(s).trim());
  const lasts = [p.lastNameTh, p.thLastName, p.surnameTh, p.lastName, p.lastname, p.familyName, p.family_name, p.surname, p.lastNameEn, p.enLastName]
    .filter(Boolean).map(s => String(s).trim());

  const thFirst = firsts.find(isThai) || "";
  const thLast = lasts.find(isThai) || "";
  const enFirst = firsts.find(s => !isThai(s)) || "";
  const enLast = lasts.find(s => !isThai(s)) || "";

  let fullname = "";
  if (thFirst && thLast) fullname = thFirst + " " + thLast;
  else if (thFirst) fullname = thFirst;
  else if (enFirst && enLast) fullname = enFirst + " " + enLast;
  else fullname = p.username || "ผู้ใช้งาน DMS SSO";

  const agency = [p.agency, p.agencyName, p.department, p.organization, p.orgName, p.subAgency]
    .filter(Boolean).map(s => String(s).trim()).find(Boolean) || "";

  return {
    username: p.username || p.userName || p.preferred_username || "",
    title: p.titleName || p.title || p.prefix || "",
    thFirstName: thFirst, thLastName: thLast,
    enFirstName: enFirst, enLastName: enLast,
    email: p.email || p.mail || "",
    phone: p.mobile || p.phoneNumber || p.telephone || "",
    position: p.position || p.positionName || p.jobTitle || "",
    agency: agency,
    fullname: fullname
  };
}

/**
 * บันทึกผู้ใช้ SSO ลง UserDB
 * หมายเหตุด้านความปลอดภัย: ค่า agency ที่ "เชื่อถือได้" คือค่าที่เจ้าหน้าที่กำหนดไว้ใน UserDB เท่านั้น
 * ผู้ใช้ใหม่จาก SSO จะถูกตั้งเป็น IsActive = false (รออนุมัติ) ไม่ได้รับสิทธิ์เห็นข้อมูลทันที
 */
function saveSsoUserToSheet(profile) {
  const lock = LockService.getScriptLock();
  lock.waitLock(20000);
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sheet = ss.getSheetByName("UserDB");
    if (!sheet) {
      sheet = ss.insertSheet("UserDB");
      sheet.appendRow(["Agency", "Email", "Phone", "FullName", "LastLogin", "IsActive"]);
    }

    const data = sheet.getDataRange().getValues();
    const ssoAgency = profile.agency ? sanitizeCell(profile.agency) : "";
    const fullname = sanitizeCell(profile.fullname);
    const phone = sanitizeCell(profile.phone);

    for (let i = 1; i < data.length; i++) {
      const dbEmail = data[i][1] ? String(data[i][1]).trim().toLowerCase() : "";
      if (dbEmail && dbEmail === profile.email) {
        const dbAgency = data[i][0] ? String(data[i][0]).trim() : "";
        const isActive = (data[i][5] === true || String(data[i][5]).toLowerCase() === "true");
        const row = i + 1;
        // ❗ ไม่เขียนทับ agency ที่เจ้าหน้าที่ตั้งไว้ ด้วยค่าจาก SSO
        const finalAgency = dbAgency || ssoAgency || "รออนุมัติ (SSO)";
        sheet.getRange(row, 1).setValue(finalAgency);
        sheet.getRange(row, 4).setValue(fullname);
        sheet.getRange(row, 5).setValue(new Date());
        return { agency: finalAgency, fullname: fullname, isActive: isActive };
      }
    }

    // ผู้ใช้ใหม่ → รออนุมัติเสมอ
    sheet.appendRow([ssoAgency || "รออนุมัติ (SSO)", profile.email, "'" + phone, fullname, new Date(), false]);
    auditLog("SSO_NEW_USER", profile.email, ssoAgency, "pending approval");
    return { agency: ssoAgency || "รออนุมัติ (SSO)", fullname: fullname, isActive: false };

  } finally {
    lock.releaseLock();
  }
}

// ==========================================================
// REGISTER / OTP LOGIN
// ==========================================================
const GENERIC_REGISTER_MSG = "ระบบได้รับคำขอของท่านแล้ว หากข้อมูลถูกต้อง เจ้าหน้าที่จะติดต่อกลับเพื่ออนุมัติบัญชี";
const GENERIC_OTP_MSG = "หากข้อมูลถูกต้อง ระบบจะส่งรหัส OTP ไปยังอีเมลที่ท่านระบุ";

function registerUser(payload) {
  const email = normEmail(payload.email);
  const phone = String(payload.phone || "").trim();

  if (!email || !isValidPhone(phone)) {
    return { success: false, message: "ข้อมูลที่กรอกไม่ถูกต้อง กรุณาตรวจสอบอีเมลและเบอร์โทรศัพท์" };
  }
  if (!rateLimit("reg_" + email, 3, 3600)) {
    return { success: true, message: GENERIC_REGISTER_MSG };   // ตอบเหมือนเดิม ไม่บอกว่าโดนจำกัด
  }

  const lock = LockService.getScriptLock();
  lock.waitLock(20000);
  try {
    const sheet = getSheetOrThrow("UserDB");
    const data = sheet.getDataRange().getValues();
    for (let i = 1; i < data.length; i++) {
      const dbEmail = data[i][1] ? String(data[i][1]).trim().toLowerCase() : "";
      if (dbEmail === email) {
        auditLog("REGISTER_DUPLICATE", email, payload.agency, "");
        return { success: true, message: GENERIC_REGISTER_MSG }; // ❗ ไม่บอกว่ามีอีเมลนี้อยู่แล้ว
      }
    }
    sheet.appendRow([
      sanitizeCell(payload.agency), email, "'" + sanitizeCell(phone),
      sanitizeCell(payload.fullname), new Date(), false
    ]);
    auditLog("REGISTER_NEW", email, payload.agency, "");
    return { success: true, message: GENERIC_REGISTER_MSG };
  } finally {
    lock.releaseLock();
  }
}

function verifyUser(agency, email, phone) {
  const e = normEmail(email);
  const ph = String(phone || "").trim();
  const ag = String(agency || "").trim();
  const cache = CacheService.getScriptCache();

  if (!e || !isValidPhone(ph) || !ag) {
    return { success: false, message: "ข้อมูลที่กรอกไม่ถูกต้อง" };
  }
  if (!rateLimit("vu_" + e, 10, 600)) {
    auditLog("LOGIN_RATE_LIMIT", e, ag, "");
    return { success: false, locked: true, message: "มีคำขอถี่เกินไป กรุณารอสักครู่แล้วลองใหม่" };
  }
  if (cache.get("lock_" + e)) {
    return { success: false, locked: true, message: "บัญชีนี้ถูกระงับชั่วคราวเป็นเวลา 3 นาที" };
  }

  const data = getSheetOrThrow("UserDB").getDataRange().getValues();
  let match = null;
  for (let i = 1; i < data.length; i++) {
    const dbEmail = data[i][1] ? String(data[i][1]).trim().toLowerCase() : "";
    if (dbEmail !== e) continue;
    const dbPhone = String(data[i][2] || "").replace(/^'/, "").trim();
    const dbAgency = String(data[i][0] || "").trim();
    if (dbAgency === ag && dbPhone === ph) {
      match = {
        agency: dbAgency,
        fullname: String(data[i][3] || ""),
        isActive: (data[i][5] === true || String(data[i][5]).toLowerCase() === "true")
      };
    }
    break;
  }

  if (!match || !match.isActive) {
    // นับความพยายามผิด และตอบข้อความกลางๆ ไม่บอกว่าอีเมลมีอยู่จริงหรือไม่
    const attempts = parseInt(cache.get("attempt_" + e) || "0", 10) + 1;
    if (attempts >= MAX_LOGIN_ATTEMPTS) {
      cache.put("lock_" + e, "1", LOCKOUT_SEC);
      cache.remove("attempt_" + e);
      auditLog("LOGIN_LOCKED", e, ag, "too many failures");
      return { success: false, locked: true, message: "ข้อมูลไม่ถูกต้องหลายครั้ง บัญชีถูกระงับชั่วคราว (3 นาที)" };
    }
    cache.put("attempt_" + e, String(attempts), 3600);
    auditLog("LOGIN_FAILED", e, ag, "attempt " + attempts);
    return { success: false, locked: false,
      message: "ข้อมูลหน่วยงาน อีเมล หรือเบอร์โทรศัพท์ไม่ถูกต้อง หรือบัญชียังไม่ได้รับอนุมัติ (ผิดพลาด " + attempts + "/" + MAX_LOGIN_ATTEMPTS + ")" };
  }

  cache.remove("attempt_" + e);
  cache.put("pending_" + e, JSON.stringify({ agency: match.agency, fullname: match.fullname }), PENDING_TTL_SEC);
  auditLog("OTP_REQUESTED", e, match.agency, "");

  const sent = issueOtp(e);
  // ❗ ไม่ส่ง fullname กลับไปก่อนยืนยัน OTP (ลดข้อมูลรั่วก่อนพิสูจน์ตัวตน)
  return { success: sent, message: GENERIC_OTP_MSG };
}

function requestOtpResend(email) {
  const e = normEmail(email);
  if (!e) return { success: true, message: GENERIC_OTP_MSG };

  const cache = CacheService.getScriptCache();
  if (!cache.get("pending_" + e)) {
    return { success: false, message: "กรุณายืนยันข้อมูลหน่วยงาน/เบอร์โทรก่อนขอรหัส OTP" };
  }
  if (cache.get("otpcooldown_" + e)) {
    return { success: false, message: "กรุณารอสักครู่ก่อนขอรหัส OTP ใหม่อีกครั้ง" };
  }
  if (!rateLimit("otpsend_" + e, 5, 3600)) {
    return { success: false, message: "ขอรหัส OTP บ่อยเกินไป กรุณาลองใหม่ภายหลัง" };
  }
  cache.put("otpcooldown_" + e, "1", OTP_RESEND_COOLDOWN_SEC);
  issueOtp(e);
  return { success: true, message: GENERIC_OTP_MSG };
}

function hashOtp(email, otp) {
  return hmacB64(String(email).toLowerCase() + ":" + String(otp), requireSecret("OTP_SECRET"));
}

/** สร้าง OTP ใหม่ + ยกเลิกรหัสเก่าทั้งหมดของอีเมลนี้ + เก็บเฉพาะ hash */
function issueOtp(email) {
  const lock = LockService.getScriptLock();
  lock.waitLock(20000);
  try {
    const sheet = getSheetOrThrow("OtpDB");
    const data = sheet.getDataRange().getValues();
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim().toLowerCase() === email && data[i][3] === "pending") {
        sheet.getRange(i + 1, 4).setValue("superseded");
      }
    }

    // OTP 6 หลักแบบสุ่มเชิงเข้ารหัส (ไม่ใช้ Math.random)
    const bytes = Utilities.computeHmacSha256Signature(Utilities.getUuid(), Utilities.getUuid());
    let num = 0;
    for (let i = 0; i < 4; i++) num = (num << 8 | (bytes[i] & 0xff)) >>> 0;
    const otp = String(100000 + (num % 900000));

    const expiresAt = new Date(Date.now() + OTP_TTL_MS);
    sheet.appendRow([email, hashOtp(email, otp), expiresAt, "pending", new Date()]);

    CacheService.getScriptCache().remove("otpattempt_" + email);

    MailApp.sendEmail(email, "รหัส OTP ยืนยันการเข้าสู่ระบบ DMS Cloud Registry",
      "เรียน ผู้ใช้งานระบบ DMS Cloud Registry\n\n" +
      "รหัส OTP สำหรับเข้าสู่ระบบของท่านคือ: " + otp + "\n\n" +
      "รหัสนี้มีอายุ 5 นาที และใช้ได้เพียงครั้งเดียว\n" +
      "หากท่านไม่ได้เป็นผู้ร้องขอ กรุณาแจ้งเจ้าหน้าที่ทันที และอย่าเปิดเผยรหัสนี้แก่ผู้ใด");
    return true;
  } catch (err) {
    Logger.log("issueOtp error: " + err);
    return false;
  } finally {
    lock.releaseLock();
  }
}

function verifyOTP(email, userOtp) {
  const e = normEmail(email);
  const code = String(userOtp || "").trim();
  const cache = CacheService.getScriptCache();

  if (!e || !/^[0-9]{6}$/.test(code)) {
    return { success: false, message: "รหัส OTP ไม่ถูกต้อง" };
  }
  if (cache.get("otplock_" + e)) {
    return { success: false, message: "ลองรหัสผิดครบจำนวนที่กำหนด กรุณารอสักครู่แล้วขอรหัสใหม่" };
  }
  if (!rateLimit("vo_" + e, 20, 600)) {
    return { success: false, message: "มีคำขอถี่เกินไป กรุณารอสักครู่" };
  }

  const lock = LockService.getScriptLock();
  lock.waitLock(20000);
  try {
    const sheet = getSheetOrThrow("OtpDB");
    const data = sheet.getDataRange().getValues();
    const now = new Date();
    const wanted = hashOtp(e, code);

    for (let i = data.length - 1; i >= 1; i--) {
      if (String(data[i][0]).trim().toLowerCase() !== e) continue;
      if (data[i][3] !== "pending") continue;                       // ข้ามรายการที่ใช้แล้ว/ถูกแทนที่

      if (now > new Date(data[i][2])) {
        sheet.getRange(i + 1, 4).setValue("expired");
        return { success: false, message: "รหัส OTP หมดอายุแล้ว กรุณาขอใหม่" };
      }

      if (constantTimeEquals(String(data[i][1]), wanted)) {
        sheet.getRange(i + 1, 4).setValue("used");
        cache.remove("otpattempt_" + e);

        const pendingRaw = cache.get("pending_" + e);
        if (!pendingRaw) {
          return { success: false, message: "เซสชันหมดอายุ กรุณาเข้าสู่ระบบใหม่" };
        }
        const pending = JSON.parse(pendingRaw);
        cache.remove("pending_" + e);

        const token = createSession({ email: e, agency: pending.agency, fullname: pending.fullname });
        auditLog("LOGIN_OTP", e, pending.agency, "");

        return {
          success: true, message: "ยืนยันตัวตนสำเร็จ",
          token: token, expiresAt: Date.now() + SESSION_TTL_MS,
          user: { email: e, agency: pending.agency, fullname: pending.fullname }
        };
      }

      const attempts = parseInt(cache.get("otpattempt_" + e) || "0", 10) + 1;
      if (attempts >= MAX_OTP_ATTEMPTS) {
        cache.put("otplock_" + e, "1", LOCKOUT_SEC);
        cache.remove("otpattempt_" + e);
        sheet.getRange(i + 1, 4).setValue("revoked");
        auditLog("OTP_LOCKED", e, "", "brute force");
        return { success: false, message: "ลองรหัสผิดครบ 5 ครั้ง กรุณารอ 3 นาทีแล้วขอรหัสใหม่" };
      }
      cache.put("otpattempt_" + e, String(attempts), 600);
      return { success: false, message: "รหัส OTP ไม่ถูกต้อง (ผิดพลาด " + attempts + "/" + MAX_OTP_ATTEMPTS + " ครั้ง)" };
    }

    return { success: false, message: "ไม่พบรหัส OTP ที่ใช้งานได้ กรุณาขอรหัสใหม่" };
  } finally {
    lock.releaseLock();
  }
}

// ==========================================================
// PUBLIC (ข้อมูลไม่อ่อนไหว) — รายชื่อหน่วยงานสำหรับหน้า login
// ==========================================================
function getPublicAgencies() {
  if (String(PROPS.getProperty("PUBLIC_AGENCY_LIST")).toLowerCase() !== "true") {
    return { success: true, agencies: [] };   // ปิดไว้เป็นค่าเริ่มต้น ให้ผู้ใช้พิมพ์เอง
  }
  const cache = CacheService.getScriptCache();
  const hit = cache.get("pub_agencies");
  if (hit) return { success: true, agencies: JSON.parse(hit) };

  const list = readAllAgencies();
  cache.put("pub_agencies", JSON.stringify(list), 600);
  return { success: true, agencies: list };
}

function readAllAgencies() {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("risk_cloud");
  if (!sheet || sheet.getLastRow() < 2) return [];
  const values = sheet.getRange(2, 2, sheet.getLastRow() - 1, 1).getValues();
  const set = {};
  for (let i = 0; i < values.length; i++) {
    const v = values[i][0] ? String(values[i][0]).trim() : "";
    if (v) set[v] = true;
  }
  return Object.keys(set).sort();
}

// ==========================================================
// PROTECTED DATA ENDPOINTS
// ==========================================================
function getAgencies(session) {
  // ✅ แคชรายชื่อ "ดิบ" เท่านั้น แล้วค่อย filter ตามสิทธิ์ (เดิมแคชผลที่ filter แล้ว = ข้อมูลรั่วข้ามผู้ใช้)
  const cache = CacheService.getScriptCache();
  let all;
  const hit = cache.get("raw_agencies");
  if (hit) {
    all = JSON.parse(hit);
  } else {
    all = readAllAgencies();
    try { cache.put("raw_agencies", JSON.stringify(all), 300); } catch (e) {}
  }
  if (isAdminSession(session)) return all;
  return all.filter(a => a === session.agency);
}

function getAllRiskCloudData(session) {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("risk_cloud");
  if (!sheet || sheet.getLastRow() < 2) return [];

  const data = sheet.getDataRange().getValues();
  const admin = isAdminSession(session);
  const assets = [];

  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    if (!row[1]) continue;
    const rowAgency = String(row[1]).trim();
    if (!admin && rowAgency !== session.agency) continue;   // ✅ row-level authorization

    const hasSaved = (row[8] && String(row[8]).trim() !== "") || (row[10] && String(row[10]).trim() !== "");
    assets.push({
      id: row[0] ? String(row[0]) : "",
      agency: rowAgency,
      typeFilter: row[2] ? String(row[2]) : "",
      name: row[3] ? String(row[3]) : "",
      ip: row[4] ? String(row[4]) : "",
      privateIp: row[5] ? String(row[5]) : "",
      projectId: row[6] ? String(row[6]) : "",
      domain: row[7] ? String(row[7]) : "",
      contact: row[8] ? String(row[8]) : "",
      note: row[9] ? String(row[9]) : "",
      sysType: row[10] ? String(row[10]) : "ระบบบริการ (Web Services)",
      pdpa: (row[11] === true || row[11] === "TRUE" || row[11] === "ใช่"),
      c: toInt13(row[12]), i: toInt13(row[13]), a: toInt13(row[14]),
      impact: toInt13(row[15]),
      status: (row[16] && String(row[16]).trim() !== "") ? String(row[16]).trim() : "ไม่ใช้งาน",
      isSaved: hasSaved
    });
  }

  auditLog("READ_ASSETS", session.email, session.agency, assets.length + " rows");
  return assets;
}

function saveAssessmentData(payload, session) {
  const incoming = Array.isArray(payload.assets) ? payload.assets : [];
  if (incoming.length === 0) return { success: false, message: "ไม่มีข้อมูลที่จะบันทึก" };
  if (incoming.length > MAX_ASSETS_PER_SAVE) return { success: false, message: "จำนวนรายการเกินกำหนด" };
  if (!rateLimit("save_" + session.email, 30, 600)) {
    return { success: false, message: "บันทึกถี่เกินไป กรุณารอสักครู่" };
  }

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(30000)) {
    return { success: false, message: "ระบบกำลังมีผู้ใช้งานบันทึกข้อมูลอยู่ กรุณาลองใหม่อีกครั้ง" };
  }

  try {
    const sheet = getSheetOrThrow("risk_cloud");
    const admin = isAdminSession(session);
    // ✅ ไม่เชื่อ agency/assessor ที่ client ส่งมา ใช้จาก session เสมอ
    const trustedAgency = session.agency;
    const trustedAssessor = session.fullname || session.email;

    const updates = {};
    incoming.forEach(a => {
      if (a && a.id !== undefined && a.id !== null) updates[String(a.id)] = a;
    });

    const lastRow = sheet.getLastRow();
    if (lastRow < 2) return { success: false, message: "ไม่มีข้อมูลในระบบ" };

    const ids = sheet.getRange(2, 1, lastRow - 1, 2).getValues();   // col A: id, col B: agency
    // คอลัมน์ I..R (9..18) = contact, note, sysType, pdpa, c, i, a, impact, status, updatedAt
    const block = sheet.getRange(2, 9, lastRow - 1, 10).getValues();
    const names = sheet.getRange(2, 4, lastRow - 1, 1).getValues();

    let changed = 0, denied = 0;

    for (let r = 0; r < ids.length; r++) {
      const id = ids[r][0] ? String(ids[r][0]) : "";
      if (!id || !updates[id]) continue;

      const rowAgency = ids[r][1] ? String(ids[r][1]).trim() : "";
      if (!admin && rowAgency !== trustedAgency) { denied++; continue; }   // ✅ แก้ได้เฉพาะของตัวเอง

      const u = updates[id];
      names[r][0]   = sanitizeCell(u.resourceName || names[r][0] || "");
      block[r][0]   = trustedAssessor;                                    // ผู้บันทึกล่าสุด
      block[r][1]   = sanitizeCell(u.note || "");
      block[r][2]   = sanitizeCell(u.sysType || "ระบบบริการ (Web Services)");
      block[r][3]   = u.pdpa ? "TRUE" : "FALSE";
      block[r][4]   = toInt13(u.c);
      block[r][5]   = toInt13(u.i);
      block[r][6]   = toInt13(u.a);
      block[r][7]   = toInt13(u.impact);
      block[r][8]   = (String(u.status).trim() === "ใช้งาน") ? "ใช้งาน" : "ไม่ใช้งาน";
      block[r][9]   = new Date();
      changed++;
    }

    if (changed > 0) {
      sheet.getRange(2, 9, lastRow - 1, 10).setValues(block);
      sheet.getRange(2, 4, lastRow - 1, 1).setValues(names);
      SpreadsheetApp.flush();
    }

    if (denied > 0) {
      auditLog("SAVE_DENIED", session.email, trustedAgency, denied + " rows outside own agency");
    }
    auditLog("SAVE_ASSETS", session.email, trustedAgency, changed + " rows updated");

    if (changed === 0) {
      return { success: false, message: "ไม่พบรายการที่ท่านมีสิทธิ์แก้ไข" };
    }
    return { success: true, message: "บันทึกการประเมินเรียบร้อยแล้ว (" + changed + " รายการ)" };

  } catch (err) {
    Logger.log("saveAssessmentData error: " + err.stack);
    return { success: false, message: "เกิดข้อผิดพลาดในการบันทึกข้อมูล" };
  } finally {
    lock.releaseLock();
  }
}

// ==========================================================
// MAINTENANCE / SETUP (รันจาก Editor เท่านั้น)
// ==========================================================
/** รันครั้งเดียวเพื่อสร้าง TOKEN_SECRET / OTP_SECRET ถ้ายังไม่มี */
function setupSecrets() {
  ["TOKEN_SECRET", "OTP_SECRET"].forEach(function (k) {
    if (!PROPS.getProperty(k) || PROPS.getProperty(k).length < 48) {
      PROPS.setProperty(k, Utilities.getUuid() + Utilities.getUuid() + Utilities.getUuid());
      Logger.log(k + " generated.");
    } else {
      Logger.log(k + " already set.");
    }
  });
}

/** ตั้ง trigger รายวันเพื่อลบ OTP เก่าออกจากชีต */
function cleanupOldOtp() {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName("OtpDB");
  if (!sheet) return;
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  const data = sheet.getDataRange().getValues();
  for (let i = data.length - 1; i >= 1; i--) {
    const t = new Date(data[i][2]).getTime();
    if (!isNaN(t) && t < cutoff) sheet.deleteRow(i + 1);
  }
}

/** บังคับให้ทุก session ที่ออกไปแล้วใช้ไม่ได้ (กรณีสงสัยว่ามีการรั่วไหล) */
function rotateTokenSecret() {
  PROPS.setProperty("TOKEN_SECRET", Utilities.getUuid() + Utilities.getUuid() + Utilities.getUuid());
  auditLog("TOKEN_SECRET_ROTATED", "system", "", "all sessions invalidated");
}

/** ตรวจความพร้อมด้านความปลอดภัยก่อน deploy */
function securitySelfCheck() {
  const out = [];
  ["CLIENT_ID", "CLIENT_SECRET", "TOKEN_SECRET", "OTP_SECRET"].forEach(function (k) {
    const v = PROPS.getProperty(k);
    out.push(k + ": " + (v ? "OK (" + v.length + " chars)" : "❌ MISSING"));
  });
  out.push("ADMIN_AGENCIES: " + (getAdminAgencies().join(" | ") || "(none)"));
  out.push("PUBLIC_AGENCY_LIST: " + (PROPS.getProperty("PUBLIC_AGENCY_LIST") || "false"));
  ["UserDB", "OtpDB", "risk_cloud"].forEach(function (n) {
    out.push("Sheet " + n + ": " + (SpreadsheetApp.getActiveSpreadsheet().getSheetByName(n) ? "OK" : "❌ MISSING"));
  });
  Logger.log(out.join("\n"));
  return out;
}