// ==========================================
// CONFIGURATION
// ==========================================
// ดึงค่า Secret จาก Project Settings (ตั้งค่าโปรเจกต์ > คุณสมบัติของสคริปต์)
const scriptProps = PropertiesService.getScriptProperties();

const SSO_CONFIG = {
  authority: "https://sso.dms.go.th/keycloak/realms/dms/protocol/openid-connect/",
  profileUrl: "https://sso.dms.go.th/dms-sso-api/api/Authen/Verify/Profile",
  
  // 🟢 ดึงค่าจากตัวแปรที่ซ่อนไว้ (ไม่ฮาร์ดโค้ดในนี้แล้ว)
  clientId: scriptProps.getProperty("CLIENT_ID"),
  clientSecret: scriptProps.getProperty("CLIENT_SECRET"), 
  
  redirectUri: "https://cloud.dms.go.th/sso-callback.html"
};

// 1. ฟังก์ชันรองรับการเช็กสถานะการเชื่อมต่อ (GET)
function doGet(e) {
  return ContentService.createTextOutput(JSON.stringify({ status: "API Online", timestamp: new Date() }))
    .setMimeType(ContentService.MimeType.JSON);
}

// 2. ฟังก์ชันหลักสำหรับรับคำสั่งจาก GitHub Pages (POST)
function doPost(e) {
  try {
    const data = JSON.parse(e.postData.contents);
    const action = data.action;
    const payload = data.payload || {};
    let result = {};

    switch (action) {
      case "getAgencies":
        result = getAgencies();
        break;
      case "getAllRiskCloudData":
        result = getAllRiskCloudData();
        break;
      case "saveAssessmentData":
        result = saveAssessmentData(payload);
        break;
      case "registerUser":
        result = registerUser(payload.agency, payload.email, payload.phone, payload.fullname);
        break;
      case "verifyUser":
        result = verifyUser(payload.agency, payload.email, payload.phone);
        break;
      case "verifyOTP":
        result = verifyOTP(payload.email, payload.userOtp);
        break;
      case "generateAndSaveOTP":
        result = generateAndSaveOTP(payload.email, payload.fullname);
        break;
      case "getIndexPage":
        result = getIndexPage();
        break;
        
      // 🟢 Action สำหรับ DMS SSO
      case "getSsoLoginUrl":
        result = getSsoLoginUrl();
        break;
      case "handleSsoCallback":
        result = handleSsoCallback(payload.code);
        break;

      default:
        result = { success: false, message: "Unrecognized Action: " + action };
    }

    return ContentService.createTextOutput(JSON.stringify({ success: true, data: result }))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    return ContentService.createTextOutput(JSON.stringify({ success: false, message: error.toString() }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}

// ==========================================
// DMS SSO LOGIC (Keycloak & Profile API)
// ==========================================

function getSsoLoginUrl() {
  try {
    const state = Math.random().toString(36).substring(2) + Date.now().toString(36);
    const authUrl = SSO_CONFIG.authority + "auth?" +
      "client_id=" + encodeURIComponent(SSO_CONFIG.clientId) +
      "&response_type=code" +
      "&scope=" + encodeURIComponent("openid profile cid") +
      "&redirect_uri=" + encodeURIComponent(SSO_CONFIG.redirectUri) +
      "&state=" + state +
      "&nonce=" + state;
      
    return { success: true, url: authUrl, state: state };
  } catch (error) {
    return { success: false, message: error.toString() };
  }
}

function handleSsoCallback(code) {
  try {
    if (!code) return { success: false, message: "ไม่พบ Authorization Code" };

    const tokenPayload = {
      grant_type: "authorization_code",
      code: code,
      redirect_uri: SSO_CONFIG.redirectUri,
      client_id: SSO_CONFIG.clientId,
      client_secret: SSO_CONFIG.clientSecret
    };

    const tokenOptions = {
      method: "post",
      payload: tokenPayload,
      muteHttpExceptions: true
    };

    const tokenResponse = UrlFetchApp.fetch(SSO_CONFIG.authority + "token", tokenOptions);
    const tokenData = JSON.parse(tokenResponse.getContentText());

    if (!tokenData.access_token) {
      return { success: false, message: "ไม่สามารถแลก Access Token ได้: " + (tokenData.error_description || tokenData.error) };
    }

    const accessToken = tokenData.access_token;

    const profileOptions = {
      method: "post",
      headers: {
        "AccessToken": accessToken,
        "Client-Id": SSO_CONFIG.clientId
      },
      contentType: "application/json",
      payload: JSON.stringify({}),
      muteHttpExceptions: true
    };

    const profileResponse = UrlFetchApp.fetch(SSO_CONFIG.profileUrl, profileOptions);
    const profileData = JSON.parse(profileResponse.getContentText());

    if (profileData && profileData.data && profileData.data.userSsoInfo) {
      const p = profileData.data.userSsoInfo;
      
      // 🟢 ฟังก์ชันเช็กตัวอักษรเพื่อแยก ไทย/อังกฤษ ชัดเจน
      const isThai = (str) => /[\u0E00-\u0E7F]/.test(str || '');
      const isEng = (str) => /[a-zA-Z]/.test(str || '') && !isThai(str);

      const possibleFirsts = [p.firstNameTh, p.thFirstName, p.nameTh, p.firstName, p.firstname, p.givenName, p.given_name, p.firstNameEn, p.enFirstName, p.name];
      const possibleLasts = [p.lastNameTh, p.thLastName, p.surnameTh, p.lastName, p.lastname, p.familyName, p.family_name, p.surname, p.lastNameEn, p.enLastName];

      const pFirsts = possibleFirsts.filter(Boolean).map(s => s.toString().trim());
      const pLasts = possibleLasts.filter(Boolean).map(s => s.toString().trim());

      // แยกภาษาไทย-อังกฤษ อย่างแม่นยำ
      const thFirst = pFirsts.find(isThai) || '';
      const thLast = pLasts.find(isThai) || '';
      const enFirst = pFirsts.find(isEng) || '';
      const enLast = pLasts.find(isEng) || '';

      // ประกอบร่างชื่อ-สกุล เป็นภาษาไทยให้แสดงผลที่เว็บ (หากไม่มีใช้ภาษาอังกฤษแทน)
      let fullname = "";
      if (thFirst && thLast) fullname = thFirst + " " + thLast;
      else if (thFirst) fullname = thFirst;
      else if (enFirst && enLast) fullname = enFirst + " " + enLast;
      else fullname = p.username || "ผู้ใช้งาน DMS SSO";

      const ssoProfile = {
        username: p.username || p.userName || p.preferred_username || '',
        title: p.titleName || p.title || p.ttl || p.prefix || '',
        thFirstName: thFirst,
        thLastName: thLast,
        enFirstName: enFirst,
        enLastName: enLast,
        email: p.email || p.mail || p.cid || '',
        phone: p.mobile || p.phoneNumber || p.telephone || '',
        cid: p.cid || p.citizenId || p.personalId || '',
        position: p.position || p.positionName || p.jobTitle || '',
        fullname: fullname
      };

      // ส่งไปบันทึกลง UserDB และ Log
      const dbUser = saveSsoUserToSheet(ssoProfile);

      return {
        success: true,
        user: {
          cid: ssoProfile.cid,
          fullname: dbUser.fullname,
          email: ssoProfile.email,
          agency: dbUser.agency 
        }
      };
    } else {
      return { success: false, message: "ไม่พบข้อมูล userSsoInfo จากระบบ DMS SSO" };
    }

  } catch (error) {
    return { success: false, message: error.toString() };
  }
}

// 🟢 ฟังก์ชันบันทึกและจับคู่ข้อมูล (อัปเดตให้บันทึกข้อมูลครบถ้วนลง UserDB)
function saveSsoUserToSheet(profile) {
  let mappedAgency = "เข้าสู่ระบบครั้งแรก (SSO)"; 
  let mappedFullname = profile.fullname;

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sheet = ss.getSheetByName('UserDB');
    
    if (!sheet) {
      sheet = ss.insertSheet('UserDB');
      sheet.appendRow(['Agency', 'Email', 'Phone/CID', 'FullName', 'LastLogin', 'IsActive', 'Username', 'Title', 'ThFirstName', 'ThLastName', 'EnFirstName', 'EnLastName', 'CID', 'Position']);
    }

    const data = sheet.getDataRange().getValues();
    let userFound = false;
    let rowIndex = -1;

    for (let i = 1; i < data.length; i++) {
      const dbEmail = data[i][1] ? data[i][1].toString().trim() : '';
      const dbPhoneCid = data[i][2] ? data[i][2].toString().replace(/^'/, '').trim() : '';

      if ((profile.email && dbEmail === profile.email) || (profile.cid && dbPhoneCid === profile.cid.toString())) {
        userFound = true;
        rowIndex = i + 1;
        
        mappedAgency = data[i][0] ? data[i][0].toString() : mappedAgency;
        mappedFullname = profile.fullname; // อัปเดตชื่อเป็นแบบล่าสุด
        break;
      }
    }

    if (userFound) {
      // 📍 อัปเดตข้อมูลของผู้ใช้เดิม ลงใน UserDB
      sheet.getRange(rowIndex, 3).setValue("'" + profile.cid);
      sheet.getRange(rowIndex, 4).setValue(mappedFullname); 
      sheet.getRange(rowIndex, 5).setValue(new Date()); 
      sheet.getRange(rowIndex, 6).setValue(true); 
      sheet.getRange(rowIndex, 7).setValue(profile.username);
      sheet.getRange(rowIndex, 8).setValue(profile.title);
      sheet.getRange(rowIndex, 9).setValue(profile.thFirstName);
      sheet.getRange(rowIndex, 10).setValue(profile.thLastName);
      sheet.getRange(rowIndex, 11).setValue(profile.enFirstName);
      sheet.getRange(rowIndex, 12).setValue(profile.enLastName);
      sheet.getRange(rowIndex, 13).setValue("'" + profile.cid);
      sheet.getRange(rowIndex, 14).setValue(profile.position);
    } else {
      // 📍 สร้างผู้ใช้ใหม่ พร้อมข้อมูลครบถ้วน ลงใน UserDB
      sheet.appendRow([
        mappedAgency, profile.email, "'" + profile.cid, profile.fullname, new Date(), true,
        profile.username, profile.title, profile.thFirstName, profile.thLastName, profile.enFirstName, profile.enLastName, "'" + profile.cid, profile.position
      ]);
    }

    // 📍 บันทึกลง Log ด้วยเช่นกัน
    const logSheet = ss.getSheetByName('Log');
    if (logSheet) {
      logSheet.appendRow([
        new Date(), mappedAgency, profile.email, profile.phone || profile.cid, "SUCCESS (SSO Login)",
        profile.username, profile.title, profile.thFirstName, profile.thLastName, profile.enFirstName, profile.enLastName, "'" + profile.cid, profile.position
      ]);
    }

  } catch (err) {
    Logger.log("Error in saveSsoUserToSheet: " + err.toString());
  }

  return { agency: mappedAgency, fullname: mappedFullname };
}

// ==========================================
// AUTH LOGIC (OTP & REGISTER)
// ==========================================

function registerUser(agency, email, phone, fullname) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName('UserDB');
  if (!sheet) return { success: false, message: "ไม่พบฐานข้อมูล UserDB" };
  
  const data = sheet.getDataRange().getValues();
  
  for (let i = 1; i < data.length; i++) {
    if (data[i][1] === email) {
      return { success: false, message: "อีเมลนี้มีอยู่ในระบบแล้ว" };
    }
  }
  
  sheet.appendRow([agency, email, "'" + phone, fullname, new Date(), false]);
  return { success: true, message: "สมัครเสร็จบันทึกเรียบร้อย โปรดติดต่อเจ้าหน้าที่เพื่อนุมัติ" };
}

function verifyUser(agency, email, phone) {
  const cache = CacheService.getScriptCache();
  const lockKey = "lock_" + email;
  const attemptKey = "attempt_" + email;
  const ss = SpreadsheetApp.getActiveSpreadsheet();

  function writeLog(statusMsg) {
    const logSheet = ss.getSheetByName('Log');
    if (logSheet) {
      logSheet.appendRow([new Date(), agency, email, phone, statusMsg]);
    }
  }
  
  if (cache.get(lockKey)) {
    writeLog("LOCKED (บัญชีถูกระงับอยู่)");
    return { success: false, locked: true, message: "บัญชีนี้ถูกระงับชั่วคราวเป็นเวลา 3 นาที" };
  }

  const sheet = ss.getSheetByName('UserDB');
  if (!sheet) return { success: false, locked: false, message: "ไม่พบฐานข้อมูล UserDB" };
  
  const data = sheet.getDataRange().getValues();
  
  let emailFound = false;
  let isMatch = false;
  let fullname = "";
  let isActive = false;

  for (let i = 1; i < data.length; i++) {
    if (data[i][1] == email) {
      emailFound = true;
      let dbPhone = data[i][2].toString().replace(/^'/, ''); 
      
      if (data[i][0] == agency && dbPhone == phone) {
        isMatch = true;
        fullname = data[i][3];
        isActive = (data[i][5] === true || data[i][5] === 'TRUE' || data[i][5] === 'true');
        break; 
      }
    }
  }
  
  if (!emailFound) {
    writeLog("FAILED (ไม่มีอีเมลในระบบ)");
    return { success: false, locked: false, message: "ไม่พบข้อมูลบัญชีนี้ในระบบ" };
  }

  if (!isMatch) {
    let attempts = parseInt(cache.get(attemptKey) || "0");
    attempts++;
    
    if (attempts >= 5) {
      cache.put(lockKey, "true", 180);
      cache.remove(attemptKey);
      
      const otpSheet = ss.getSheetByName('OtpDB');
      if (otpSheet) otpSheet.appendRow([email, "LOCKED", new Date(), "locked_3mins"]);
      
      writeLog("LOCKED (กรอกผิดครบ 5 ครั้ง)");
      return { success: false, locked: true, message: "ข้อมูลไม่ถูกต้องครบ 5 ครั้ง บัญชีถูกระงับชั่วคราว (3 นาที)" };
    } else {
      cache.put(attemptKey, attempts.toString(), 3600);
      writeLog(`FAILED (ข้อมูลไม่ตรง - ครั้งที่ ${attempts})`);
      return { success: false, locked: false, message: `หน่วยงานหรือเบอร์โทรศัพท์ไม่ถูกต้อง (ผิดพลาด ${attempts}/5 ครั้ง)` };
    }
  }
  
  if (!isActive) {
    writeLog("FAILED (รออนุมัติ)");
    return { success: false, locked: false, inactive: true, message: "โปรดติดต่อเจ้าหน้าที่เพื่อนุมัติ" };
  }

  cache.remove(attemptKey);
  writeLog("SUCCESS (ขอ OTP สำเร็จ)");
  return generateAndSaveOTP(email, fullname); 
}

function generateAndSaveOTP(email, fullname) {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 5 * 60000);
  
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('OtpDB');
  if (sheet) sheet.appendRow([email, otp, expiresAt, "pending"]);
  
  const body = `สวัสดีคุณ ${fullname}\n\nรหัส OTP สำหรับเข้าสู่ระบบคลาวด์ของคุณคือ: ${otp}\nรหัสนี้จะหมดอายุในอีก 5 นาที\n\nหากคุณไม่ได้ทำรายการนี้ กรุณาเพิกเฉยต่ออีเมลฉบับนี้`;
  MailApp.sendEmail(email, "รหัส OTP ยืนยันการเข้าสู่ระบบ", body);
  
  return { success: true, message: "ระบบได้ส่งรหัส OTP ไปยังอีเมลของท่านแล้ว", fullname: fullname };
}

function verifyOTP(email, userOtp) {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('OtpDB');
  if (!sheet) return { success: false, message: "ไม่พบฐานข้อมูล OtpDB" };
  
  const data = sheet.getDataRange().getValues();
  const now = new Date();
  
  for (let i = data.length - 1; i >= 1; i--) {
    if (data[i][0] == email) {
      const dbOtp = data[i][1].toString();
      const expiresAt = new Date(data[i][2]);
      const status = data[i][3];
      
      if (status !== "pending") return { success: false, message: "รหัสนี้ถูกใช้งานไปแล้ว หรือถูกยกเลิก" };
      if (now > expiresAt) {
        sheet.getRange(i + 1, 4).setValue("expired");
        return { success: false, message: "รหัส OTP หมดอายุแล้ว กรุณาขอใหม่" };
      }
      if (dbOtp === userOtp.toString().trim()) {
        sheet.getRange(i + 1, 4).setValue("used");
        return { success: true, message: "ยืนยันตัวตนสำเร็จ" };
      } else {
        return { success: false, message: "รหัส OTP ไม่ถูกต้อง" };
      }
    }
  }
  return { success: false, message: "ไม่พบข้อมูลการขอ OTP" };
}

// ==========================================
// OPTIMIZED DATA MANAGEMENT (FAST SPEED)
// ==========================================

function getIndexPage() {
  try {
    return HtmlService.createHtmlOutputFromFile('index').getContent();
  } catch (error) {
    return `<div style="text-align:center; padding: 50px;">
              <h2 style="color: red;">เกิดข้อผิดพลาดในการโหลดหน้าเว็บ</h2>
              <p>ไม่พบไฟล์ <b>index.html</b></p>
            </div>`;
  }
}

function testMailPermission() {
  const myEmail = Session.getActiveUser().getEmail();
  MailApp.sendEmail(myEmail, "ทดสอบสิทธิ์ส่งอีเมล", "ระบบสามารถส่งอีเมลได้เรียบร้อยแล้ว");
  Logger.log("ส่งอีเมลสำเร็จไปยัง: " + myEmail);
}

function getAgencies() {
  const cache = CacheService.getScriptCache();
  const cachedAgencies = cache.get("cache_agencies");
  if (cachedAgencies) return JSON.parse(cachedAgencies);

  try {
    const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('risk_cloud');
    if (!sheet) return [];
    
    const data = sheet.getRange(2, 2, sheet.getLastRow() - 1, 1).getValues(); 
    const uniqueAgencies = new Set();
    
    for (let i = 0; i < data.length; i++) {
      if (data[i][0]) uniqueAgencies.add(data[i][0].toString().trim());
    }
    
    const agencies = Array.from(uniqueAgencies).filter(Boolean);
    try { cache.put("cache_agencies", JSON.stringify(agencies), 1800); } catch (e) {}
    
    return agencies;
  } catch (error) {
    return [];
  }
}

function getAllRiskCloudData() {
  const cache = CacheService.getScriptCache();
  const cachedData = cache.get("all_risk_cloud_data");
  if (cachedData) return JSON.parse(cachedData);

  try {
    const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('risk_cloud');
    if (!sheet) return [];
    
    const data = sheet.getDataRange().getValues();
    const assets = [];
    
    for (let i = 1; i < data.length; i++) {
      const row = data[i];
      if(row[1]) {
        const hasSaved = (row[8] && row[8].toString().trim() !== "") || (row[10] && row[10].toString().trim() !== "");

        assets.push({
          id: row[0] ? row[0].toString() : '',
          agency: row[1] ? row[1].toString() : '',
          typeFilter: row[2] ? row[2].toString() : '', 
          name: row[3] ? row[3].toString() : '',       
          ip: row[4] ? row[4].toString() : '',          
          privateIp: row[5] ? row[5].toString() : '',   
          projectId: row[6] ? row[6].toString() : '',
          domain: row[7] ? row[7].toString() : '',      
          contact: row[8] ? row[8].toString() : '',
          note: row[9] ? row[9].toString() : '',         
          sysType: row[10] ? row[10].toString() : 'ระบบบริการ (Web Services)',
          pdpa: (row[11] === true || row[11] === 'TRUE' || row[11] === 'ใช่'),
          c: parseInt(row[12]) || 1,
          i: parseInt(row[13]) || 1,
          a: parseInt(row[14]) || 1,
          impact: parseInt(row[15]) || 1,
          status: (row[16] && row[16].toString().trim() !== '') ? row[16].toString().trim() : 'ไม่ใช้งาน',
          isSaved: hasSaved
        });
      }
    }
    
    try { cache.put("all_risk_cloud_data", JSON.stringify(assets), 1800); } catch(e) {}
    return assets;
  } catch (error) {
    return [];
  }
}

function saveAssessmentData(payload) {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName('risk_cloud');
    if (!sheet) return { success: false, message: "ไม่พบชีต risk_cloud" };

    const logSheet = ss.getSheetByName('Sheet1');
    if (logSheet) {
      logSheet.appendRow([new Date(), payload.agency, payload.assessor, "อัปเดตแบบประเมินความเสี่ยง", payload.assets.length + " รายการ"]);
    }

    const fullRange = sheet.getDataRange();
    const data = fullRange.getValues();
    
    const updates = new Map();
    payload.assets.forEach(asset => {
      if (asset.id) updates.set(asset.id.toString(), asset);
    });

    let isModified = false;

    for (let i = 1; i < data.length; i++) {
      const rowId = data[i][0] ? data[i][0].toString() : null;
      
      if (rowId && updates.has(rowId)) {
        const update = updates.get(rowId);
        
        data[i][3]  = update.resourceName || '';               
        data[i][8]  = payload.assessor || '';                  
        data[i][9]  = update.note || '';                       
        data[i][10] = update.sysType || 'ระบบบริการ (Web Services)'; 
        data[i][11] = update.pdpa ? "TRUE" : "FALSE";         
        data[i][12] = parseInt(update.c) || 1;               
        data[i][13] = parseInt(update.i) || 1;               
        data[i][14] = parseInt(update.a) || 1;               
        data[i][15] = parseInt(update.impact) || 1;          
        data[i][16] = (update.status && update.status.toString().trim() !== '') ? update.status.toString().trim() : 'ไม่ใช้งาน'; 
        
        isModified = true;
      }
    }

    if (isModified) {
      fullRange.setValues(data);
    }
    
    CacheService.getScriptCache().remove("all_risk_cloud_data");
    return { success: true, message: "บันทึกการประเมินลงฐานข้อมูลเรียบร้อยแล้ว!" };

  } catch (error) {
    return { success: false, message: error.toString() };
  }
}