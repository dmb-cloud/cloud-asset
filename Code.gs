// ==========================================
// CONFIGURATION
// ==========================================
const scriptProps = PropertiesService.getScriptProperties();

const SSO_CONFIG = {
  authority: "https://sso.dms.go.th/keycloak/realms/dms/protocol/openid-connect/",
  profileUrl: "https://sso.dms.go.th/dms-sso-api/api/Authen/Verify/Profile",
  clientId: scriptProps.getProperty("CLIENT_ID") || "dmscloudmanagement",
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
      case "getAgencies": result = getAgencies(); break;
      case "getAllRiskCloudData": result = getAllRiskCloudData(); break;
      case "saveAssessmentData": result = saveAssessmentData(payload); break;
      case "registerUser": result = registerUser(payload.agency, payload.email, payload.phone, payload.fullname); break;
      case "verifyUser": result = verifyUser(payload.agency, payload.email, payload.phone); break;
      case "verifyOTP": result = verifyOTP(payload.email, payload.userOtp); break;
      case "generateAndSaveOTP": result = generateAndSaveOTP(payload.email, payload.fullname); break;
      case "getIndexPage": result = getIndexPage(); break;
      case "getSsoLoginUrl": result = getSsoLoginUrl(); break;
      case "handleSsoCallback": result = handleSsoCallback(payload.code); break;
      default: result = { success: false, message: "Unrecognized Action: " + action };
    }

    return ContentService.createTextOutput(JSON.stringify({ success: true, data: result }))
      .setMimeType(ContentService.MimeType.JSON);
  } catch (error) {
    return ContentService.createTextOutput(JSON.stringify({ success: false, message: error.toString() }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}

// ==========================================
// DMS SSO LOGIC
// ==========================================
function getSsoLoginUrl() {
  try {
    const state = Math.random().toString(36).substring(2) + Date.now().toString(36);
    const authUrl = SSO_CONFIG.authority + "auth?client_id=" + encodeURIComponent(SSO_CONFIG.clientId) +
      "&response_type=code&scope=" + encodeURIComponent("openid profile cid") +
      "&redirect_uri=" + encodeURIComponent(SSO_CONFIG.redirectUri) +
      "&state=" + state + "&nonce=" + state;
    return { success: true, url: authUrl, state: state };
  } catch (error) {
    return { success: false, message: error.toString() };
  }
}

function handleSsoCallback(code) {
  try {
    if (!code) return { success: false, message: "ไม่พบ Authorization Code" };

    const tokenPayload = { grant_type: "authorization_code", code: code, redirect_uri: SSO_CONFIG.redirectUri, client_id: SSO_CONFIG.clientId, client_secret: SSO_CONFIG.clientSecret };
    const tokenOptions = { method: "post", payload: tokenPayload, muteHttpExceptions: true };
    const tokenResponse = UrlFetchApp.fetch(SSO_CONFIG.authority + "token", tokenOptions);
    const tokenData = JSON.parse(tokenResponse.getContentText());

    if (!tokenData.access_token) return { success: false, message: "ไม่สามารถแลก Access Token ได้" };

    const profileOptions = { method: "post", headers: { "AccessToken": tokenData.access_token, "Client-Id": SSO_CONFIG.clientId }, contentType: "application/json", payload: JSON.stringify({}), muteHttpExceptions: true };
    const profileResponse = UrlFetchApp.fetch(SSO_CONFIG.profileUrl, profileOptions);
    const profileData = JSON.parse(profileResponse.getContentText());

    if (profileData && profileData.data && profileData.data.userSsoInfo) {
      const p = profileData.data.userSsoInfo;
      const isThai = (str) => /[\u0E00-\u0E7F]/.test(str || '');
      const possibleFirsts = [p.firstNameTh, p.thFirstName, p.nameTh, p.firstName, p.firstname, p.givenName, p.given_name, p.firstNameEn, p.enFirstName, p.name];
      const possibleLasts = [p.lastNameTh, p.thLastName, p.surnameTh, p.lastName, p.lastname, p.familyName, p.family_name, p.surname, p.lastNameEn, p.enLastName];

      const thFirst = possibleFirsts.filter(Boolean).map(s => s.toString().trim()).find(isThai) || '';
      const thLast = possibleLasts.filter(Boolean).map(s => s.toString().trim()).find(isThai) || '';
      const enFirst = possibleFirsts.filter(Boolean).map(s => s.toString().trim()).find(s => !isThai(s)) || '';
      const enLast = possibleLasts.filter(Boolean).map(s => s.toString().trim()).find(s => !isThai(s)) || '';

      let fullname = "";
      if (thFirst && thLast) fullname = thFirst + " " + thLast;
      else if (thFirst) fullname = thFirst;
      else if (enFirst && enLast) fullname = enFirst + " " + enLast;
      else fullname = p.username || "ผู้ใช้งาน DMS SSO";

      const ssoProfile = {
        username: p.username || p.userName || p.preferred_username || '', title: p.titleName || p.title || p.ttl || p.prefix || '',
        thFirstName: thFirst, thLastName: thLast, enFirstName: enFirst, enLastName: enLast,
        email: p.email || p.mail || '', phone: p.mobile || p.phoneNumber || p.telephone || '',
        position: p.position || p.positionName || p.jobTitle || '', fullname: fullname 
      };

      const dbUser = saveSsoUserToSheet(ssoProfile);
      return { success: true, user: { cid: "", fullname: dbUser.fullname, email: ssoProfile.email, agency: dbUser.agency } };
    } else {
      return { success: false, message: "ไม่พบข้อมูลจากระบบ DMS SSO" };
    }
  } catch (error) {
    return { success: false, message: error.toString() };
  }
}

function saveSsoUserToSheet(profile) {
  let mappedAgency = "เข้าสู่ระบบครั้งแรก (SSO)"; 
  let mappedFullname = profile.fullname;
  let dbPhone = "";

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sheet = ss.getSheetByName('UserDB');
    if (!sheet) { sheet = ss.insertSheet('UserDB'); sheet.appendRow(['Agency', 'Email', 'Phone', 'FullName', 'LastLogin', 'IsActive']); }

    const data = sheet.getDataRange().getValues();
    let userFound = false; let rowIndex = -1;

    for (let i = 1; i < data.length; i++) {
      const dbEmail = data[i][1] ? data[i][1].toString().trim() : '';
      if (profile.email && dbEmail === profile.email) {
        userFound = true; rowIndex = i + 1; 
        mappedAgency = data[i][0] ? data[i][0].toString() : mappedAgency;
        mappedFullname = profile.fullname;
        dbPhone = data[i][2] ? data[i][2].toString().replace(/^'/, '').trim() : '';
        break;
      }
    }

    const finalPhone = profile.phone || dbPhone || "";
    if (userFound) {
      sheet.getRange(rowIndex, 3).setValue("'" + finalPhone); sheet.getRange(rowIndex, 4).setValue(mappedFullname); 
      sheet.getRange(rowIndex, 5).setValue(new Date()); sheet.getRange(rowIndex, 6).setValue(true); 
    } else {
      sheet.appendRow([mappedAgency, profile.email, "'" + finalPhone, profile.fullname, new Date(), true]);
    }

    const logSheet = ss.getSheetByName('Log');
    if (logSheet) {
      logSheet.appendRow([new Date(), mappedAgency, profile.email, "'" + finalPhone, "SUCCESS (SSO Login)", profile.username, profile.title, profile.thFirstName, profile.thLastName, profile.enFirstName, profile.enLastName, profile.position]);
    }
  } catch (err) {}
  return { agency: mappedAgency, fullname: mappedFullname };
}

// ==========================================
// DATA MANAGEMENT
// ==========================================
function getAgencies() {
  const cache = CacheService.getScriptCache();
  const cachedAgencies = cache.get("cache_agencies");
  if (cachedAgencies) return JSON.parse(cachedAgencies);
  try {
    const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName('risk_cloud');
    if (!sheet) return [];
    const data = sheet.getRange(2, 2, sheet.getLastRow() - 1, 1).getValues(); 
    const uniqueAgencies = new Set();
    for (let i = 0; i < data.length; i++) { if (data[i][0]) uniqueAgencies.add(data[i][0].toString().trim()); }
    const agencies = Array.from(uniqueAgencies).filter(Boolean);
    try { cache.put("cache_agencies", JSON.stringify(agencies), 1800); } catch (e) {}
    return agencies;
  } catch (error) { return []; }
}

function getAllRiskCloudData() {
  CacheService.getScriptCache().remove("all_risk_cloud_data");

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
          agency: row[1] ? row[1].toString().trim() : '', 
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
    return assets;
  } catch (error) { return []; }
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
      if (asset.id) updates.set(asset.id.toString().trim(), asset);
    });

    let isModified = false;

    for (let i = 1; i < data.length; i++) {
      const rowId = data[i][0] ? data[i][0].toString().trim() : null;
      
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
        
        // 🟢 บันทึกเวลาประทับลงคอลัมน์ที่ 18 (Index 17) โดยตรง
        data[i][17] = new Date(); 
        
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