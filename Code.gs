// ==========================================
// CONFIGURATION
// ==========================================
const scriptProps = PropertiesService.getScriptProperties();

const SSO_CONFIG = {
  authority: "https://sso.dms.go.th/keycloak/realms/dms/protocol/openid-connect/",
  profileUrl: "https://sso.dms.go.th/dms-sso-api/api/Authen/Verify/Profile",
  clientId: scriptProps.getProperty("CLIENT_ID"),
  clientSecret: scriptProps.getProperty("CLIENT_SECRET"), 
  redirectUri: "https://cloud.dms.go.th/sso-callback.html"
};

function doGet(e) {
  return ContentService.createTextOutput(JSON.stringify({ status: "API Online", timestamp: new Date() }))
    .setMimeType(ContentService.MimeType.JSON);
}

// 1. ตรวจสอบใน doPost(e) ว่ามี case "getSsoLoginUrl" แล้วหรือยัง
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
      
      // 🟢 บรรทัดนี้ต้องมีเพื่อให้เรียก SSO Login ได้
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

// 2. ตรวจสอบว่ามีฟังก์ชัน getSsoLoginUrl() นี้อยู่ในไฟล์ Code.gs
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

// ==========================================
// DATA MANAGEMENT
// ==========================================
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
        const rawStatus = row[16] ? row[16].toString().trim() : '';
        // 🟢 รองรับคำว่า "ใช้งาน" และ "ยืนยันใช้งาน"
        const finalStatus = (rawStatus === 'ใช้งาน' || rawStatus === 'ยืนยันใช้งาน') ? 'ใช้งาน' : 'ไม่ใช้งาน';

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
          status: finalStatus,
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
      if (asset.id !== undefined && asset.id !== null) {
        updates.set(String(asset.id).trim(), asset);
      }
    });

    let isModified = false;
    let modifiedCount = 0;

    for (let i = 1; i < data.length; i++) {
      const rowId = data[i][0] !== undefined && data[i][0] !== null ? String(data[i][0]).trim() : "";
      
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
        
        // 🟢 บันทึกคำว่า "ใช้งาน" หรือ "ไม่ใช้งาน" ลงคอลัมน์ Q
        const saveStatus = (update.status && String(update.status).trim() === 'ใช้งาน') ? 'ใช้งาน' : 'ไม่ใช้งาน';
        data[i][16] = saveStatus; 
        
        // 🟢 บันทึกเวลาลงในคอลัมน์ R (Index 17)
        data[i][17] = new Date(); 
        
        isModified = true;
        modifiedCount++;
      }
    }

    if (isModified) {
      fullRange.setValues(data);
      CacheService.getScriptCache().remove("all_risk_cloud_data");
      return { success: true, message: `อัปเดตข้อมูลสำเร็จ ${modifiedCount} รายการ` };
    } else {
      return { success: false, message: "ไม่พบ ID สินทรัพย์ที่ตรงกันในฐานข้อมูล" };
    }

  } catch (error) {
    return { success: false, message: error.toString() };
  }
}