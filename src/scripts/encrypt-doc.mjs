import { readFileSync, writeFileSync } from "node:fs";
import { randomBytes, pbkdf2Sync, createCipheriv } from "node:crypto";

function u8ToB64(u8) {
  return Buffer.from(u8).toString("base64");
}

function encryptHtmlToPayload(html, password, iter = 200_000) {
  const salt = randomBytes(16);
  const key = pbkdf2Sync(password, salt, iter, 32, "sha256"); // 32 bytes => 256-bit
  const iv = randomBytes(12); // GCM recommended 12 bytes
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(html, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes

  // WebCrypto 的 AES-GCM decrypt 期待 “ciphertext||tag”
  const ctPlusTag = Buffer.concat([ct, tag]);

  return {
    v: 1,
    algo: "AES-GCM",
    iter,
    salt_b64: u8ToB64(salt),
    iv_b64: u8ToB64(iv),
    ct_b64: u8ToB64(ctPlusTag),
  };
}

// 用法：node scripts/encrypt-doc.mjs input.html output.json password
const [,, inPath, outPath, password] = process.argv;
if (!inPath || !outPath || !password) {
  console.error("Usage: node scripts/encrypt-doc.mjs input.html output.json <password>");
  process.exit(1);
}

const html = readFileSync(inPath, "utf8");
const payload = encryptHtmlToPayload(html, password);
writeFileSync(outPath, JSON.stringify(payload, null, 2), "utf8");
console.log("Encrypted ->", outPath);
