import argon2 from "argon2";
import crypto from "crypto";
import fs from "fs";
import AdmZip from "adm-zip";

const fileIV = Buffer.from("1065faf25ac5560968c58ce6dc0ae36f", "hex");

const genKey = (seed: string) => {
  return crypto
    .createHash("sha256")
    .update(String(seed))
    .digest("base64")
    .substr(0, 32);
};

// Hashing section
export async function checkPassword(
  password: string,
  hashes: string[]
): Promise<number> {
  const results = await Promise.all(
    hashes.map((hash) => argon2.verify(hash, password))
  );

  return results.indexOf(true);
}

// Encryption / Decryption section
const algorithm = "aes-256-ctr";

type Key = { iv: string; content: string };

export function decryptText(hash: Key, password: string) {
  // Generate hash from password
  let secretKey = genKey(password);

  const decipher = crypto.createDecipheriv(
    algorithm,
    secretKey,
    Buffer.from(hash.iv, "hex")
  );

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(hash.content, "hex")),
    decipher.final(),
  ]);

  return decrypted.toString();
}

// File encryption / decryption
export function decryptFile(
  key: string,
  inputFile: string,
  outputFile: string
) {
  const zip = new AdmZip("./mysteryfile");
  const inputData = zip.getEntry(inputFile).getData();
  const cipher = crypto.createDecipheriv(algorithm, genKey(key), fileIV);
  const output = Buffer.concat([cipher.update(inputData), cipher.final()]);
  fs.writeFileSync(outputFile, output);
}
