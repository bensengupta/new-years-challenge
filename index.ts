import prompts from "prompts";
import chalk from "chalk";
import logSymbols from "log-symbols";

import { checkPassword, decryptText, decryptFile } from "./utils";

/**
 * Hash is used to verify if password from user input is correct.
 * Key is the key to decrypt the mystery file, that is encrypted using
 * the user input password.
 */
const keys = [
  {
    hash:
      "$argon2i$v=19$m=4096,t=3,p=1$qmqnQzwLZsJZajM4Gpy3KA$uqVsVqy5PedWgv+yDMV+DJe+MEv+Wiwr2A4hhXdSxKA",
    key: {
      iv: "f7d394f259f53a320ce0e4544ae29f63",
      content:
        "b4d5bd941e8c1cbbc665677bd9839bc102bd644dd2625f46a257ed5ac136fdd9300e70dd362a939e4858ca53a44796de42598c0bf7cc9aa0f4ea1e2d19e60f2a64e27bccd2e358f8ac5241827531aa3c24cfee8fc5bf37a784b2841751d7dc2aae7f835b9a8a85c7866b3f8e67e4cbbe86923e83fa0db9b944ce7fb9330e9082",
    },
    file: "mystery",
  },
  {
    hash:
      "$argon2i$v=19$m=4096,t=3,p=1$fGIESWeePe2hGSdCcOCbdQ$EjOGLoY44YmhROJyohp8l1aeUaCy3x3F5GRSpRz/BXA",
    key: {
      iv: "f7cbb83d8c8521cf54398b958d472c55",
      content:
        "2e29f64bffe3b7baefc9a8335cd671ceced05c7fa8d0be25015aac16ac7afb38a7667c6beef27a8440715776519c3566010c0116a13a29841e0c4200a267670cb83a7dd31732eb00f972d18f84e700ef5b0461d2ba1b3dd5ff2137ca06bc778efe3221b4c8d0fdbe556d68975b7a1d61f96f50b7a717923dbf8dbcd70574a26a",
    },
    file: "mystery",
  },
  {
    hash:
      "$argon2i$v=19$m=4096,t=3,p=1$G9hjYxHw/pMddRC0YMESeA$vz81410kr/dFZEhBUrlwHwiXdpQG7KNj/+g63rqkKcs",
    key: {
      iv: "35b5955543a4145a5236d3a48a0ec7be",
      content:
        "7732c0eac55634e823848565ddd7138275e3fcf2f571a5992bcc7b2642c6c6f040ab53ccf2385d4fce5757ffe4f855b290ef5a1bfb84d5588438471be1d38aff9f774e31d57d78d3a8b283eb8deaf7db475c31d587f1545185b2f810b6f66ade915862d993bf53d899ff473052a11dbeb5faa870592cb54afa8a1e59c4f68f55fcb73a3320f6690d600d05e5029b434d092f577f00183d88374c7de83d85433c08cec64702a19aec2526f44947935d818f148406d9ad811a366f4b5af7ef0cb8802484c2a633860aa842e6d73ccd4517a064e6bbae4008e1b8bba70935e926812153b5397b0ab5e9c8347f01fdadd6822aa8fd983808215fc126715d2ff565077686c3d4b0da3f55e6b01b3a416e74db20ec9c268e834102d19d828c16f168b20a995a653de1090f059dfe80d3696df7dd3b5f870cdc983876dacb0b11faf3c1a95f6204db1391f4c92969afb32f4bebea0fa859",
    },
    file: "secret",
  },
  {
    hash:
      "$argon2i$v=19$m=4096,t=3,p=1$Srfeh+7GCMTA+PK8W+DOqA$I9oX0diP6QKMn54SnhcluCaL0t1WkN4nGtamobauKqM",
    key: {
      iv: "99e7e2e12183fc305abdc66debcff588",
      content:
        "d71d58ee7cdfc4ba867059bdce223c52795de326357555e4b262d211639621340347046d3dca5cd3c6e50e0be3a069fd0aa320df912676d4200f07e8fc023b4524059a8e509dce91703969fe4ae8ca8c6626afadb4d3f0555d2031f6c54ebe8bab291a012c3b37ff7ea70f1d18374235d50801804fa1c15e136d90404df2e1fa7a229039bfdc07e483decd817584a0c608d0d865380464dc26afe8f4710009ce1e0427701b904735b733d3653d3609b2008887a582a618bdf5809d0f8850bc7111b108756d6a3e2c2760fe92d74ebea5f734efaba6ea8d8dab557e2f50323adcd3befdc545053efc0e05c3cfee628da99e645f63227a2ed13d042cbc53665e0eed1b660a6cfb1654f121a2ad519110b49d25d838788df2850eafaf9b1d95a547036452ab74847c709eed40939c051fc0aec9c8ba71d3d34a5c2e8f0c19149f575339d3104fca9bc5a8b4170ddcb9aedf7b40e608",
    },
    file: "secret",
  },
];

(async function () {
  // Position of password in keys arary
  let matchedIndex = -1;
  let password = "";

  console.log(
    chalk.bold(chalk.blue("Decrypt file:")),
    "Enter passphrase to continue"
  );

  do {
    const response = await prompts(
      {
        type: "text",
        name: "password",
        message: "Passphrase?",
      },
      { onCancel: () => process.exit(0) }
    );

    matchedIndex = await checkPassword(
      response.password,
      keys.map((k) => k.hash)
    );

    if (matchedIndex !== -1) {
      console.log(logSymbols.success, "Passphrase valid, decrypting file...");
      password = response.password;
    } else {
      console.log(logSymbols.error, "Passphrase invalid, try again.");
    }
  } while (matchedIndex === -1);

  // Decrypt file with password
  const { key, file } = keys[matchedIndex];

  const fileKey = decryptText(key, password);

  decryptFile(fileKey, file, `${file}.jpg`);
})();
