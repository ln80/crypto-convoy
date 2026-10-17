// canonical.v1.json: every type of the canonical encoding (§1). Expected bytes are written by hand.
import { writeVectors } from "./common.mjs";

const cases = [
  { name: "u8 zero", fields: [["u8", 0]], encoded: "00" },
  { name: "u8 max", fields: [["u8", 255]], encoded: "ff" },
  { name: "u32 one", fields: [["u32", 1]], encoded: "00000001" },
  { name: "u32 max", fields: [["u32", 4294967295]], encoded: "ffffffff" },
  { name: "u64 2^32", fields: [["u64", 4294967296]], encoded: "0000000100000000" },
  { name: "u64 max safe", fields: [["u64", 9007199254740991]], encoded: "001fffffffffffff" },
  { name: "bytes empty", fields: [["bytes", ""]], encoded: "00000000" },
  { name: "bytes three", fields: [["bytes", "a1b2c3"]], encoded: "00000003a1b2c3" },
  { name: "string ascii", fields: [["string", "team"]], encoded: "000000047465616d" },
  { name: "string utf-8", fields: [["string", "é"]], encoded: "00000002c3a9" },
  { name: "list empty", fields: [["list", []]], encoded: "00000000" },
  {
    name: "list of u32 and bytes pairs",
    fields: [["list", [[["u32", 0], ["bytes", "ff"]], [["u32", 1], ["bytes", ""]]]]],
    encoded: "00000002" + "00000000" + "00000001ff" + "00000001" + "00000000",
  },
  { name: "optional absent", fields: [["optional", null]], encoded: "00" },
  { name: "optional present string", fields: [["optional", ["string", "d"]]], encoded: "010000000164" },
  {
    name: "label then fields",
    fields: [["string", "crypto-convoy/v1/grant"], ["u32", 7]],
    encoded: "00000016" + Buffer.from("crypto-convoy/v1/grant").toString("hex") + "00000007",
  },
];

const refused = [
  { name: "truncated u32", read: "u32", encoded: "000001" },
  { name: "bytes length past the end", read: "bytes", encoded: "00000005aabb" },
  { name: "trailing byte", read: "u32", encoded: "0000000100" },
  { name: "optional flag 2", read: "optional-u8", encoded: "0201" },
  { name: "invalid utf-8 string", read: "string", encoded: "00000001ff" },
  { name: "u64 above 2^53", read: "u64", encoded: "0020000000000000" },
];

writeVectors("canonical.v1.json", {
  file: "canonical.v1",
  covers: "Protocol §1, canonical encoding",
  cases,
  refused,
});
