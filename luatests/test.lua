local ctid = require "ctid"

local function toHex(bin, sep)
    local space = sep and sep or ''
    local hex = ""
    for i = 1, #bin do
        local b = string.byte(bin, i)
        hex = hex .. string.format("%02X%s", b, space)
    end
    return hex
end

--生成密钥对(hex string)
print("-------------------------keygen-------------------------")
local pub, pri = ctid.keygen()
print("public key:", pub)
print("private key:", pri)

--DER格式的加密解密
--加密
print("-------------------------encrypt-------------------------")
local plaintext = "hello"
local cipher = ctid.encrypt(plaintext, pub)
print("cipher:", toHex(cipher))
--解密
print("-------------------------decrypt-------------------------")
local r = ctid.decrypt(cipher, pri)
print("decrypted text:", r)


--生成签名
print("-------------------------sign-------------------------")
local sigtext = "hell0"
local sig = ctid.sign(sigtext, pub, pri)
print("signature:", toHex(sig))

--验证签名
print("-------------------------verify-------------------------")
local re = ctid.verify(sigtext, toHex(sig), pub)
print("对" .. sigtext .. "验签结果:", re)

--生成SM3 HASH
print("-------------------------SM3-------------------------")
local hash = ctid.sm3digest("hello")
print("hello digest:", toHex(hash))


--对C1C3C2格式的密文解密
--公钥：
local pub_hex =
"04EF97B55A84E24E39517AF95E002EFA2148EB298B1DF8F307B6C2AAF22E34656AE94A6EB8E63FCA15BB7464CB96F222C9BC61BD6E55F4776811EDE522B37B9CE6"
--私钥：
local pri_hex = "711c74e0b6b7fea3a177f26ef15bfd42cbc405fcb61f23da8143a6fab8c05f7f"
local hello_text = "hello"
--对hello加密的密文
local cipher_hex =
"0492bce3198631e31be5acb821c3daac906789881be188be473f8adf3e8841e9bd76a060602129e5f21614b688951a7b9cb6910293c399eed36796d2585a524e61904e71ff9653505791d3ce6f544eb8adba58187f8dbf0fd97ad19234f74416a26f012a31f8"
--对hello的签名
local sig_hex =
"304502205765593cab7a20b034fca3d764ea73ae0052db327dc1e98ae7b9af3b47f1b331022100a00d4bc4c7177092307481a5ba1a44d24d9dad157c5bdf2a722e3a38309edbc9"

--测试解密
print("-------------------------decrypt C1C3C2-------------------------")
local r1 = ctid.decrypt_C1C3C2(cipher_hex, pri_hex)
print("对" .. hello_text .. "进行C1C3C2解密:", r1)


print("-------------------------对指定签名验签-------------------------")
local rr = ctid.verify(hello_text, sig_hex, pub_hex)
print("对指定签名验签结果:", rr)


--测试大文本加密
local bigtext = string.rep('C', 65535, '')
print("解密后的大文本:", ctid.decrypt(ctid.encrypt(bigtext, pub_hex), pri_hex))
