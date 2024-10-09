import binascii
from nacl.signing import SigningKey
import nacl.bindings
import hashlib

'''
world更新条件
(_id == update._id)&&(_ts < update._ts)&&(_type == update._type)
'''

def parseUintFromBytes(data, offset, length):
    """从二进制数据中解析无符号整数"""
    return int.from_bytes(data[offset:offset + length], byteorder='big'), offset + length


def parseIpAddress(data, offset, ipType):
    """根据类型解析 IP 地址，ipv4 和 ipv6"""
    if ipType == 0x04:  # IPv4
        ipBytes = data[offset:offset + 4]
        ipAddress = ".".join(map(str, ipBytes))
        offset += 4
    elif ipType == 0x06:  # IPv6
        ipBytes = data[offset:offset + 16]
        ipAddress = ":".join(f"{(ipBytes[i] << 8) + ipBytes[i + 1]:x}" for i in range(0, 16, 2))
        offset += 16
    else:  # 如果是占位符（类型0x00），返回 None
        ipAddress = None
    return ipAddress, offset


def bytesToHex(data):
    """将字节数组转换为16进制字符串"""
    return binascii.hexlify(data).decode('utf-8')


def parseWorldFile(filePath):
    with open(filePath, "rb") as f:
        data = f.read()
        offset = 0

        typeByte, offset = parseUintFromBytes(data, offset, 1)
        idBytes, offset = parseUintFromBytes(data, offset, 8)
        tsBytes, offset = parseUintFromBytes(data, offset, 8)

        publicKey = bytesToHex(data[offset:offset + 64])
        offset += 64
        signature = bytesToHex(data[offset:offset + 96])
        offset += 96

        rootsCount, offset = parseUintFromBytes(data, offset, 1)
        roots = []

        for _ in range(rootsCount):
            address = bytesToHex(data[offset:offset + 5])
            offset += 5
            identityType, offset = parseUintFromBytes(data, offset, 1)
            rootPublicKey = bytesToHex(data[offset:offset + 64])
            offset += 64
            placeholder, offset = parseUintFromBytes(data, offset, 1)

            stableEndpointsCount, offset = parseUintFromBytes(data, offset, 1)
            stableEndpoints = []

            for _ in range(stableEndpointsCount):
                endpointType, offset = parseUintFromBytes(data, offset, 1)

                ipAddress, offset = parseIpAddress(data, offset, endpointType)
                port, offset = parseUintFromBytes(data, offset, 2)

                if ipAddress:
                    stableEndpoints.append({
                        "type": endpointType,
                        "ip": ipAddress,
                        "port": str(port)
                    })

            roots.append({
                "address": address,
                "identity_type": identityType,
                "public_key": rootPublicKey,
                "stable_endpoints": stableEndpoints
            })

        return {
            "type": typeByte,
            "id": idBytes,
            "timestamp": tsBytes,
            "public_key": publicKey,
            "signature": signature,
            "roots": roots
        }


def generateKeypair():
    """生成密钥对"""
    signingKey = SigningKey.generate()
    verifyKey = signingKey.verify_key

    privateKey = signingKey.encode()
    publicKey = verifyKey.encode()

    return privateKey, publicKey


def derivePublicKey(privateKey):
    """从私钥读取公钥"""
    signingKey = SigningKey(privateKey[:32])
    verifyKey = signingKey.verify_key
    return verifyKey.encode()


def signMessage(privateKeyBytes, publicKeyBytes, message):
    """签署消息"""
    digest = hashlib.sha512(message).digest()
    extsk = hashlib.sha512(bytearray(privateKeyBytes)).digest()

    extsk = bytearray(extsk)
    extsk[0] &= 248
    extsk[31] &= 127
    extsk[31] |= 64

    extsk = bytes(extsk)

    sig = bytearray(96)
    sig[32:64] = extsk[32:64]
    sig[64:96] = digest[:32]

    hmg = hashlib.sha512(sig[32:96]).digest()
    rPoint = nacl.bindings.crypto_core_ed25519_scalar_reduce(hmg)
    R = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(rPoint)

    sig[0:32] = R

    hramInput = sig
    for i in range(32):
        hramInput[32 + i] = publicKeyBytes[i]
    
    hram = hashlib.sha512(hramInput).digest()
    scs = nacl.bindings.crypto_core_ed25519_scalar_reduce(hram)

    scsk = nacl.bindings.crypto_core_ed25519_scalar_reduce(extsk)
    scs = nacl.bindings.crypto_core_ed25519_scalar_mul(scs, scsk)
    finalScalar = nacl.bindings.crypto_core_ed25519_scalar_add(scs, rPoint)

    sig[32:64] = finalScalar

    return sig


def uintToBytes(value, length):
    """将无符号整数转换为指定长度的字节"""
    return value.to_bytes(length, byteorder='big')


def hexToBytes(hexStr):
    """将16进制字符串转换为字节数组"""
    return binascii.unhexlify(hexStr)


def ipToBytes(ipAddress, ipType):
    """将 IP 地址转换为字节，支持 IPv4 和 IPv6"""
    if ipType == 0x04:
        return bytes(map(int, ipAddress.split('.')))
    elif ipType == 0x06:
        segments = ipAddress.split(':')
        return b''.join(int(segment, 16).to_bytes(2, byteorder='big') for segment in segments)
    return b''


def writeWorldDataAsBytes(WorldInfo, forSign=False):
    """将 World_info 转换为字节数组"""
    data = bytearray()
    
    if forSign:
        data.extend(hexToBytes('7f7f7f7f7f7f7f7f'))
    
    data.extend(uintToBytes(WorldInfo['type'], 1))
    data.extend(uintToBytes(WorldInfo['id'], 8))
    data.extend(uintToBytes(WorldInfo['timestamp'], 8))

    data.extend(hexToBytes(WorldInfo['public_key']))
    
    if not forSign:
        data.extend(hexToBytes(WorldInfo['signature']))

    data.extend(uintToBytes(len(WorldInfo['roots']), 1))
    
    for root in WorldInfo['roots']:
        data.extend(hexToBytes(root['address']))
        data.extend(uintToBytes(root["identity_type"], 1))
        data.extend(hexToBytes(root['public_key']))
        data.append(0x00)

        data.extend(uintToBytes(len(root['stable_endpoints']), 1))
        
        for endpoint in root['stable_endpoints']:
            data.extend(uintToBytes(endpoint['type'], 1))
            data.extend(ipToBytes(endpoint['ip'], endpoint['type']))
            data.extend(uintToBytes(int(endpoint['port']), 2))

    if WorldInfo['type'] == 127:
        data.append(uintToBytes(0, 2))

    if forSign:
        data.extend(hexToBytes('f7f7f7f7f7f7f7f7'))

    return data

if __name__ == '__main__':
    privateKey, publicKey= generateKeypair()
    World_info = parseWorldFile("world.bin")
    import json
    json_data=json.dumps(World_info, indent=4)
    print(json_data)
    
    forsignData=writeWorldDataAsBytes(World_info,True)
    World_info['public_key']=derivePublicKey(privateKey).hex()
    World_info['signature']=signMessage(privateKey,publicKey,forsignData).hex()
    with open("out_world.bin", "wb") as f:
        f.write(writeWorldDataAsBytes(World_info))
