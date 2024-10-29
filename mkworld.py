import binascii
from nacl.signing import SigningKey
import nacl.bindings
import hashlib
import json
import os
import ipaddress

'''
world更新条件
1.(_id == update._id)&&(_ts < update._ts)&&(_type == update._type)
2.公钥匹配
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


def json2bin(privateKey,publickey,jsonData):
    """
    将JSON数据和私钥转换为字节数组
    """
    # 获取签名数据
    worldDataBytes = writeWorldDataAsBytes(jsonData, forSign=True)
    jsonData['signature'] = signMessage(privateKey,publickey,worldDataBytes).hex()

    # 转换为最终的字节数据
    return writeWorldDataAsBytes(jsonData)

def bin2json(buffer):
    """
    从二进制数据中恢复JSON数据
    """
    offset = 0
    typeByte, offset = parseUintFromBytes(buffer, offset, 1)
    idBytes, offset = parseUintFromBytes(buffer, offset, 8)
    tsBytes, offset = parseUintFromBytes(buffer, offset, 8)
    publicKey = bytesToHex(buffer[offset:offset + 64])
    offset += 64
    signature = bytesToHex(buffer[offset:offset + 96])
    offset += 96

    rootsCount, offset = parseUintFromBytes(buffer, offset, 1)
    roots = []

    for _ in range(rootsCount):
        address = bytesToHex(buffer[offset:offset + 5])
        offset += 5
        identityType, offset = parseUintFromBytes(buffer, offset, 1)
        rootPublicKey = bytesToHex(buffer[offset:offset + 64])
        offset += 64
        placeholder, offset = parseUintFromBytes(buffer, offset, 1)

        stableEndpointsCount, offset = parseUintFromBytes(buffer, offset, 1)
        stableEndpoints = []

        for _ in range(stableEndpointsCount):
            endpointType, offset = parseUintFromBytes(buffer, offset, 1)
            ipAddress, offset = parseIpAddress(buffer, offset, endpointType)
            port, offset = parseUintFromBytes(buffer, offset, 2)

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

def parseWorldFile(filePath):
    """
    从文件解析二进制数据并调用 bin2json 返回 JSON 数据
    """
    with open(filePath, "rb") as f:
        data = f.read()
    return bin2json(data)


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

def readKeypairs(buffer):
    """
    从字节数组中读取两对公钥和私钥，并返回字典
    如果 buffer 长度少于 128 字节或校验失败，则返回 None
    """
    if len(buffer) < 128:
        return None

    publicKey1 = bytes(buffer[:32])
    publicKey2= bytes(buffer[32:64])
    privateKey1= bytes(buffer[64:96])
    privateKey2= bytes(buffer[96:128])

    keypairs = {
        "publicKey1": publicKey1,
        "publicKey2": publicKey2,
        "privateKey1": privateKey1,
        "privateKey2": privateKey2
    }

    print("读取到的密钥对：")
    for key, value in keypairs.items():
        print(f"{key}: {binascii.hexlify(value).decode()}")

    # 校验密钥对
    try:
        # 校验第一个密钥对
        signingKey1 = SigningKey(privateKey1)
        derivedPublicKey1 = signingKey1.verify_key.encode()
        if derivedPublicKey1 != publicKey1:
            print("密钥对 1 校验失败：公钥不匹配")
            return None

        # 校验第二个密钥对
        signingKey2 = SigningKey(privateKey2)
        derivedPublicKey2 = signingKey2.verify_key.encode()
        if derivedPublicKey2 != publicKey2:
            print("密钥对 2 校验失败：公钥不匹配")
            return None

        print("密钥对校验成功：公钥匹配")
    except Exception as e:
        print(f"校验过程中发生错误: {e}")
        return None

    return keypairs

def writeKeypairs():
    """
    生成两对密钥对并返回包含所有密钥的字节数组
    """
    privateKey1, publicKey1 = generateKeypair()
    privateKey2, publicKey2 = generateKeypair()

    # 创建包含两对密钥的字节数组
    data = bytearray()
    data.extend(publicKey1)
    data.extend(publicKey2)
    data.extend(privateKey1)
    data.extend(privateKey2)

    return data

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
    try:
        if ipType == 0x04:  # IPv4
            return ipaddress.IPv4Address(ipAddress).packed
        elif ipType == 0x06:  # IPv6
            return ipaddress.IPv6Address(ipAddress).packed
    except ipaddress.AddressValueError:
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

    # 检查文件是否存在并读取密钥对
    current_file_path = "current.c25519"

    # 尝试读取密钥对
    if os.path.exists(current_file_path):
        with open(current_file_path, "rb") as f:
            buffer = f.read()
            keypairs = readKeypairs(buffer)

    # 如果文件不存在或读取失败，则生成新的密钥对
    if 'keypairs' not in locals() or keypairs is None:
        print("文件不存在或读取失败，生成新的密钥对")
        keypairsBytes = writeKeypairs()
        keypairs = readKeypairs(keypairsBytes)

        # 将新生成的密钥对写入 current.c25519 文件
        with open(current_file_path, "wb") as f:
            f.write(keypairsBytes)


    '''从bin文件中加载'''
    World_info = parseWorldFile("world.bin")

    json_data=json.dumps(World_info, indent=4)
    print(json_data)
    with open("parsed_data.json",mode='w',encoding='utf-8') as f:
        f.write(json_data)

    # '''从json文件中加载'''
    # with open("parsed_data.json",mode='r',encoding='utf-8') as f:
    #     World_info=json.load(f)

    print(bytesToHex(keypairs["publicKey1"]+keypairs["publicKey2"]))
    World_info["public_key"]=bytesToHex(keypairs["publicKey1"]+keypairs["publicKey2"])

    bin_data=json2bin(keypairs["privateKey2"],keypairs["publicKey2"],World_info)
    with open("out_world.bin", "wb") as f:
        f.write(bin_data)
