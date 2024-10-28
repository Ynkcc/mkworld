# 文件头部分

```
type_byte：1 字节，文件的类型。
id_bytes：8 字节，文件的唯一标识符。
ts_bytes：8 字节，时间戳。
public_key：64 字节，文件的两个公钥 前一个不参与校验。
signature：96 字节，签名。
```

# roots 部分

```
roots_count：1 字节， roots 节点的数量。
roots：列表，用于存储所有 roots 节点的数据。
```

# 每个 root 节点

```
address：5 字节，该节点的地址。
separator：1 字节，代表私钥类型， 已知 0x00 为C25519/Ed25519。
root_public_key：64 字节， root 节点的公钥。
placeholder：1 字节，私钥占位符 0x00。
stable_endpoints_count：1 字节， stableEndpoints 节点的数量。
stable_endpoints：列表，用于存储 stableEndpoints 节点的数据。
```

# stableEndpoints 部分

```
endpoint_type：1 字节，节点类型，0x00 占位，0x04 ipv4，0x06 ipv6。
ip：4 或 16 字节， ipv4 或 ipv6 地址。
port：2 字节，端口号。
```