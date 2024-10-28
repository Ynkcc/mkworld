import streamlit as st
import json
import os
from streamlit_ace import st_ace
from mkworld import writeKeypairs, bytesToHex, readKeypairs, json2bin, bin2json  # 假设这些函数已经在 mkworld.py 中定义

def main():
    st.title("Planet Generation and Key Pair Management")

    # 子页面导航
    page = st.sidebar.radio("Select Page", ("JSON to Binary", "Binary to JSON"))

    if page == "JSON to Binary":
        # 加载 default.json 文件内容
        default_json_path = "default.json"
        if os.path.exists(default_json_path):
            with open(default_json_path, "r") as f:
                default_json_data = json.load(f)

        # 显示 JSON 编辑器
        json_input = st_ace(
            value=json.dumps(default_json_data, indent=4),
            language="json",
            theme="monokai",
            height=300
        )

        # 上传 current.c25519 文件
        key_file = st.file_uploader("Upload current.c25519 file", type=["c25519"])

        # 生成行星并下载
        if st.button("Generate Planet"):
            # 检查用户是否上传了密钥文件
            if key_file is not None:
                buffer = key_file.read()
                keypairs = readKeypairs(buffer)
                if keypairs is None:
                    st.error("Invalid key pair file.")
                    return
            else:
                # 生成新的密钥对
                keypairsBytes = writeKeypairs()
                keypairs = readKeypairs(keypairsBytes)

                # 提供下载链接
                st.download_button("Download Generated Key Pair File", bytes(keypairsBytes), file_name="current.c25519")

            # 将编辑后的 JSON 转换为二进制文件
            edited_json_data = json.loads(json_input)
            # 替换公钥
            edited_json_data["public_key"] = bytesToHex(keypairs["publicKey1"] + keypairs["publicKey2"])
            bin_data = bytes(json2bin(keypairs["privateKey2"], keypairs["publicKey2"], edited_json_data))

            # 提供下载链接
            st.download_button("Download Planet Binary", bin_data, file_name="planet")

    elif page == "Binary to JSON":
        uploaded_file = st.file_uploader("Upload planet file")
        if uploaded_file is not None:
            buffer = uploaded_file.read()
            json_data = bin2json(buffer)

            if json_data:
                # 显示 JSON 编辑器
                json_input = st_ace(
                    value=json.dumps(json_data, indent=4),
                    language="json",
                    theme="monokai",
                    height=300
                )
            else:
                st.error("Failed to convert binary file to JSON.")

if __name__ == "__main__":
    main()
