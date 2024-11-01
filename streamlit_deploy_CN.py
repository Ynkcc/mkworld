import streamlit as st
import json
import os
from streamlit_ace import st_ace
from mkworld import writeKeypairs, bytesToHex, readKeypairs, json2bin, bin2json  # 假设这些函数已经在 mkworld.py 中定义

def main():
    st.title("planet文件 生成和解析")

    # 子页面导航
    page = st.sidebar.radio("选择页面", ("生成planet", "解析planet"))

    if page == "生成planet":
        if "json_input" not in st.session_state:
            # 加载 default.json 文件内容
            default_json_path = "default.json"
            if os.path.exists(default_json_path):
                with open(default_json_path, "r") as f:
                    default_json_data = json.load(f)
                    st.session_state.json_input = json.dumps(default_json_data, indent=4)
            else:
                st.session_state.json_input = "{}"
        
        # 显示 JSON 编辑器
        json_input = st_ace(
            value=st.session_state.json_input,
            language="json",
            theme="monokai",
            height=300
        )

        # 上传 current.c25519 文件
        key_file = st.file_uploader("上传 current.c25519 文件(如果你有)", type=["c25519"])
        
        # 生成行星并下载
        if st.button("生成planet文件"):
            # 检查用户是否上传了密钥文件
            if key_file is not None:
                buffer = key_file.read()
                # 保存密钥
                st.session_state.key_file = buffer
                keypairs = readKeypairs(buffer)
                if keypairs is None:
                    st.error("无效的current.c25519文件。")
                    return
            elif "key_file" in st.session_state and st.session_state.key_file is not None:
                buffer = st.session_state.key_file
                keypairs = readKeypairs(buffer)
                if keypairs is None:
                    st.error("无效的current.c25519文件。")
                    return
            else:
                # 生成新的密钥对
                keypairsBytes = writeKeypairs()
                # 保存密钥
                st.session_state.key_file = keypairsBytes
                keypairs = readKeypairs(keypairsBytes)
       
            # 保存文本框
            st.session_state.json_input = json_input
            # 将编辑后的 JSON 转换为二进制文件
            edited_json_data = json.loads(json_input)
            # 替换公钥
            edited_json_data["public_key"] = bytesToHex(keypairs["publicKey1"] + keypairs["publicKey2"])
            bin_data = bytes(json2bin(keypairs["privateKey2"], keypairs["publicKey2"], edited_json_data))

            # 提供下载链接
            st.download_button("下载planet", bin_data, file_name="planet")

        # 提供密钥文件下载链接
        if "key_file" in st.session_state and st.session_state.key_file is not None:
            st.download_button("下载 current.c25519 文件", bytes(st.session_state.key_file), file_name="current.c25519")

    elif page == "解析planet":
        uploaded_file = st.file_uploader("上传planet")
        if st.button("解析planet文件"):
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
                    st.error("planet文件转换为 JSON 失败。")

if __name__ == "__main__":
    main()
