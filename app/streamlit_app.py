import streamlit as st
import sys
import os

# Add the parent directory to the path so we can import from src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.deepseek_client import DeepSeekClient
from src.virustotal_client import VirusTotalClient

st.set_page_config(page_title="AI Code Security Framework", page_icon="🛡️", layout="wide")

st.title("🛡️ AI Code Security Framework")
st.markdown("Empirical Threat Modeling for AI-Generated C Code using **DeepSeek** and **VirusTotal**.")

tab1, tab2 = st.tabs(["🔍 Source Code Analysis (DeepSeek)", "🦠 Artifact Screening (VirusTotal)"])

with tab1:
    st.header("Analyze C Source Code")
    st.write("Paste AI-generated C code below to detect CWE vulnerabilities using DeepSeek's semantic engine.")
    
    code_input = st.text_area("C Source Code", height=300, placeholder="int main() {\n    char buf[10];\n    strcpy(buf, \"overflow\");\n}")
    
    if st.button("Run Semantic Analysis"):
        if code_input.strip():
            with st.spinner("Analyzing code with DeepSeek..."):
                try:
                    client = DeepSeekClient()
                    result = client.classify_cwe(code_input, "streamlit_input.c")
                    st.success("Analysis Complete!")
                    st.json(result)
                except Exception as e:
                    st.error(f"API Error: {e}")
        else:
            st.warning("Please paste some code first.")

with tab2:
    st.header("Artifact Screening")
    st.warning("⚠️ **Privacy Notice:** Uploading a file to VirusTotal shares it with 70+ security vendors. Only upload non-sensitive, synthetic test files.")
    
    uploaded_file = st.file_uploader("Upload a compiled binary (.exe, .bin)", type=["exe", "bin", "out"])
    
    if uploaded_file is not None:
        if st.button("Scan with VirusTotal"):
            with st.spinner("Uploading and scanning..."):
                try:
                    # Save uploaded file temporarily
                    temp_path = f"temp_{uploaded_file.name}"
                    with open(temp_path, "wb") as f:
                        f.write(uploaded_file.getbuffer())
                    
                    # Upload to VT
                    vt = VirusTotalClient()
                    upload_res = vt.upload(temp_path)
                    
                    if "data" in upload_res:
                        analysis_id = upload_res["data"]["id"]
                        st.info(f"File uploaded. Analysis ID: {analysis_id}. Fetching report...")
                        
                        # Get report
                        report = vt.get_analysis(analysis_id)
                        summary = vt.summarise(report)
                        
                        if summary["verdict"] == "flagged":
                            st.error(f"🚨 Threat Detected! {summary['detected']} out of {summary['engines']} engines flagged this file.")
                        else:
                            st.success(f"✅ Clean. 0 out of {summary['engines']} engines flagged this file.")
                    else:
                        st.error(f"Upload failed: {upload_res}")
                    
                    # Clean up temp file
                    os.remove(temp_path)
                    
                except Exception as e:
                    st.error(f"API Error: {e}")

st.sidebar.markdown("---")
st.sidebar.info("This app is part of a research paper: *An Empirical Threat Modeling Framework for Ethical and Security Vulnerability Detection in AI-Generated Web Code*.")