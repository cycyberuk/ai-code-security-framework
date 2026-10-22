import streamlit as st
import sys
import os

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="AI Code Security",
    page_icon="🛡️",
    layout="wide"
)

# --- IMPORT MODULES ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    from src.deepseek_client import DeepSeekClient
    from src.virustotal_client import VirusTotalClient
except ImportError as e:
    st.error(f"Failed to load modules: {e}")

# --- HEADER ---
st.markdown("## 🛡️ AI Code Security Framework")
st.markdown("Empirical threat modeling for AI-generated C code using **DeepSeek** and **VirusTotal**.")
st.divider() # Creates a subtle thin line

# --- MAIN LAYOUT ---
tab1, tab2 = st.tabs(["🔍 Semantic Analysis (DeepSeek)", "🦠 Artifact Screening (VirusTotal)"])

# ==========================================
# TAB 1: DEEPSEEK
# ==========================================
with tab1:
    col1, col2 = st.columns([1, 1], gap="large")
    
    with col1:
        st.markdown("### Source Code Input")
        default_code = 'int main() {\n    char buf[10];\n    strcpy(buf, "overflow");\n    return 0;\n}'
        code_input = st.text_area("Paste C Code", value=default_code, height=350, label_visibility="collapsed")
        
        st.write("") # Spacer
        analyze_btn = st.button("Analyze Code", type="primary", use_container_width=True)
        
        with st.expander("ℹ️ How it works"):
            st.write("The DeepSeek LLM analyzes the code semantically to identify CWE vulnerabilities, ignoring traditional regex signatures.")
        
    with col2:
        st.markdown("### Analysis Results")
        
        if analyze_btn:
            if not code_input.strip():
                st.warning("Please paste some code first.")
            else:
                with st.spinner("DeepSeek is analyzing the code..."):
                    try:
                        client = DeepSeekClient()
                        result = client.classify_cwe(code_input, "streamlit_input.c")
                        
                        if result.get("secure", True) and not result.get("cwes"):
                            st.success("✅ No vulnerabilities detected.")
                        else:
                            st.error("⚠️ Vulnerabilities Detected")
                            st.json(result, expanded=True)
                            
                    except Exception as e:
                        st.error(f"API Error: {e}")
        else:
            st.info("Awaiting analysis. Results will appear here.")

# ==========================================
# TAB 2: VIRUSTOTAL
# ==========================================
with tab2:
    col1, col2 = st.columns([1, 1], gap="large")
    
    with col1:
        st.markdown("### Artifact Upload")
        st.warning("⚠️ **Privacy Notice:** Uploading a file to VirusTotal shares it with 70+ security vendors. Only upload non-sensitive files.")
        
        uploaded_file = st.file_uploader("Upload a compiled binary (.exe, .bin)", type=["exe", "bin", "out"])
        
        st.write("") # Spacer
        scan_btn = st.button("Scan Artifact", type="secondary", use_container_width=True)
        
    with col2:
        st.markdown("### Threat Intelligence")
        
        if scan_btn:
            if uploaded_file is None:
                st.warning("Please upload a file first.")
            else:
                with st.spinner("Uploading and scanning..."):
                    try:
                        temp_path = f"temp_{uploaded_file.name}"
                        with open(temp_path, "wb") as f:
                            f.write(uploaded_file.getbuffer())
                        
                        vt = VirusTotalClient()
                        upload_res = vt.upload(temp_path)
                        
                        if "data" in upload_res:
                            analysis_id = upload_res["data"]["id"]
                            report = vt.get_analysis(analysis_id)
                            summary = vt.summarise(report)
                            
                            st.markdown(f"**Analysis ID:** `{analysis_id}`")
                            
                            if summary["verdict"] == "flagged":
                                st.error(f"🚨 **Threat Detected!** {summary['detected']} out of {summary['engines']} engines flagged this file.")
                            else:
                                st.success(f"✅ **Clean.** 0 out of {summary['engines']} engines flagged this file.")
                        else:
                            st.error(f"Upload failed: {upload_res}")
                        
                        os.remove(temp_path)
                        
                    except Exception as e:
                        st.error(f"API Error: {e}")
        else:
            st.info("Awaiting upload. VirusTotal report will appear here.")

# --- FOOTER ---
st.divider()
st.caption("© 2026 AI Code Security Framework. Results available in the published paper.")
