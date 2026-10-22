import streamlit as st
import sys
import os

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="AI Code Security | Threat Modeling",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CUSTOM CSS FOR DARK THEME & MATURE UI ---
st.markdown("""
<style>
    /* Dark Theme Base */
    .stApp {
        background-color: #0E1117;
        color: #FAFAFA;
    }
    
    /* Sidebar Styling */
    [data-testid="stSidebar"] {
        background-color: #161B22;
        border-right: 1px solid #30363D;
    }
    
    /* Input Areas */
    .stTextArea textarea {
        background-color: #0D1117;
        color: #C9D1D9;
        border: 1px solid #30363D;
        border-radius: 6px;
        font-family: 'Courier New', Courier, monospace;
    }
    .stTextArea textarea:focus {
        border-color: #58A6FF;
        box-shadow: 0 0 0 1px #58A6FF;
    }
    
    /* Primary Buttons */
    .stButton>button {
        background-color: #238636;
        color: white;
        border: 1px solid rgba(240, 246, 252, 0.1);
        border-radius: 6px;
        padding: 0.5rem 1rem;
        font-weight: 600;
        transition: background-color 0.2s;
        width: 100%;
    }
    .stButton>button:hover {
        background-color: #2EA043;
        border-color: #8B949E;
    }
    
    /* Secondary Buttons (VT) */
    .stButton>button[kind="secondary"] {
        background-color: #21262D;
        color: #C9D1D9;
        border: 1px solid #30363D;
    }
    .stButton>button[kind="secondary"]:hover {
        background-color: #30363D;
    }

    /* Alerts and JSON */
    .stAlert {
        background-color: #161B22;
        border: 1px solid #30363D;
        border-radius: 6px;
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #FAFAFA !important;
        font-weight: 600 !important;
    }
    
    /* Code Block Font */
    pre {
        background-color: #0D1117 !important;
        border: 1px solid #30363D !important;
        border-radius: 6px !important;
    }
</style>
""", unsafe_allow_html=True)

# --- IMPORT MODULES (Safely) ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    from src.deepseek_client import DeepSeekClient
    from src.virustotal_client import VirusTotalClient
except ImportError as e:
    st.error(f"Failed to load modules: {e}")

# --- SIDEBAR ---
with st.sidebar:
    st.image("https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png", width=40)
    st.title("Security Framework")
    st.caption("v1.0.0 | Empirical Threat Modeling")
    st.markdown("---")
    
    st.markdown("### 📖 About")
    st.markdown("""
    This framework integrates **DeepSeek's semantic engine** and **VirusTotal API v3** to detect vulnerabilities in AI-generated C code.
    
    **Empirical Results:**
    *   **DeepSeek F1:** 0.876
    *   **Static Baseline F1:** 0.611
    *   **Improvement:** +26.5%
    """)
    st.markdown("---")
    st.markdown("### 🔗 Links")
    st.markdown("[GitHub Repository](https://github.com/cycyberuk/ai-code-security-framework)")
    st.caption("© 2026. All rights reserved.")

# --- MAIN LAYOUT ---
st.title("🛡️ AI Code Security Framework")
st.markdown("Advanced threat modeling and vulnerability detection for AI-generated C code.")
st.markdown("---")

# Tabs
tab1, tab2 = st.tabs(["🔍 Semantic Analysis (DeepSeek)", "🦠 Artifact Screening (VirusTotal)"])

# --- TAB 1: DEEPSEEK ---
with tab1:
    col1, col2 = st.columns([1.5, 1])
    
    with col1:
        st.subheader("Source Code Input")
        st.markdown("Paste AI-generated C code below to detect CWE vulnerabilities.")
        
        # Default test code
        default_code = 'int main() {\n    char buf[10];\n    strcpy(buf, "overflow");\n    return 0;\n}'
        code_input = st.text_area("C Source Code", value=default_code, height=350, label_visibility="collapsed")
        
        analyze_btn = st.button("Run Semantic Analysis", type="primary")
        
    with col2:
        st.subheader("Analysis Results")
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
                            st.json(result)
                            
                    except Exception as e:
                        st.error(f"API Error: {e}")
        else:
            st.info("Awaiting analysis. Results will appear here.")

# --- TAB 2: VIRUSTOTAL ---
with tab2:
    col1, col2 = st.columns([1.5, 1])
    
    with col1:
        st.subheader("Artifact Upload")
        st.warning("⚠️ **Privacy Notice:** Uploading a file to VirusTotal shares it with 70+ security vendors. Only upload non-sensitive, synthetic test files.")
        
        uploaded_file = st.file_uploader("Upload a compiled binary (.exe, .bin)", type=["exe", "bin", "out"], label_visibility="collapsed")
        
        scan_btn = st.button("Scan Artifact with VirusTotal", type="secondary")
        
    with col2:
        st.subheader("Threat Intelligence")
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
                            
                            st.info(f"Analysis ID: {analysis_id}")
                            
                            if summary["verdict"] == "flagged":
                                st.error(f"🚨 Threat Detected! {summary['detected']} out of {summary['engines']} engines flagged this file.")
                            else:
                                st.success(f"✅ Clean. 0 out of {summary['engines']} engines flagged this file.")
                        else:
                            st.error(f"Upload failed: {upload_res}")
                        
                        os.remove(temp_path)
                        
                    except Exception as e:
                        st.error(f"API Error: {e}")
        else:
            st.info("Awaiting upload. VirusTotal report will appear here.")
