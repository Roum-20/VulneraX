import streamlit as st
from scanner import run_scan

st.set_page_config(page_title="VulneraX", layout="wide")
st.title("🎯VULNERAX DASHBOARD")

st.markdown("Enter a target URL to scan for common web vulnerabilities:")

url = st.text_input("Target URL", placeholder="https://example.com")

if st.button("Start Scan"):
    if url:
        with st.spinner("🔍 Scanning in progress..."):
            result = run_scan(url)

        st.success("✅ Scan Complete!")

        st.markdown(f"**🔗 Target URL:** {result['url']}")
        st.markdown(f"**📄 Total URLs Scanned:** {result['total_urls']}")
        st.markdown(f"**⚠️ Vulnerabilities Found:** {len(result['vulnerabilities'])}")

        if result["vulnerabilities"]:
            vuln_types = {}
            for vuln in result["vulnerabilities"]:
                vuln_types[vuln['type']] = vuln_types.get(vuln['type'], 0) + 1

            st.subheader("📊 Vulnerability Distribution")
            st.bar_chart(vuln_types)

            st.subheader("🧾 Detailed Vulnerabilities")
            for idx, vuln in enumerate(result["vulnerabilities"], 1):
                with st.expander(f"{idx}. {vuln['type']} on {vuln['url']}"):
                    for key, val in vuln.items():
                        st.write(f"**{key.capitalize()}**: `{val}`")
        else:
            st.info("✅ No vulnerabilities detected.")
    else:
        st.warning("⚠️ Please enter a valid URL.")
