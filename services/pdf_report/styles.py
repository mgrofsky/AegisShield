"""PDF Report CSS Styles"""

PDF_STYLES = """
@page {
    size: landscape;
    margin: 1cm;
}

@page portrait {
    size: portrait;
    margin: 1cm;
}

body { font-family: 'Helvetica', sans-serif; font-size: 14px; }
h1, h2, h3 { color: #333; }
table { width: 100%; border-collapse: collapse; }
th, td { border: 1px solid #ddd; padding: 8px; }
th { background-color: #f2f2f2; text-align: left; }
.page-break { page-break-before: always; }
tr { page-break-inside: avoid; }
p { font-size: 14px; }
.landscape-section { page: landscape; }
.mermaid-code {
    font-size: 10px;
    font-family: 'Courier New', Courier, monospace;
}
.gherkin-code {
    font-size: 10px;
    font-family: 'Courier New', Courier, monospace;
}
.footer {
    position: absolute;
    bottom: 0;
    width: 100%;
    text-align: center;
    font-size: 12px;
    color: #555;
}
.toc { margin-bottom: 2cm; }
.toc h2 { font-size: 18px; text-align: center; text-decoration: underline; }
.toc ul { list-style-type: none; padding-left: 0; }
.toc li { margin-bottom: 8px; font-size: 14px; }
.toc a { text-decoration: none; color: #333; }
.toc a:hover { text-decoration: underline; }
ul { line-height: 1.0; margin: 0; padding: 0; }
ul li { margin-bottom: 8px; }
"""
