package writer

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{.ReportName}} - RMM Hunter Report</title>

<!-- Modern font -->
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;500;700&display=swap" rel="stylesheet">

<style>
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }

    body {
        font-family: 'Inter', sans-serif;
        background: radial-gradient(circle at top left, #101820, #0a0a0a);
        color: #e5e5e5;
        line-height: 1.6;
        overflow-x: hidden;
    }

    .container {
        max-width: 1250px;
        margin: 0 auto;
        padding: 25px;
    }

    .header {
        text-align: center;
        padding: 50px 20px 40px;
        background: linear-gradient(135deg, #1f2933, #273543);
        border-radius: 16px;
        margin-bottom: 40px;
        box-shadow: 0 8px 20px rgba(0,0,0,0.4);
    }

    .company-name {
        font-size: 2.8em;
        font-weight: 700;
        color: #00aaff;
    }

    .company-link {
        color: #00aaff;
        font-size: 1.05em;
        text-decoration: none;
        transition: color 0.3s;
    }

    .company-link:hover {
        color: #66c2ff;
    }

    .report-title {
        font-size: 2.2em;
        margin: 20px 0;
        font-weight: 500;
    }

    .risk-section {
        margin-top: 25px;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 10px;
    }

    .risk-banner {
        font-weight: bold;
        text-transform: uppercase;
        font-size: 1.3em;
        letter-spacing: 1px;
        padding: 14px 30px;
        border-radius: 25px;
        color: white;
    }

    .risk-gauge {
        width: 130px;
        height: 130px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        background: conic-gradient({{riskColor .RiskRating.Rating}} {{mul .RiskRating.Score 10}}%, #333 0%);
        box-shadow: inset 0 0 12px rgba(0,0,0,0.6);
    }

    .risk-gauge-inner {
        width: 85px;
        height: 85px;
        border-radius: 50%;
        background: #1a1a1a;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #fff;
        font-weight: 700;
        font-size: 1.4em;
    }

    .metadata {
        background-color: rgba(40, 40, 40, 0.9);
        padding: 20px;
        border-radius: 10px;
        margin-bottom: 40px;
        box-shadow: 0 4px 10px rgba(0,0,0,0.4);
    }

    .metadata h3 {
        margin-bottom: 10px;
        color: #00aaff;
    }

    .item-detail strong {
        color: #00aaff;
    }

    .nav-sidebar {
        position: fixed;
        left: 20px;
        top: 50%;
        transform: translateY(-50%);
        background-color: rgba(25,25,25,0.95);
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 6px 20px rgba(0,0,0,0.5);
        max-height: 70vh;
        overflow-y: auto;
        backdrop-filter: blur(10px);
    }

    .nav-sidebar h3 {
        color: #00aaff;
        margin-bottom: 12px;
        font-size: 1.1em;
    }

    .nav-sidebar ul {
        list-style: none;
    }

    .nav-sidebar li { margin-bottom: 6px; }

    .nav-sidebar a {
        color: #ddd;
        text-decoration: none;
        display: block;
        padding: 6px 10px;
        border-radius: 6px;
        transition: all 0.3s;
        font-size: 0.9em;
    }

    .nav-sidebar a:hover {
        background-color: #00aaff;
        color: #fff;
    }

    .search-box {
        width: 100%;
        padding: 10px;
        border: none;
        border-radius: 6px;
        margin-bottom: 15px;
        background-color: #222;
        color: #ddd;
        font-size: 0.95em;
        outline: none;
    }

    .search-box::placeholder { color: #777; }

    .content { margin-left: 260px; }

    .section {
        background-color: rgba(44,44,44,0.85);
        margin-bottom: 35px;
        border-radius: 10px;
        overflow: hidden;
        backdrop-filter: blur(8px);
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        transition: transform 0.2s;
    }

    .section:hover { transform: translateY(-2px); }

    .section-header {
        background-color: #263445;
        padding: 20px;
        cursor: pointer;
        display: flex;
        justify-content: space-between;
        align-items: center;
        transition: background-color 0.3s;
    }

    .section-header:hover { background-color: #2f435b; }

    .section-title {
        font-size: 1.3em;
        font-weight: 600;
    }

    .section-count {
        background-color: #00aaff;
        color: white;
        padding: 5px 12px;
        border-radius: 15px;
        font-size: 0.9em;
    }

    .section-content {
        padding: 20px;
        display: none;
        animation: fadeIn 0.3s ease-in-out;
    }

    .section-content.active { display: block; }

    .item {
        background-color: #2a2a2a;
        padding: 15px;
        margin-bottom: 10px;
        border-radius: 8px;
        border-left: 4px solid #00aaff;
        transition: all 0.3s;
    }

    .item:hover {
        transform: translateY(-3px);
        box-shadow: 0 3px 8px rgba(0,0,0,0.4);
    }

    .item-title {
        font-weight: 600;
        color: #00aaff;
        margin-bottom: 8px;
    }

    .item-detail {
        margin-bottom: 5px;
        font-size: 0.9em;
    }

    .empty-state {
        text-align: center;
        color: #7f8c8d;
        font-style: italic;
        padding: 40px;
    }

    @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
    }

    @media (max-width: 768px) {
        .nav-sidebar { display: none; }
        .content { margin-left: 0; }
    }
</style>
</head>

<body>
<div class="nav-sidebar">
    <input type="text" id="search" placeholder="Search findings..." class="search-box">
    <h3>Navigation</h3>
    <ul>
        <li><a href="#processes">Processes</a></li>
        <li><a href="#services">Services</a></li>
        <li><a href="#connections">Connections</a></li>
        <li><a href="#tasks">Scheduled Tasks</a></li>
        <li><a href="#autoruns">AutoRuns</a></li>
        <li><a href="#binaries">Binaries</a></li>
        <li><a href="#directories">Directories</a></li>
    </ul>
</div>

<div class="content">
<div class="container">

<div class="header">
    <div class="company-name">KrakenTech LLC</div>
    <a href="https://krakensec.tech" class="company-link" target="_blank">https://krakensec.tech</a>
    <div class="report-title">{{.ReportName}}</div>

    <div class="risk-section">
        <div class="risk-banner" style="background-color: {{riskColor .RiskRating.Rating}};">
            Risk Level: {{.RiskRating.Rating}} ({{printf "%.1f" .RiskRating.Score}}/10)
        </div>
        <div class="risk-gauge">
            <div class="risk-gauge-inner">{{printf "%.1f" .RiskRating.Score}}</div>
        </div>
    </div>
</div>

<div class="metadata">
    <h3>Report Metadata</h3>
    <div class="item-detail"><strong>Generated:</strong> {{.GeneratedAt}}</div>
    <div class="item-detail"><strong>Risk Summary:</strong> {{.RiskRating.Summary}}</div>
</div>

{{/* === Sections === */}}

{{define "section"}}
<div class="section" id="{{.ID}}">
  <div class="section-header" onclick="toggleSection('{{.ID}}')">
      <span class="section-title">{{.Title}}</span>
      <span class="section-count">{{.Count}}</span>
  </div>
  <div class="section-content">
      {{if .HasItems}}
          {{range .Items}}
              <div class="item">{{.}}</div>
          {{end}}
      {{else}}
          <div class="empty-state">No {{.Title}} found</div>
      {{end}}
  </div>
</div>
{{end}}

<!-- Processes -->
<div class="section" id="processes">
    <div class="section-header" onclick="toggleSection('processes')">
        <span class="section-title">Suspicious Processes</span>
        <span class="section-count">{{len .Findings.Processes}}</span>
    </div>
    <div class="section-content">
        {{if .Findings.Processes}}
            {{range .Findings.Processes}}
            <div class="item">
                <div class="item-title">{{.Name}}</div>
                <div class="item-detail"><strong>PID:</strong> {{.PID}}</div>
                <div class="item-detail"><strong>PPID:</strong> {{.PPID}}</div>
                {{if .Path}}<div class="item-detail"><strong>Path:</strong> {{.Path}}</div>{{end}}
                {{if .Parent}}<div class="item-detail"><strong>Parent:</strong> {{.Parent}}</div>{{end}}
                {{if .Args}}<div class="item-detail"><strong>Args:</strong> {{.Args}}</div>{{end}}
            </div>
            {{end}}
        {{else}}
            <div class="empty-state">No suspicious processes found</div>
        {{end}}
    </div>
</div>

<!-- Services -->
<div class="section" id="services">
    <div class="section-header" onclick="toggleSection('services')">
        <span class="section-title">Suspicious Services</span>
        <span class="section-count">{{len .Findings.Services}}</span>
    </div>
    <div class="section-content">
        {{if .Findings.Services}}
            {{range .Findings.Services}}
            <div class="item">
                <div class="item-title">{{.DisplayName}}</div>
                <div class="item-detail"><strong>Name:</strong> {{.Name}}</div>
                <div class="item-detail"><strong>Binary Path:</strong> {{.BinaryPathName}}</div>
                <div class="item-detail"><strong>Start Type:</strong> {{.StartType}}</div>
                {{if .Description}}<div class="item-detail"><strong>Description:</strong> {{.Description}}</div>{{end}}
            </div>
            {{end}}
        {{else}}
            <div class="empty-state">No suspicious services found</div>
        {{end}}
    </div>
</div>

<!-- Connections -->
<div class="section" id="connections">
    <div class="section-header" onclick="toggleSection('connections')">
        <span class="section-title">Suspicious Outbound Connections</span>
        <span class="section-count">{{len .Findings.OutboundConnections}}</span>
    </div>
    <div class="section-content">
        {{if .Findings.OutboundConnections}}
            {{range .Findings.OutboundConnections}}
            <div class="item">
                <div class="item-title">{{.Process}}</div>
                <div class="item-detail"><strong>Local:</strong> {{.LocalAddr}}</div>
                <div class="item-detail"><strong>Remote:</strong> {{.RemoteAddr}}</div>
                {{if .RemoteHost}}<div class="item-detail"><strong>Host:</strong> {{.RemoteHost}}</div>{{end}}
                <div class="item-detail"><strong>State:</strong> {{.State}}</div>
                <div class="item-detail"><strong>PID:</strong> {{.PID}}</div>
            </div>
            {{end}}
        {{else}}
            <div class="empty-state">No suspicious outbound connections found</div>
        {{end}}
    </div>
</div>

<!-- Scheduled Tasks -->
<div class="section" id="tasks">
    <div class="section-header" onclick="toggleSection('tasks')">
        <span class="section-title">Suspicious Scheduled Tasks</span>
        <span class="section-count">{{len .Findings.ScheduledTasks}}</span>
    </div>
    <div class="section-content">
        {{if .Findings.ScheduledTasks}}
            {{range .Findings.ScheduledTasks}}
            <div class="item">
                <div class="item-title">{{.Name}}</div>
                {{if .Author}}<div class="item-detail"><strong>Author:</strong> {{.Author}}</div>{{end}}
                {{if .Path}}<div class="item-detail"><strong>Path:</strong> {{.Path}}</div>{{end}}
                <div class="item-detail"><strong>State:</strong> {{.State}}</div>
                <div class="item-detail"><strong>Enabled:</strong> {{.Enabled}}</div>
                {{if .Description}}<div class="item-detail"><strong>Description:</strong> {{.Description}}</div>{{end}}
                {{if .LastRun}}<div class="item-detail"><strong>Last Run:</strong> {{.LastRun}}</div>{{end}}
                {{if .NextRun}}<div class="item-detail"><strong>Next Run:</strong> {{.NextRun}}</div>{{end}}
            </div>
            {{end}}
        {{else}}
            <div class="empty-state">No suspicious scheduled tasks found</div>
        {{end}}
    </div>
</div>

<!-- AutoRuns -->
<div class="section" id="autoruns">
    <div class="section-header" onclick="toggleSection('autoruns')">
        <span class="section-title">Suspicious AutoRuns</span>
        <span class="section-count">{{len .Findings.AutoRuns}}</span>
    </div>
    <div class="section-content">
        {{if .Findings.AutoRuns}}
            {{range .Findings.AutoRuns}}
            <div class="item">
                <div class="item-title">{{.Name}}</div>
                <div class="item-detail"><strong>Command:</strong> {{.Command}}</div>
                <div class="item-detail"><strong>Location:</strong> {{.Location}}</div>
                <div class="item-detail"><strong>Enabled:</strong> {{.Enabled}}</div>
                {{if .Description}}<div class="item-detail"><strong>Description:</strong> {{.Description}}</div>{{end}}
            </div>
            {{end}}
        {{else}}
            <div class="empty-state">No suspicious autoruns found</div>
        {{end}}
    </div>
</div>

<!-- Binaries -->
<div class="section" id="binaries">
    <div class="section-header" onclick="toggleSection('binaries')">
        <span class="section-title">Suspicious Binaries</span>
        <span class="section-count">{{len .Findings.Binaries}}</span>
    </div>
    <div class="section-content">
        {{if .Findings.Binaries}}
            {{range .Findings.Binaries}}
            <div class="item">
                <div class="item-detail">{{.}}</div>
            </div>
            {{end}}
        {{else}}
            <div class="empty-state">No suspicious binaries found</div>
        {{end}}
    </div>
</div>

<!-- Directories -->
<div class="section" id="directories">
    <div class="section-header" onclick="toggleSection('directories')">
        <span class="section-title">Suspicious Directories</span>
        <span class="section-count">{{len .Findings.Directories}}</span>
    </div>
    <div class="section-content">
        {{if .Findings.Directories}}
            {{range .Findings.Directories}}
            <div class="item">
                <div class="item-detail">{{.}}</div>
            </div>
            {{end}}
        {{else}}
            <div class="empty-state">No suspicious directories found</div>
        {{end}}
    </div>
</div>

</div>
</div>

<script>
function toggleSection(sectionId) {
    const content = document.querySelector('#' + sectionId + ' .section-content');
    if (content) {
        content.classList.toggle('active');
    }
}

document.addEventListener('DOMContentLoaded', function() {
    // Auto-expand first section that has items
    const sections = document.querySelectorAll('.section');
    for (let section of sections) {
        const count = parseInt(section.querySelector('.section-count').textContent);
        if (count > 0) {
            const content = section.querySelector('.section-content');
            if (content) {
                content.classList.add('active');
                break;
            }
        }
    }

    // Smooth scrolling for navigation links
    document.querySelectorAll('.nav-sidebar a').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href').substring(1);
            const targetElement = document.getElementById(targetId);
            if (targetElement) {
                targetElement.scrollIntoView({ behavior: 'smooth' });
                const content = targetElement.querySelector('.section-content');
                if (content && !content.classList.contains('active')) {
                    content.classList.add('active');
                }
            }
        });
    });

    // Live search filter
    const searchBox = document.getElementById('search');
    if (searchBox) {
        searchBox.addEventListener('input', function(e) {
            const q = e.target.value.toLowerCase();
            const sections = document.querySelectorAll('.section');

            sections.forEach(section => {
                const items = section.querySelectorAll('.item');
                let hasVisibleItems = false;

                items.forEach(item => {
                    if (item.textContent.toLowerCase().includes(q)) {
                        item.style.display = '';
                        hasVisibleItems = true;
                    } else {
                        item.style.display = 'none';
                    }
                });

                // Auto-expand sections with matching items
                if (q && hasVisibleItems) {
                    const content = section.querySelector('.section-content');
                    if (content && !content.classList.contains('active')) {
                        content.classList.add('active');
                    }
                }
            });
        });
    }
});
</script>
</body>
</html>`
