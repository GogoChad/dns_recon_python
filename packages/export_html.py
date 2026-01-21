"""Export DNS results to minimal HTML reports."""

def export_html(data, output_file='dns_map.html'):
    """Generate compact HTML report."""
    domain = data.get('domain', 'Unknown')
    scan_date = data.get('scan_date', 'N/A')
    results = data.get('results', {})
    summary = data.get('summary', {})
    
    html = f'''<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>DNS: {domain}</title>
<style>body{{font-family:monospace;background:#1a1a2e;color:#eee;padding:20px;margin:0}}.container{{max-width:1200px;margin:0 auto;background:#16213e;border-radius:8px;padding:20px}}h1{{color:#bb86fc;border-bottom:2px solid #bb86fc;padding-bottom:10px}}h2{{color:#03dac6;margin-top:20px;border-left:4px solid #03dac6;padding-left:10px}}.meta{{background:#0f3460;padding:10px;border-radius:5px;margin:15px 0}}.summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:15px 0}}.stat{{background:#533483;padding:10px;border-radius:5px;text-align:center}}.stat-value{{font-size:24px;font-weight:bold;color:#03dac6}}.section{{background:#0f3460;margin:15px 0;padding:15px;border-radius:5px;border-left:4px solid #bb86fc}}pre{{background:#1a1a2e;padding:10px;border-radius:3px;overflow-x:auto}}ul{{list-style:none;padding:0}}li{{padding:5px 0;border-bottom:1px solid #333}}li:last-child{{border-bottom:none}}code{{color:#03dac6}}</style>
</head><body><div class="container">
<h1>DNS Report: {domain}</h1>
<div class="meta"><strong>Date:</strong> {scan_date}<br><strong>Depth:</strong> {data.get('depth','N/A')} | <strong>Max:</strong> {data.get('max_results','N/A')}</div>
<div class="summary">
<div class="stat"><div class="stat-value">{summary.get('domains_found',0)}</div><div>Domains</div></div>
<div class="stat"><div class="stat-value">{summary.get('ips_found',0)}</div><div>IPs</div></div>
<div class="stat"><div class="stat-value">{len(results)}</div><div>Strategies</div></div>
</div>'''
    
    for strategy, data_items in results.items():
        html += f'<div class="section"><h2>{strategy.upper().replace("_"," ")}</h2>'
        if isinstance(data_items, list):
            html += '<ul>'
            for item in data_items[:50]:
                if isinstance(item, dict):
                    html += '<li><pre>' + str(item) + '</pre></li>'
                else:
                    html += f'<li><code>{item}</code></li>'
            html += '</ul>'
        elif isinstance(data_items, dict):
            html += '<ul>'
            for key, value in list(data_items.items())[:50]:
                html += f'<li><strong>{key}:</strong> '
                html += f'<pre>{value}</pre>' if isinstance(value, (list, dict)) else f'<code>{value}</code>'
                html += '</li>'
            html += '</ul>'
        else:
            html += f'<pre>{data_items}</pre>'
        html += '</div>'
    
    html += '</div></body></html>'
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)
    
    return output_file
