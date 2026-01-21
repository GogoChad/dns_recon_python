"""Export DNS mapping results to JSON format."""

import json
from datetime import datetime


def export_json(data, output_file='dns_map.json', pretty=True):
    # Build structured JSON data with metadata and statistics
    json_data = {
        'domain': data.get('domain', 'unknown'),
        'scan_date': data.get('scan_date', datetime.now().isoformat()),
        'metadata': {
            'depth': data.get('depth', 0),
            'max_results': data.get('max_results', 0),
            'total_results': data.get('total_results', 0),
            'strategies_used': list(data.get('results', {}).keys())
        },
        'results': data.get('results', {}),
        'statistics': {
            'domains_found': len([r for results in data.get('results', {}).values() 
                                 if isinstance(results, list) for r in results]),
            'strategies_count': len(data.get('results', {}))
        }
    }
    
    # Write to file with optional pretty-printing
    with open(output_file, 'w', encoding='utf-8') as f:
        if pretty:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
        else:
            json.dump(json_data, f, ensure_ascii=False)
    
    return output_file
