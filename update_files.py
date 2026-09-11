import json
import re
from pathlib import Path

transcript_path = Path("/Users/suryaprakasht/.gemini/antigravity-ide/brain/24799aed-9362-4de2-892d-df3cdfa07f7d/.system_generated/logs/transcript_full.jsonl")

full_content = ""
with open(transcript_path, 'r', encoding='utf-8') as f:
    for line in f:
        data = json.loads(line)
        content = data.get("content", "")
        # If content is a list (multimodal parts)
        if isinstance(content, list):
            text_parts = [p.get("text", "") for p in content if isinstance(p, dict)]
            text = "".join(text_parts)
        else:
            text = str(content)
            
        if "Hybrid Memory & Disk Forensics Framework — Full Source" in text:
            full_content = text
            break

if not full_content:
    print("Still not found!")
else:
    print("Found! Length:", len(full_content))
    pattern = re.compile(r'## `([^`]+)`\n\n```[^\n]*\n(.*?)```', re.DOTALL)
    matches = pattern.findall(full_content)
    print("Matches found:", len(matches))
    
    project_root = Path("/Users/suryaprakasht/Downloads/hybrid-forensics-framework")
    count = 0
    for filename, file_content in matches:
        file_path = project_root / filename
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as out_f:
            out_f.write(file_content)
        print(f"Updated {filename}")
        count += 1
    print(f"Total files updated: {count}")
