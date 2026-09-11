import json
import re
from pathlib import Path

transcript_path = Path("/Users/suryaprakasht/.gemini/antigravity-ide/brain/24799aed-9362-4de2-892d-df3cdfa07f7d/.system_generated/logs/transcript_full.jsonl")

full_content = ""
with open(transcript_path, 'r', encoding='utf-8') as f:
    for line in f:
        if "Hybrid Memory & Disk Forensics Framework" in line and "Full Source" in line:
            full_content += line

print("Found lines:", len(full_content))
if len(full_content) > 0:
    with open('dumped_prompt.json', 'w') as f:
        f.write(full_content)
