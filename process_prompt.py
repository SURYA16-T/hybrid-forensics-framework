import json
import re
from pathlib import Path

# The file contains multiple JSON lines or a single JSON string?
# Let's read the file and extract the content string.
with open('dumped_prompt.json', 'r', encoding='utf-8') as f:
    lines = f.readlines()

full_text = ""
for line in lines:
    try:
        data = json.loads(line)
        # Extract content text from data
        content = data.get("content", "")
        if isinstance(content, list):
            text_parts = [p.get("text", "") for p in content if isinstance(p, dict)]
            full_text += "".join(text_parts)
        else:
            full_text += str(content)
    except json.JSONDecodeError:
        continue

# The pattern to match file sections:
# ## `filename`\n\n```...\ncontent\n```
pattern = re.compile(r'## `([^`]+)`\n+```[^\n]*\n(.*?)```', re.DOTALL)
matches = pattern.findall(full_text)

project_root = Path("/Users/suryaprakasht/Downloads/hybrid-forensics-framework")

if not matches:
    print("No files matched! Printing a snippet of the text:")
    print(full_text[:1000])
else:
    count = 0
    for filename, file_content in matches:
        file_path = project_root / filename
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as out_f:
            out_f.write(file_content)
        print(f"Updated {filename}")
        count += 1
    print(f"Total files updated: {count}")
