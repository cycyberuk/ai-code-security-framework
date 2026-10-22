import json, os
from openai import OpenAI
from dotenv import load_dotenv
from json_repair import repair_json

load_dotenv()

class DeepSeekClient:
    def __init__(self):
        self.client = OpenAI(
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com",
        )
        self.model = "deepseek-chat"

    def classify_cwe(self, code: str, filename: str) -> dict:
        # Truncate extremely long code files to save tokens and prevent API limits
        if len(code) > 15000:
            code = code[:15000] + "\n\n// ... [Code truncated for analysis] ..."

        prompt = f"""Analyse this C code for CWE weaknesses.
Return ONLY JSON: {{"cwes":[{{"cwe_id":"CWE-XXX","confidence":0.0}}],"secure":true}}
If none, return {{"cwes":[],"secure":true}}.
File: {filename}
```c
{code}
```"""
        
        try:
            r = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_tokens=1024,
            )
            
            raw_content = r.choices[0].message.content.strip()
            
            # If the API returns empty (e.g. balance is zero)
            if not raw_content:
                raise ValueError("API returned an empty response. Check your DeepSeek balance.")

            # Clean up markdown formatting if the model added it
            if raw_content.startswith("```json"):
                raw_content = raw_content[7:-3].strip()
            elif raw_content.startswith("```"):
                raw_content = raw_content[3:-3].strip()

            # Parse JSON (and auto-repair if it got truncated)
            return json.loads(repair_json(raw_content))

        except Exception as e:
            # Print the actual API response if there's an error so we can see it
            print(f"\n[DeepSeek Error] {filename}: {e}")
            return {"cwes": [], "secure": True}