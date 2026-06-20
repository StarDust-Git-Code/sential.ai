import google.generativeai as genai
import sys
import json

def get_models(api_key):
    genai.configure(api_key=api_key)
    try:
        models = [m.name for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
        print(json.dumps(models, indent=2))
    except Exception as e:
        print(json.dumps({"error": str(e)}))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        get_models(sys.argv[1])
    else:
        print(json.dumps({"error": "No API key provided"}))
