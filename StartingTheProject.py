# How to run the project

# From the project root, in three terminals:

# // bash
# # 1. Preflight (rerun every time after Docker restarts) — needs the fixed API key
# .venv/Scripts/python.exe -m vulnguard.main doctor --build-sandbox
 
# # 2. Backend API on port 8000
# .venv/Scripts/python.exe -m vulnguard.main dashboard --backend fastapi --port 8000
# # 3. React dashboard on http://localhost:5173
# cd ui && npm run dev






# // Suggestions While Running the Project

# LiteLLM completion() model= gemini-3.8-flash; provider = gemini
# 12:15:55 │ LiteLLM                      │ INFO    │ 
# LiteLLM completion() model= gemini-3.8-flash; provider = gemini
# 12:15:55 - LiteLLM:INFO: vertex_and_google_ai_studio_gemini.py:1147 - Warning: Setting temperature < 1.0 for Gemini 3 models (gemini-3.8-flash) can cause infinite loops, degraded reasoning performance, and failure on complex tasks. Strongly recommended to use temperature = 1.0 (default).
# 12:15:55 │ LiteLLM                      │ INFO    │ Warning: Setting temperature < 1.0 for Gemini 3 models (gemini-3.8-flash) can cause infinite loops, degraded reasoning performance, and failure on complex tasks. Strongly recommended to use temperature = 1.0 (default).
# 12:15:55 - LiteLLM:WARNING: vertex_and_google_ai_studio_gemini.py:1152 - DeprecationWarning: `temperature`, `top_p`, and `top_k` continue to function for Gemini 3+ (gemini-3.8-flash) but are planned for removal in a future release. Move sampling guidance into the `system` instructions instead.
# 12:15:55 │ LiteLLM                      │ WARNING │ DeprecationWarning: `temperature`, `top_p`, and `top_k` continue to function for Gemini 3+ (gemini-3.8-flash) but are planned for removal in a future release. Move sampling guidance into the `system` instructions instead.