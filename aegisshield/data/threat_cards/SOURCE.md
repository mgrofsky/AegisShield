# OWASP threat cards

`owasp_llm_top_10.md`, `owasp_agentic.md`, and `owasp_crosswalk.json` are short summaries, written for this app, of material from the OWASP GenAI Security Project. `aegisshield/pipeline/threat_card_service.py` adds them to the threat-model prompt for an application that embeds a language model or acts as an agent.

- OWASP Top 10 for LLM Applications (2025): https://genai.owasp.org/llm-top-10/ (project repository https://github.com/OWASP/www-project-top-10-for-large-language-model-applications)
- OWASP Agentic Security Initiative, agentic threats: https://genai.owasp.org/
- The cross-walk also names categories from the OWASP Machine Learning Security Top 10 (https://owasp.org/www-project-machine-learning-security-top-10/) and OWASP working drafts on MCP servers and agent skills.

License: the OWASP material is licensed under the Creative Commons Attribution-ShareAlike 4.0 International License (CC BY-SA 4.0, https://creativecommons.org/licenses/by-sa/4.0/), as the project repository's README and the genai.owasp.org site state. These summaries are adaptations of it and are shared under the same license. Changes: the entries are shortened and reworded as prompt guidance, and the cross-walk maps categories across the lists. OWASP does not endorse this app.
