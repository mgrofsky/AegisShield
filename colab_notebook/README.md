# Praxis Research Notebook: AI-Enhanced Threat Modeling

This repository contains a colab notebook, developed to support a doctoral praxis project evaluating an AI-enhanced threat modeling tool.

The notebook includes:
- Exploratory analysis of tool-generated vs. expert-developed threat descriptions
- Readability scoring using the Flesch-Kincaid Grade Level metric
- Cosine similarity analysis using Sentence-BERT
- MITRE ATT&CK mapping coverage checks
- Preliminary statistical testing using `scipy.stats`

> **Note**: While exploratory statistics were performed in Python (e.g., Mann-Whitney U test using SciPy), final statistical results reported in the paper were obtained using **Minitab**, which handles tie correction and output formatting more effectively.


