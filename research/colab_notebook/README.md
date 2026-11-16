# Analysis notebook

`notebook.ipynb` is the Google Colab notebook from the doctoral praxis that evaluated AegisShield's first-generation tool against expert-developed threat models. It holds:

- Exploratory analysis of tool-generated and expert-developed threat descriptions
- Readability scoring with the Flesch-Kincaid Grade Level (`textstat`)
- Cosine similarity of threat descriptions with Sentence-BERT (`stsb-roberta-large`)
- MITRE ATT&CK mapping coverage checks
- Preliminary statistical tests with `scipy.stats` (Shapiro-Wilk and Mann-Whitney U)

The final statistics reported in the paper were computed in Minitab, which handles tie correction and output formatting, not in this notebook.

The notebook reads its data from a Google Drive folder (`drive/MyDrive/colab_data/`): the rubric scores, the tool results, and the threats extracted from the case studies. Those prepared files are not in the repository, so the notebook cannot be rerun from the repository alone. See [`../README.md`](../README.md).
