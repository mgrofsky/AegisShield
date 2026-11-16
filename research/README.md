# Research

This folder holds the material behind the praxis paper that evaluated
AegisShield: the case studies, the inputs and outputs of the batch runs, the
code that ran them, and the analysis notebook. None of it is needed to run
the app, the app does not read it, it is not copied into the Docker image,
and it is not linted, tested, or measured for coverage.

The app in `aegisshield/` is a later rewrite and is not the tool that
produced these results.

## What is here

| Folder | What it is | Part it plays in the paper |
|---|---|---|
| [`case_studies/`](case_studies/) | 15 published case studies, one Markdown file each, and the evaluation rubric (`rubric_criteria.md`) | the systems whose published, expert-developed threat models (in the cited papers) the tool was compared against, and each case study's rubric score |
| [`batch/inputs/`](batch/inputs/) | one JSON profile per case study, replicating what a user would enter in the app | what the tool was given for each case |
| [`batch/outputs/`](batch/outputs/) | one JSON result per case study | the tool's threat models that the paper analyzed |
| [`batch/`](batch/) (the `.py` files) | the first-generation batch pipeline, `main-batch.py` and its modules | the code that produced the outputs (since edited; see below) |
| [`colab_notebook/`](colab_notebook/) | the analysis notebook and its README | readability, semantic similarity, ATT&CK mapping coverage, and exploratory statistics |

Each output file holds 30 runs, and each run is a threat model of 18 threats,
3 per STRIDE category, which `main-batch.py` checks before it keeps a run:
450 threat models and 8,100 threats in all.

The final statistics in the paper were computed in Minitab, not in the
notebook (see its README).

## How the code relates to the published results

The contents of the inputs and outputs have not changed since the
repository's first commit (`1ba5956`, April 2025). The code in `batch/` is
not the code as it was in that commit. These commits changed the same files:

- `4185997`, `b6bb5dc`: "style: apply Ruff formatting across codebase (no
  functional changes)"
- `270e2b6`: "SP 800-53 control mappings"
- `788484d`: "Adding Explicit Key Masking"
- `8f88c44`: "Update OpenAI model from gpt-4o to gpt-5.4 across all modules"
- `0b3ed2d`: "Update MITRE ATT&CK data to v18.1 and add VoIP/Telephony app
  type" (this commit also replaced the ATT&CK bundles in
  `MITRE_ATTACK_DATA/`, which this pipeline reads)
- `3fd68b1`: "Refactor backend: centralized config, singleton OpenAI client,
  unified retry, MITRE caching"
- `bfbaed1`: "docs: clarify NIST SP 800-53 alignment wording, add
  local_config.example.py"
- The move of the pipeline, unchanged, from the repository root to
  `research/batch/`, with the input and output paths in `main-batch.py`
  changed to `research/batch/inputs/` and `research/batch/outputs/`

So running `batch/` today uses a different model and different ATT&CK data
from the code in the first commit. To see the code and data as they were
committed with the results, read them from that commit:

```
git ls-tree --name-only 1ba5956
git show 1ba5956:main-batch.py
```

The repository does not record which model version or ATT&CK release
produced the outputs beyond what that commit's code names.

## Rerun it

From the repository alone you can read every case study, input, and
output. Rerunning the batch needs your own paid OpenAI key (and NVD and OTX
keys), and uses today's model and ATT&CK data. The notebook cannot be rerun
from the repository alone.

### The batch runs

A batch run makes paid calls to OpenAI, NVD, and OTX, so it needs your own
keys and is not part of the repository's checks. Its modules import with
the app's requirements installed. From the repository root (the data paths
are relative to it):

```
cp research/batch/local_config.example.py research/batch/local_config.py
# put your OpenAI, NVD, and AlienVault OTX keys in research/batch/local_config.py
python research/batch/main-batch.py
```

Python puts the script's own folder first on the import path, so its flat
imports (`threat_model`, `mitre_attack`, `nvd_search`, and the rest) resolve
from `research/batch/`. It reads `MITRE_ATTACK_DATA/` and
`research/batch/inputs/`, and writes `research/batch/outputs/`, and `logs/`
and `error_log.txt` in the repository root. It imports Streamlit, so install
the app's requirements first.

Running it calls OpenAI, NVD, and OTX with your keys, and overwrites the
published results in `research/batch/outputs/`. Copy the repository first if
you want to keep them.

### The notebook

The notebook was written for Google Colab and reads its data from a Google
Drive folder (`drive/MyDrive/colab_data/`), not from this repository: the
rubric scores, the tool results, and the threats extracted from the case
studies. Those prepared files are not in the repository, so the notebook
cannot be rerun from this folder alone.
