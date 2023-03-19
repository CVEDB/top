#!/bin/bash

# Run getTop.py and store the results in end.md
python3 .github/getTop.py > end.md

# Concatenate he.md, end.md, and ed.md to create the updated README.md file
cat he.md end.md ed.md > README.md

# Run getCodeql.py and store the results in Top_Codeql1.md
python3 .github/getCodeql.py > Top_Codeql1.md

# Concatenate hecdql.md, Top_Codeql1.md, and ed.md to create the updated Top_Codeql.md file
cat hecdql.md Top_Codeql1.md ed.md > Top_Codeql.md

# Commit the changes and push to the remote repository
git add README.md Top_Codeql.md
git commit -m "Update $(date +%Y-%m-%d)"
git push origin main
