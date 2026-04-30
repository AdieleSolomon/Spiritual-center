# To check the status of your repository
git status
git pull origin main


# normal commit
git add .
git commit -m "update $(Get-Date -Format 'yyyy-MM-dd')"
<<<<<<< HEAD
git pull origin main
=======
>>>>>>> 2e079c07e1ba014a2dca109a3c86becc94f626f7
git push origin main


# Initial commit (for new repositories)
git inits
git pull origin main
git add .
git commit -m "Initial commit - Complete website with gallery"
<<<<<<< HEAD
git remote add origin
=======
git remote add origin https://github.com/AdieleSolomon/ELASTIC-TOURS-LTD.git
>>>>>>> 2e079c07e1ba014a2dca109a3c86becc94f626f7
git push -u origin main


#  Force push (Overwrites remote with your local files)
git remote remove origin
git remote add origin https://github.com/AdieleSolomon/ELASTIC-TOURS-LTD.git
git branch -M main
git push -u origin main --force


# If you want to keep remote files and merge (safer if remote has important files):
git remote add origin https://github.com/AdieleSolomon/Throne-Of-Grace.git
git branch -M main
git pull origin main --allow-unrelated-histories


# Resolve any conflicts if they occur
git add .
git commit -m "Merge unrelated histories"
git push -u origin main


# To clone a repository
git clone https://github.com/AdieleSolomon/Throne-Of-Grace.git
cd Throne-Of-Grace
git remote add origin https://github.com/AdieleSolomon/Throne-Of-Grace.git


# If you get an error about being on 'master' instead of 'main':
# Check current branch
git branch

# If you're on 'master', rename it to 'main'
git branch -M master main

# Then push
git push -u origin main --force


# To set up your Git username and email (only need to do this once)
git config --global user.name "Your Name"
git config --global user.email "yR2lK@example.com"


# To check your Git configuration
git config --list


# To view commit history
git log --oneline --graph --all


# To view changes before committing
git diff   